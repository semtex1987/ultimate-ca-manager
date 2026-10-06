"""SmartCard-HSM offline-root ceremony orchestration (UCM ↔ RAM bridge)."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from typing import Any, Dict, List, Optional

from models import CA, db
from models.hsm import HsmCustodian, HsmKey, HsmProvider
from services.hsm.base_provider import HsmConnectionError, HsmOperationError
from services.hsm.sc_hsm_cloud_provider import call_bridge
from utils.datetime_utils import utc_now
from utils.public_endpoints import get_ram_public_origin

logger = logging.getLogger(__name__)

# Last access line written for each custodian, so the 4s ceremony poll does not
# fill the system log with the same status.
_logged_access: Dict[tuple, tuple] = {}

# Ceremony flags stored inside provider config (non-secret).
_CEREMONY_KEYS = (
    'assembly_slot',
    'wipe_confirmed',
    'ocsp_acknowledged',
    'crl_stale',
    'ceremony_active',
)


def _sock(provider: HsmProvider) -> Optional[str]:
    return (provider.get_config() or {}).get('socket_path')


def bridge_status(provider: HsmProvider) -> dict:
    try:
        return call_bridge('status', sock_path=_sock(provider))
    except HsmConnectionError as exc:
        logger.info('RAM bridge unreachable for provider %s: %s', provider.id, exc)
        return {'ok': False, 'error': str(exc), 'ceremony': {}, 'custodians': {}}


def _set_ceremony_flags(provider: HsmProvider, **flags) -> None:
    cfg = provider.get_config()
    for key, value in flags.items():
        if value is None:
            cfg.pop(key, None)
        else:
            cfg[key] = value
    provider.set_config(cfg)
    provider.updated_at = utc_now()


def sync_custodians(provider: HsmProvider, roster: List[dict]) -> None:
    """Replace custodian rows from ``[{user_id, share_index}, ...]``.

    Generates a fresh connect_token for new rows; keeps existing tokens when
    the (user_id, share_index) pair is unchanged. Never stores share bytes.
    """
    if not isinstance(roster, list):
        raise ValueError('custodians must be a list')

    wanted: Dict[int, dict] = {}
    for entry in roster:
        if not isinstance(entry, dict):
            raise ValueError('each custodian must be an object')
        if 'user_id' not in entry or 'share_index' not in entry:
            raise ValueError('custodians require user_id and share_index')
        share_index = int(entry['share_index'])
        user_id = int(entry['user_id']) if entry['user_id'] is not None else None
        if user_id is None:
            continue
        if share_index in wanted:
            raise ValueError(f'duplicate share_index {share_index}')
        wanted[share_index] = {'user_id': user_id, 'share_index': share_index}

    existing = {c.share_index: c for c in provider.custodians.all()}
    # Remove slots no longer in roster
    for share_index, row in list(existing.items()):
        if share_index not in wanted:
            db.session.delete(row)

    for share_index, spec in wanted.items():
        row = existing.get(share_index)
        if row is None:
            row = HsmCustodian(
                provider_id=provider.id,
                user_id=spec['user_id'],
                share_index=share_index,
                display_name='',
            )
            row.set_connect_token(secrets.token_urlsafe(32))
            db.session.add(row)
        else:
            if row.user_id != spec['user_id']:
                row.user_id = spec['user_id']
                # New keyholder → new connect token
                row.set_connect_token(secrets.token_urlsafe(32))
            elif not row.connect_token_enc:
                row.set_connect_token(secrets.token_urlsafe(32))


def detail_dict(
    provider: HsmProvider,
    *,
    viewer_user_id: Optional[int] = None,
    viewer_can_write_hsm: bool = False,
    viewer_can_contribute_hsm: bool = False,
    include_config: bool = True,
) -> dict:
    """GET detail shape consumed by HSMPage.jsx."""
    cfg = provider.get_config()
    status = bridge_status(provider) if provider.type == 'sc-hsm-cloud' else {}
    ceremony = status.get('ceremony') or {}
    connected_map = status.get('custodians') or {}

    base = provider.to_dict(include_config=include_config, include_custodian_tokens=False)

    if provider.type != 'sc-hsm-cloud':
        return base

    # Flatten config fields the form reads
    base['token_label'] = cfg.get('token_label') or ''
    base['device_scheme'] = cfg.get('device_scheme') or 'shares'
    base['key_domains'] = cfg.get('key_domains') or 1
    base['threshold_n'] = cfg.get('threshold_n')
    base['total_m'] = cfg.get('total_m')
    base['assembly_slot'] = cfg.get('assembly_slot')
    base['wipe_confirmed'] = bool(cfg.get('wipe_confirmed'))
    base['key_assembled'] = bool(ceremony.get('key_assembled'))

    # The bridge is the source of truth. A local flag must not show a window
    # as open when the bridge is down or has not confirmed the ceremony.
    if status.get('ok'):
        active = bool(ceremony.get('active'))
    else:
        active = False
    connected_ids = {
        str(cid) for cid, info in connected_map.items() if info.get('connected')
    }
    connected_count = len(connected_ids)

    if not active:
        base['ceremony_status'] = 'offline'
    else:
        base['ceremony_status'] = {
            'state': 'open',
            'connected_count': connected_count,
        }

    # CRL stale: window open and bridge says CRL not ready after latest change
    if active and ceremony.get('key_assembled'):
        crl_ready = bool(ceremony.get('crl_ready_for_wipe'))
        # Prefer live bridge flag; fall back to stored cfg
        base['crl_stale'] = (not crl_ready) if 'crl_ready_for_wipe' in ceremony else bool(cfg.get('crl_stale', True))
    elif active:
        base['crl_stale'] = bool(cfg.get('crl_stale', False))
    else:
        base['crl_stale'] = False

    if ceremony.get('wipe_verified'):
        base['wipe_confirmed'] = True

    ram_public = get_ram_public_origin()
    base['ram_public'] = {
        'origin': ram_public['origin'],
        'mode': ram_public['mode'],
        'listen_port': ram_public['listen_port'],
    }
    base['ocsp_responder_warning'] = _ocsp_warning_for_provider(provider, cfg)
    base['bridge'] = {
        'reachable': bool(status.get('ok')),
        'error': None if status.get('ok') else (status.get('error') or 'RAM bridge unreachable'),
        'vpcd_connected': bool(status.get('vpcd_connected')),
    }
    pem = ceremony.get('public_key_pem') if ceremony.get('key_assembled') else None
    if pem:
        digest = hashlib.sha256(pem.encode('utf-8') if isinstance(pem, str) else pem).hexdigest()
        base['key_fingerprint'] = digest[:16]
    else:
        base['key_fingerprint'] = None

    custodians_out = []
    for c in provider.custodians.order_by(HsmCustodian.share_index).all():
        username = None
        if c.user:
            username = c.user.username or c.user.full_name
        cid = str(c.id)
        bridge_info = connected_map.get(cid) or connected_map.get(str(c.share_index)) or {}
        connected = bool(bridge_info.get('connected'))
        if connected and bridge_info.get('readable'):
            status_str = 'connected'
            access = 'readable'
        elif connected and bridge_info.get('has_atr'):
            status_str = 'connected'
            access = 'card'
        elif connected:
            status_str = 'connected'
            access = 'session'
        elif cfg.get('contributed_shares') and str(c.share_index) in (cfg.get('contributed_shares') or []):
            status_str = 'contributed'
            access = 'waiting'
        else:
            status_str = 'waiting'
            access = 'waiting'

        is_me = viewer_user_id is not None and c.user_id == viewer_user_id
        entry = {
            'id': c.id,
            'user_id': c.user_id,
            'share_index': c.share_index,
            'username': username,
            'name': username or c.display_name or f'share-{c.share_index}',
            'status': status_str,
            'access': access,
            'probe_error': bridge_info.get('probe_error') if connected else None,
            'probe_sw': bridge_info.get('probe_sw') if connected else None,
            'card_state': bridge_info.get('card_state') if connected else None,
            'card_ready': bool(bridge_info.get('card_ready')) if connected else False,
            'is_me': is_me,
        }
        # Token URL only for that custodian (contribute) or write:hsm operators
        if viewer_can_write_hsm or (viewer_can_contribute_hsm and is_me):
            entry['ram_client_url'] = c.ram_client_url()
        _log_custodian_access(provider.id, entry)
        custodians_out.append(entry)

    base['custodians'] = custodians_out
    return base


def _log_custodian_access(provider_id: int, entry: dict) -> None:
    """Write one system-log line when a token's access state changes."""
    if entry.get('access') == 'waiting' and not entry.get('probe_error'):
        return
    signature = (
        entry.get('access'),
        entry.get('probe_error'),
        entry.get('probe_sw'),
        entry.get('card_state'),
        bool(entry.get('card_ready')),
    )
    key = (provider_id, entry.get('id'))
    if _logged_access.get(key) == signature:
        return
    _logged_access[key] = signature
    logger.info(
        'sc-hsm provider %s custodian %s access=%s probe_sw=%s probe_error=%s card_state=%s ready=%s',
        provider_id,
        entry.get('id'),
        entry.get('access'),
        entry.get('probe_sw') or '-',
        entry.get('probe_error') or '-',
        entry.get('card_state') or '-',
        bool(entry.get('card_ready')),
    )


def _ocsp_warning_for_provider(provider: HsmProvider, cfg: dict) -> Any:
    if cfg.get('ocsp_acknowledged'):
        return None
    # Optional explicit message from config; else probe linked CA responder.
    if cfg.get('ocsp_responder_warning'):
        return cfg['ocsp_responder_warning']
    try:
        from models import CA
        # CAs whose HSM key belongs to this provider
        key_ids = [k.id for k in provider.keys.all()]
        if not key_ids:
            return None
        cas = CA.query.filter(CA.hsm_key_id.in_(key_ids), CA.offline.is_(True)).all()
        for ca in cas:
            warning = _responder_expiry_warning(ca)
            if warning:
                return warning
    except Exception as exc:  # noqa: BLE001
        logger.debug('ocsp warning probe failed: %s', exc)
    return None


def _responder_expiry_warning(ca) -> Optional[dict]:
    """Truthy warning when delegated OCSP responder expires before next ceremony."""
    try:
        from models.certificate import Certificate
        from utils.datetime_utils import utc_now
        from datetime import timedelta
        # Heuristic: OCSP responder certs issued by this CA with short remaining life
        responders = (
            Certificate.query
            .filter_by(ca_id=ca.id, status='active')
            .filter(Certificate.cert_type.in_(['ocsp', 'ocsp_responder', 'OCSP']))
            .all()
        )
        # Also match by EKU/common patterns via descr
        if not responders:
            responders = (
                Certificate.query
                .filter_by(ca_id=ca.id, status='active')
                .filter(Certificate.common_name.ilike('%ocsp%'))
                .all()
            )
        horizon = utc_now() + timedelta(days=400)  # ~yearly ceremony
        for cert in responders:
            not_after = getattr(cert, 'not_after', None) or getattr(cert, 'valid_to', None)
            if not_after and not_after < horizon:
                return {
                    'message': (
                        f'OCSP responder certificate for CA {ca.descr} expires '
                        f'{not_after.isoformat()}; renew it before wipe'
                    ),
                }
    except Exception:  # noqa: BLE001
        return None
    return None


def begin_ceremony(provider: HsmProvider) -> dict:
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    cfg = provider.get_config()
    custodians = []
    for c in provider.custodians.order_by(HsmCustodian.share_index).all():
        custodians.append({
            'custodian_id': str(c.id),
            'connect_token': c.get_connect_token(),
            'share_index': c.share_index,
            'user_id': c.user_id,
        })
    if not custodians:
        raise ValueError('No custodians assigned; write:hsm must set the roster first')

    use_fake = os.getenv('RAM_BRIDGE_FAKE', '').strip().lower() in ('1', 'true', 'yes')
    params = {
        'provider_id': provider.id,
        'threshold_n': int(cfg.get('threshold_n') or len(custodians)),
        'total_m': int(cfg.get('total_m') or len(custodians)),
        'custodians': custodians,
        'wrapped_root_b64': cfg.get('wrapped_root') or cfg.get('wrapped_root_blob'),
        'use_fake': use_fake,
    }
    result = call_bridge('begin_ceremony', params, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'begin_ceremony failed')

    _set_ceremony_flags(
        provider,
        ceremony_active=True,
        wipe_confirmed=False,
        ocsp_acknowledged=False,
        crl_stale=False,
        assembly_slot=None,
    )
    provider.status = 'connected'
    db.session.commit()
    return {'ok': True}


def set_assembly_slot(provider: HsmProvider, share_index: int, *, user_pin: str = '') -> dict:
    custodian = (
        HsmCustodian.query
        .filter_by(provider_id=provider.id, share_index=int(share_index))
        .first()
    )
    if not custodian:
        raise ValueError(f'No custodian with share_index={share_index}')

    result = call_bridge('set_assembly', {
        'assembly_custodian_id': str(custodian.id),
        'user_pin': user_pin or '',
    }, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'set_assembly failed')
    ceremony = result.get('ceremony') or {}
    if not ceremony.get('key_assembled'):
        raise HsmOperationError('root key was not assembled')

    _set_ceremony_flags(provider, assembly_slot=int(share_index), crl_stale=True)
    db.session.commit()
    return {'ok': True, 'assembly_slot': int(share_index)}


def _custodian_for_provider(provider: HsmProvider, custodian_id: int) -> HsmCustodian:
    row = HsmCustodian.query.filter_by(provider_id=provider.id, id=int(custodian_id)).first()
    if row is None:
        raise ValueError('Custodian not found on this provider')
    return row


def inspect_token(provider: HsmProvider, custodian_id: int) -> dict:
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    row = _custodian_for_provider(provider, custodian_id)
    return call_bridge('inspect_token', {
        'custodian_id': str(row.id),
    }, sock_path=_sock(provider))


def token_init_params(cfg: dict) -> dict:
    """Scheme and counts for device INITIALIZE, taken from the provider only.

    An n-of-m provider always uses DKEK shares sized to ``threshold_n``.
    The ceremony UI does not ask for that count again.
    """
    scheme = (cfg.get('device_scheme') or 'shares').strip()
    if scheme not in ('none', 'random', 'shares', 'domains'):
        raise ValueError('unknown device key scheme')
    if scheme == 'shares':
        count = int(cfg.get('threshold_n') or 1)
        if count < 1 or count > 16:
            raise ValueError('dkek share count out of range')
        return {'scheme': 'shares', 'dkek_shares': count, 'key_domains': 1}
    if scheme == 'domains':
        domains = int(cfg.get('key_domains') or 1)
        if domains < 1 or domains > 16:
            raise ValueError('key domain count out of range')
        return {'scheme': 'domains', 'dkek_shares': 1, 'key_domains': domains}
    return {'scheme': scheme, 'dkek_shares': 1, 'key_domains': 1}


def prepare_token(
    provider: HsmProvider,
    custodian_id: int,
    *,
    confirm: str,
    so_pin: str = '',
    user_pin: str = '',
    reinitialize: bool = False,
) -> dict:
    """Ask the bridge to initialize or wipe one token. PINs are not stored.

    The device-key scheme and the share count come from the provider. A
    request cannot substitute a different count.
    """
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    row = _custodian_for_provider(provider, custodian_id)
    cfg = provider.get_config()
    init = token_init_params(cfg)
    return call_bridge('prepare_token', {
        'custodian_id': str(row.id),
        'confirm': confirm or '',
        'so_pin': so_pin or '',
        'user_pin': user_pin or '',
        'reinitialize': bool(reinitialize),
        'scheme': init['scheme'],
        'dkek_shares': init['dkek_shares'],
        'key_domains': init['key_domains'],
    }, sock_path=_sock(provider))


def acknowledge_ocsp(provider: HsmProvider) -> dict:
    _set_ceremony_flags(provider, ocsp_acknowledged=True)
    db.session.commit()
    return {'ok': True}


def mark_crl_fresh(provider: HsmProvider) -> None:
    """Called after a successful CRL regenerate during a window."""
    if provider.type != 'sc-hsm-cloud':
        return
    try:
        call_bridge('mark_crl_signed', sock_path=_sock(provider))
    except Exception:  # noqa: BLE001
        pass
    _set_ceremony_flags(provider, crl_stale=False)
    db.session.commit()


def mark_operator_change(provider: HsmProvider) -> None:
    """Any root-key operator action after assembly makes CRL stale until republished."""
    if provider.type != 'sc-hsm-cloud':
        return
    try:
        call_bridge('mark_change', sock_path=_sock(provider))
    except Exception:  # noqa: BLE001
        pass
    _set_ceremony_flags(provider, crl_stale=True)
    db.session.commit()


def _sc_hsm_provider_for_ca(ca) -> Optional[HsmProvider]:
    hsm_key_id = getattr(ca, 'hsm_key_id', None)
    if not hsm_key_id:
        return None
    hsm_key = db.session.get(HsmKey, hsm_key_id)
    if hsm_key is None or hsm_key.provider is None:
        return None
    if hsm_key.provider.type != 'sc-hsm-cloud':
        return None
    return hsm_key.provider


def on_crl_published(ca) -> None:
    """Clear crl_stale after a successful operator CRL regenerate."""
    provider = _sc_hsm_provider_for_ca(ca)
    if provider is not None:
        mark_crl_fresh(provider)


def on_operator_change(ca) -> None:
    """Mark CRL stale after a revocation or other unpublished root-key change."""
    provider = _sc_hsm_provider_for_ca(ca)
    if provider is not None:
        mark_operator_change(provider)


def _publish_crl_before_wipe(provider: HsmProvider) -> None:
    """Regenerate every linked offline CA's CRL before the key is destroyed.

    With no CA bound there is nothing to publish, so the bridge is told the
    CRL step is done. A failure leaves the key in place.
    """
    key_ids = [k.id for k in provider.keys.all()]
    cas = []
    if key_ids:
        cas = CA.query.filter(CA.hsm_key_id.in_(key_ids), CA.offline.is_(True)).all()
    if not cas:
        call_bridge('mark_crl_signed', sock_path=_sock(provider))
        _set_ceremony_flags(provider, crl_stale=False)
        return
    from services.crl_service import CRLService
    for ca in cas:
        try:
            CRLService.generate_crl(ca.id, username='ceremony-wipe')
        except Exception as exc:  # noqa: BLE001 — wipe must not proceed
            raise HsmOperationError(
                f"CRL regeneration failed; wipe refused: {exc}"
            ) from exc


def wipe_assembly(provider: HsmProvider) -> dict:
    cfg = provider.get_config()
    status = bridge_status(provider)
    if not status.get('ok'):
        raise HsmOperationError('RAM bridge unavailable; wipe not confirmed')
    ceremony = status.get('ceremony') or {}
    warning = _ocsp_warning_for_provider(provider, cfg)
    if warning and not cfg.get('ocsp_acknowledged'):
        raise HsmOperationError(
            'OCSP responder warning must be acknowledged before wipe'
        )

    if ceremony.get('key_assembled'):
        _publish_crl_before_wipe(provider)
        status = bridge_status(provider)
        ceremony = status.get('ceremony') or {}
        if not ceremony.get('crl_ready_for_wipe'):
            raise HsmOperationError(
                'CRL must be regenerated after the latest change before wipe'
            )
    elif cfg.get('crl_stale'):
        raise HsmOperationError(
            'CRL must be regenerated after the latest change before wipe'
        )

    try:
        result = call_bridge('wipe_assembly', sock_path=_sock(provider))
    except HsmConnectionError as exc:
        raise HsmOperationError(f'RAM bridge unavailable: {exc}') from exc
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'wipe_assembly failed')
    verified = bool(
        result.get('wipe_verified')
        or result.get('already_wiped')
        or (result.get('ceremony') or {}).get('wipe_verified')
    )
    if not verified:
        raise HsmOperationError('wipe could not be verified; window stays open')

    _set_ceremony_flags(provider, wipe_confirmed=True, crl_stale=False)
    db.session.commit()
    return {'ok': True, 'wipe_confirmed': True}


def end_ceremony(provider: HsmProvider) -> dict:
    cfg = provider.get_config()
    if not cfg.get('wipe_confirmed'):
        raise HsmOperationError('end requires wipe_confirmed')
    result = call_bridge('end_ceremony', sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'end_ceremony failed')

    _set_ceremony_flags(
        provider,
        ceremony_active=False,
        wipe_confirmed=False,
        assembly_slot=None,
        ocsp_acknowledged=False,
        crl_stale=False,
    )
    provider.status = 'offline'
    db.session.commit()
    return {'ok': True}


def ensure_ceremony_key(provider: HsmProvider) -> Optional[HsmKey]:
    """Return the ceremony signing key, creating the row from a stored or live PEM."""
    existing = (
        HsmKey.query.filter_by(provider_id=provider.id)
        .filter(HsmKey.purpose.in_(('signing', 'all')))
        .order_by(HsmKey.id)
        .first()
    )
    if existing is not None:
        return existing
    cfg = provider.get_config()
    pem = cfg.get('public_key_pem')
    if not pem:
        try:
            status = call_bridge('status', sock_path=_sock(provider))
            ceremony = (status or {}).get('ceremony') or {}
            if ceremony.get('key_assembled'):
                pem = ceremony.get('public_key_pem')
        except Exception:  # noqa: BLE001 — bridge down means there is no live key
            pem = None
    if not pem:
        return None
    key = HsmKey(
        provider_id=provider.id,
        key_identifier='1',
        label=f'{provider.name} root',
        algorithm='RSA-2048',
        key_type='asymmetric',
        purpose='signing',
        public_key_pem=pem,
        is_extractable=False,
    )
    db.session.add(key)
    if not cfg.get('public_key_pem'):
        cfg['public_key_pem'] = pem
        provider.set_config(cfg)
    db.session.commit()
    return key


def _store_new_root(provider: HsmProvider, result: dict, *, assembly_slot: Optional[int] = None) -> dict:
    """Persist a wrapped root from create or roll. Share bytes are not in ``result``."""
    wrapped = result.get('wrapped_root_b64')
    public_pem = result.get('public_key_pem')
    if not wrapped or not public_pem:
        raise HsmOperationError('key creation did not return a wrapped blob and public key')
    cfg = provider.get_config()
    cfg['wrapped_root'] = wrapped
    cfg['public_key_pem'] = public_pem
    provider.set_config(cfg)
    signing = [key for key in provider.keys.all() if key.purpose in ('signing', 'all')]
    if signing:
        for key in signing:
            key.public_key_pem = public_pem
    else:
        db.session.add(HsmKey(
            provider_id=provider.id,
            key_identifier='1',
            label=f'{provider.name} root',
            algorithm='RSA-2048',
            key_type='asymmetric',
            purpose='signing',
            public_key_pem=public_pem,
            is_extractable=False,
        ))
    flags = {'crl_stale': True, 'wipe_confirmed': False}
    if assembly_slot is not None:
        flags['assembly_slot'] = int(assembly_slot)
    _set_ceremony_flags(provider, **flags)
    resigned = _self_sign_bound_roots(provider, public_pem)
    db.session.commit()
    return {
        'ok': True,
        'public_key_pem': public_pem,
        'shares_written': result.get('shares_written'),
        'cas_resigned': resigned,
    }


def create_root_key(provider: HsmProvider, share_index: int, confirm: str, *, user_pin: str = '') -> dict:
    """Generate the first root key and write a share onto every custodian token."""
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    if (provider.get_config().get('device_scheme') or 'shares') != 'shares':
        raise ValueError('Create root key applies to an n-of-m DKEK share provider')
    if confirm != 'DELETE':
        raise HsmOperationError('Type DELETE to create the root key')
    custodian = (
        HsmCustodian.query
        .filter_by(provider_id=provider.id, share_index=int(share_index))
        .first()
    )
    if not custodian:
        raise ValueError(f'No custodian with share_index={share_index}')
    result = call_bridge('create_root_key', {
        'assembly_custodian_id': str(custodian.id),
        'confirm': confirm,
        'user_pin': user_pin or '',
    }, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'create_root_key failed')
    stored = _store_new_root(provider, result, assembly_slot=int(share_index))
    stored['assembly_slot'] = int(share_index)
    return stored


def roll_root_key(provider: HsmProvider, *, user_pin: str = '') -> dict:
    """Roll the assembled root key, store the new wrapped blob, self-sign.

    The response has the new public key only. Share bytes stay on the tokens.
    """
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    result = call_bridge('roll_root_key', {
        'user_pin': user_pin or '',
    }, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'roll_root_key failed')
    return _store_new_root(provider, result)


def _self_sign_bound_roots(provider: HsmProvider, public_pem: str) -> List[int]:
    """Replace each bound offline root certificate with a self-signed one on the new key."""
    import base64
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    from services.hsm.ca_key_loader import get_ca_signing_key
    from utils.datetime_utils import utc_now

    key_ids = [k.id for k in provider.keys.all()]
    if not key_ids:
        return []
    cas = CA.query.filter(CA.hsm_key_id.in_(key_ids), CA.offline.is_(True)).all()
    public_key = serialization.load_pem_public_key(public_pem.encode('ascii'))
    resigned: List[int] = []
    now = utc_now()
    for ca in cas:
        if not ca.crt or ca.caref:
            continue
        old = x509.load_pem_x509_certificate(base64.b64decode(ca.crt))
        signing_key = get_ca_signing_key(ca)
        builder = (
            x509.CertificateBuilder()
            .subject_name(old.subject)
            .issuer_name(old.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )
        cert = builder.sign(signing_key, hashes.SHA256())
        ca.crt = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode('ascii')
        ca.subject = old.subject.rfc4514_string()
        ca.issuer = old.subject.rfc4514_string()
        ca.serial_number = str(cert.serial_number)
        resigned.append(ca.id)
    return resigned
