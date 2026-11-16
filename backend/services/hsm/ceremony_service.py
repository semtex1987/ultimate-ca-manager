"""SmartCard-HSM offline-root ceremony orchestration (UCM ↔ RAM bridge)."""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import os
import secrets
import time
import uuid
import zipfile
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
    base['has_wrapped_root'] = bool(cfg.get('wrapped_root') or cfg.get('wrapped_root_blob'))

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

    pka_mode = is_pka(provider)
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
        enrolled = keyholder_key(c) if pka_mode else None
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
        if pka_mode:
            live = status.get('pka') or {}
            entry['enrolled'] = enrolled is not None
            entry['key_fingerprint'] = enrolled.fingerprint if enrolled else None
            entry['key_chr'] = enrolled.chr if enrolled else None
            entry['key_device_chr'] = enrolled.device_chr if enrolled else None
            entry['approved'] = cid in (live.get('approved') or [])
            entry['authenticated'] = cid in (live.get('authenticated') or [])
            # Keyholders never connect a card to the bridge in this scheme.
            entry['status'] = 'enrolled' if enrolled else 'not_enrolled'
            entry['access'] = 'waiting'
        elif is_me and (viewer_can_contribute_hsm or viewer_can_write_hsm):
            # A connect URL admits a card into that custodian's slot. Only the
            # custodian sees it; an operator holding every URL could fill
            # every slot alone.
            entry['ram_client_url'] = c.ram_client_url()
        if not pka_mode:
            _log_custodian_access(provider.id, entry)
        custodians_out.append(entry)

    base['custodians'] = custodians_out
    if pka_mode:
        base['pka'] = _pka_detail(provider, cfg, status, viewer_can_write_hsm=viewer_can_write_hsm)
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


def begin_ceremony(
    provider: HsmProvider,
    *,
    operations: Optional[list] = None,
    max_signatures: Any = None,
    ttl_hours: Any = None,
    opened_by: Optional[str] = None,
) -> dict:
    if provider.type != 'sc-hsm-cloud':
        raise ValueError('Not an sc-hsm-cloud provider')
    if is_pka(provider):
        return begin_pka_ceremony(
            provider,
            operations=operations,
            max_signatures=max_signatures,
            ttl_hours=ttl_hours,
            opened_by=opened_by,
        )
    if not legacy_share_ceremony_allowed():
        raise ValueError(LEGACY_REFUSAL)
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
        'device_scheme': (cfg.get('device_scheme') or 'shares'),
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
        'device_scheme': provider.get_config().get('device_scheme') or 'shares',
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

    transcript = result.get('transcript')
    if transcript:
        _store_transcript(provider, transcript)
    _set_ceremony_flags(
        provider,
        ceremony_active=False,
        wipe_confirmed=False,
        assembly_slot=None,
        ocsp_acknowledged=False,
        crl_stale=False,
        ceremony_manifest=None,
    )
    _rotate_connect_tokens(provider)
    provider.status = 'offline'
    db.session.commit()
    out = {'ok': True}
    if transcript:
        out['transcript_final_hash'] = transcript.get('final_hash')
        out['ceremony_id'] = transcript.get('ceremony_id')
    return out


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
    if is_pka(provider):
        raise ValueError('A pka provider generates its root key with generate-root-key during an unlocked window')
    scheme = provider.get_config().get('device_scheme') or 'shares'
    if scheme not in ('shares', 'random'):
        raise ValueError('Create root key applies to an n-of-m DKEK share provider or a random DKEK')
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
        'device_scheme': scheme,
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
    if is_pka(provider):
        raise HsmOperationError(
            'A pka root is never re-keyed in place. Create a new provider for the new root '
            'and cross-certify if relying parties need continuity.'
        )
    result = call_bridge('roll_root_key', {
        'user_pin': user_pin or '',
        'device_scheme': provider.get_config().get('device_scheme') or 'shares',
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


# =============================================================================
# Public key authentication (device_scheme = 'pka')
# docs/design/sc-hsm-remote-ceremony-pka.md
# =============================================================================

LEGACY_REFUSAL = (
    'Remote DKEK-share ceremonies are disabled: they pass key shares through '
    'the UCM host. Use a public key authentication (pka) provider, or set '
    'UCM_ALLOW_LEGACY_SHARE_CEREMONY=1 to accept that risk. '
    'See docs/design/sc-hsm-remote-ceremony-pka.md.'
)

# Written only by the ceremony code. A provider edit cannot set or change them.
SERVER_MANAGED_KEYS = (
    'public_key_pem',
    'pinned_device_chr',
    'keyholders_locked',
    'root_connect_token',
    'ceremony_manifest',
    'transcripts',
)
# Bound to the root HSM once its keyholder keys are registered.
BOUND_KEYS = ('device_scheme', 'threshold_n', 'total_m')
MAX_STORED_TRANSCRIPTS = 20
DEFAULT_WINDOW_HOURS = 8
MAX_WINDOW_HOURS = 72


def legacy_share_ceremony_allowed() -> bool:
    return os.getenv('UCM_ALLOW_LEGACY_SHARE_CEREMONY', '').strip().lower() in ('1', 'true', 'yes')


def is_pka(provider: HsmProvider) -> bool:
    if provider is None or provider.type != 'sc-hsm-cloud':
        return False
    return (provider.get_config().get('device_scheme') or '') == 'pka'


def protect_ceremony_config(incoming: dict, existing: dict) -> dict:
    """Keep ceremony-owned config keys out of operator edits."""
    out = {k: v for k, v in (incoming or {}).items() if k not in SERVER_MANAGED_KEYS}
    for key in SERVER_MANAGED_KEYS:
        if key in (existing or {}):
            out[key] = existing[key]
    return out


class CeremonyBindingError(ValueError):
    """A provider edit the ceremony state does not allow. Safe to show."""


def check_bound_provider_change(provider: HsmProvider, existing: dict, incoming: dict, roster) -> None:
    """Refuse edits that would no longer match the registered root HSM."""
    if (existing or {}).get('ceremony_active'):
        raise CeremonyBindingError('Close the signing window before editing this provider')
    if (existing or {}).get('device_scheme') != 'pka' or not existing.get('keyholders_locked'):
        return
    for key in BOUND_KEYS:
        if key in incoming and str(incoming.get(key)) != str(existing.get(key)):
            raise CeremonyBindingError(
                f'{key} is fixed once keyholder keys are registered on the root HSM; '
                're-initialize the device and create a new provider to change it'
            )
    if roster is not None:
        current = sorted(
            (c.share_index, c.user_id) for c in provider.custodians.all()
        )
        wanted = sorted(
            (int(e['share_index']), int(e['user_id']))
            for e in roster if isinstance(e, dict) and e.get('user_id') is not None
        )
        if current != wanted:
            raise CeremonyBindingError('The keyholder roster is fixed once keys are registered on the root HSM')


def keyholder_key(custodian: HsmCustodian):
    """Parsed enrollment export of a custodian, or None."""
    from services.hsm import sc_hsm_pka as pka
    raw = custodian.auth_public_key
    if not raw:
        return None
    try:
        return pka.parse_pka_export(base64.b64decode(raw))
    except (ValueError, pka.PkaError):
        logger.warning('stored keyholder export for custodian %s does not parse', custodian.id)
        return None


def _custodian_for_user(provider: HsmProvider, user_id: Optional[int]) -> HsmCustodian:
    if user_id is None:
        raise PermissionError('not signed in')
    rows = HsmCustodian.query.filter_by(provider_id=provider.id, user_id=int(user_id)).all()
    if not rows:
        raise PermissionError('you are not a keyholder of this provider')
    if len(rows) > 1:
        # One person must not count twice toward the threshold.
        raise PermissionError('you hold more than one keyholder slot; fix the roster first')
    return rows[0]


def enroll_keyholder(provider: HsmProvider, user_id: int, export: bytes) -> dict:
    """Store a keyholder's ``--export-for-pub-key-auth`` file on their own row."""
    from services.hsm import sc_hsm_pka as pka
    if not is_pka(provider):
        raise ValueError('Enrollment applies to a public key authentication provider')
    cfg = provider.get_config()
    if cfg.get('keyholders_locked'):
        raise ValueError('Keyholder keys are already registered on the root HSM; enrollment is closed')
    if cfg.get('ceremony_active'):
        raise ValueError('Close the signing window before enrolling')
    custodian = _custodian_for_user(provider, user_id)
    key = pka.parse_pka_export(export)
    for other in provider.custodians.all():
        if other.id == custodian.id:
            continue
        existing = keyholder_key(other)
        if existing and (existing.fingerprint == key.fingerprint or existing.chr == key.chr):
            raise ValueError('This key is already enrolled for another keyholder')
    custodian.auth_public_key = base64.b64encode(export).decode('ascii')
    db.session.commit()
    return {'custodian_id': custodian.id, 'share_index': custodian.share_index, **key.summary()}


def registration_bundle(provider: HsmProvider) -> bytes:
    """Zip of every keyholder export, in roster order, for ``sc-hsm-tool`` at the site."""
    if not is_pka(provider):
        raise ValueError('Registration applies to a public key authentication provider')
    cfg = provider.get_config()
    total = int(cfg.get('total_m') or 0)
    threshold = int(cfg.get('threshold_n') or 0)
    rows = provider.custodians.order_by(HsmCustodian.share_index).all()
    keys = [(row, keyholder_key(row)) for row in rows]
    missing = [row.share_index for row, key in keys if key is None]
    if missing or len(rows) != total:
        raise ValueError(
            f'All {total} keyholders must be enrolled first; missing slots: {missing or "roster size"}'
        )
    lines = [
        f'UCM provider: {provider.name} (id {provider.id})',
        f'Threshold: {threshold} of {total}',
        '',
        'Run at the root HSM site, with keyholders and a witness on the call:',
        '',
        f'  sc-hsm-tool --initialize --so-pin <SO-PIN> --pin <user PIN> \\',
        f'              --public-key-auth {total} --required-pub-keys {threshold}',
    ]
    for index, (row, _key) in enumerate(keys, start=1):
        lines.append(f'  sc-hsm-tool --register-public-key {index:02d}-slot{row.share_index}.pka --pin <user PIN>')
    lines += [
        '  sc-hsm-tool --public-key-auth-status',
        f'  # expect: total {total}, missing 0, required {threshold}',
        '',
        'Each keyholder reads their fingerprint aloud from their own agent; compare:',
        '',
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for index, (row, key) in enumerate(keys, start=1):
            name = row.user.username if row.user else f'slot{row.share_index}'
            archive.writestr(f'{index:02d}-slot{row.share_index}.pka', base64.b64decode(row.auth_public_key))
            lines.append(
                f'  slot {row.share_index}  {name:<20} key {key.chr:<16} device {key.device_chr:<16} '
                f'sha256 {key.fingerprint}'
            )
        archive.writestr('README.txt', '\n'.join(lines) + '\n')
    return buffer.getvalue()


def server_tls_spki_sha256() -> str:
    """SHA-256 of the SubjectPublicKeyInfo keyholders see on the UCM HTTPS endpoint.

    Behind a TLS-terminating proxy set UCM_PUBLIC_TLS_SPKI_SHA256 to the
    proxy certificate's value; otherwise the UCM certificate is used.
    """
    override = os.getenv('UCM_PUBLIC_TLS_SPKI_SHA256', '').strip().lower().replace(':', '')
    if override:
        return override
    data_dir = os.getenv('DATA_DIR', '/opt/ucm/data')
    path = os.getenv('HTTPS_CERT_PATH', os.path.join(data_dir, 'https_cert.pem'))
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(path, 'rb') as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki).hexdigest()
    except (OSError, ValueError):
        return ''


def _ceremony_sas(manifest: Optional[dict], device_chr: Optional[str]) -> Optional[str]:
    from services.hsm import sc_hsm_pka as pka
    if not manifest or not device_chr:
        return None
    return pka.compute_sas(
        str(manifest.get('ceremony_id')),
        pka.manifest_hash(manifest),
        device_chr,
        server_tls_spki_sha256(),
    )


def root_ram_client_url(provider: HsmProvider) -> Optional[str]:
    token = provider.get_config().get('root_connect_token')
    if not token:
        return None
    origin = get_ram_public_origin()['origin'].rstrip('/')
    return f'{origin}/hsm/ram/{token}'


def _pka_detail(provider: HsmProvider, cfg: dict, status: dict, *, viewer_can_write_hsm: bool) -> dict:
    live = status.get('pka') if status.get('ok') else None
    manifest = cfg.get('ceremony_manifest')
    device_chr = (live or {}).get('device_chr')
    transcripts = cfg.get('transcripts') or []
    detail = {
        'pinned_device_chr': cfg.get('pinned_device_chr'),
        'keyholders_locked': bool(cfg.get('keyholders_locked')),
        'has_root_key': bool(cfg.get('public_key_pem')),
        'root_connected': bool(status.get('root_connected')),
        'manifest': manifest,
        'manifest_sha256': (live or {}).get('manifest_sha256'),
        'sas': _ceremony_sas(manifest, device_chr) if live else None,
        'live': live,
        'transcripts': [
            {
                'ceremony_id': t.get('ceremony_id'),
                'final_hash': t.get('final_hash'),
                'closed_at': t.get('closed_at'),
                'entries': len(t.get('entries') or []),
                'countersigned_by': sorted((t.get('countersignatures') or {}).keys()),
            }
            for t in reversed(transcripts[-5:])
        ],
    }
    if viewer_can_write_hsm:
        detail['root_ram_client_url'] = root_ram_client_url(provider)
    return detail


def begin_pka_ceremony(
    provider: HsmProvider,
    *,
    operations: Optional[list],
    max_signatures: Any,
    ttl_hours: Any = None,
    opened_by: Optional[str] = None,
) -> dict:
    from services.hsm import sc_hsm_pka as pka
    cfg = provider.get_config()
    threshold = int(cfg.get('threshold_n') or 0)
    total = int(cfg.get('total_m') or 0)
    if threshold < 1 or total < threshold:
        raise ValueError('Set a threshold between 1 and the number of keyholders')
    rows = provider.custodians.order_by(HsmCustodian.share_index).all()
    if len(rows) != total:
        raise ValueError(f'The roster has {len(rows)} keyholders; the provider expects {total}')
    user_ids = [row.user_id for row in rows]
    if None in user_ids or len(set(user_ids)) != len(user_ids):
        raise ValueError('Each keyholder slot needs a different user')
    keyholders = []
    for row in rows:
        if keyholder_key(row) is None:
            raise ValueError(f'Keyholder in slot {row.share_index} has not enrolled a key')
        keyholders.append({
            'custodian_id': str(row.id),
            'share_index': row.share_index,
            'export_b64': row.auth_public_key,
        })
    try:
        ops, budget = pka.validate_manifest_request(operations, max_signatures)
    except pka.PkaError as exc:
        raise ValueError(str(exc)) from exc
    try:
        hours = float(ttl_hours) if ttl_hours not in (None, '') else DEFAULT_WINDOW_HOURS
    except (TypeError, ValueError) as exc:
        raise ValueError('ttl_hours must be a number') from exc
    if hours <= 0 or hours > MAX_WINDOW_HOURS:
        raise ValueError(f'ttl_hours must be between 0 and {MAX_WINDOW_HOURS}')
    if not cfg.get('root_connect_token'):
        cfg['root_connect_token'] = secrets.token_urlsafe(32)
        provider.set_config(cfg)
        cfg = provider.get_config()
    now = time.time()
    expires_at = now + hours * 3600
    manifest = {
        'version': 1,
        'ceremony_id': str(uuid.uuid4()),
        'provider_id': provider.id,
        'provider_name': provider.name,
        'device_chr': cfg.get('pinned_device_chr'),
        'threshold_n': threshold,
        'total_m': total,
        'opened_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
        'expires_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_at)),
        'opened_by': opened_by or '',
        'operations': ops,
        'max_signatures': budget,
    }
    if any(op['type'] == 'generate_root_key' for op in ops) and cfg.get('public_key_pem'):
        raise ValueError('This provider already has a root key; a new root needs a new provider')
    result = call_bridge('begin_ceremony', {
        'device_scheme': 'pka',
        'provider_id': provider.id,
        'threshold_n': threshold,
        'total_m': total,
        'root_connect_token': cfg['root_connect_token'],
        'keyholders': keyholders,
        'pinned_device_chr': cfg.get('pinned_device_chr'),
        'public_key_pem': cfg.get('public_key_pem'),
        'manifest': manifest,
        'expires_at': expires_at,
    }, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or 'begin_ceremony failed')
    _set_ceremony_flags(
        provider,
        ceremony_active=True,
        wipe_confirmed=False,
        ocsp_acknowledged=False,
        crl_stale=False,
        assembly_slot=None,
        ceremony_manifest=manifest,
    )
    provider.status = 'connected'
    db.session.commit()
    return {'ok': True, 'ceremony_id': manifest['ceremony_id'], 'manifest_sha256': pka.manifest_hash(manifest).hex()}


def _bridge_pka(provider: HsmProvider, method: str, params: Optional[dict] = None) -> dict:
    if not is_pka(provider):
        raise ValueError('Not a public key authentication provider')
    result = call_bridge(method, params or {}, sock_path=_sock(provider))
    if not result.get('ok'):
        raise HsmOperationError(result.get('error') or f'{method} failed')
    return result


def pin_root_device(provider: HsmProvider, device_chr: str) -> dict:
    """Record the root HSM's device reference after it was read out on the call."""
    device_chr = (device_chr or '').strip()
    if not device_chr:
        raise ValueError('device_chr is required')
    cfg = provider.get_config()
    if cfg.get('pinned_device_chr') and cfg['pinned_device_chr'] != device_chr:
        raise ValueError('A different root HSM is already pinned for this provider')
    _bridge_pka(provider, 'pka_pin_device', {'device_chr': device_chr})
    cfg = provider.get_config()
    cfg['pinned_device_chr'] = device_chr
    # Pinning happens after the keyholder keys were registered at the site.
    cfg['keyholders_locked'] = True
    provider.set_config(cfg)
    db.session.commit()
    return {'ok': True, 'pinned_device_chr': device_chr}


def keyholder_context(provider: HsmProvider, user_id: int) -> dict:
    """Everything the keyholder agent shows before the keyholder approves."""
    custodian = _custodian_for_user(provider, user_id)
    key = keyholder_key(custodian)
    cfg = provider.get_config()
    status = bridge_status(provider)
    live = status.get('pka') if status.get('ok') else None
    manifest = cfg.get('ceremony_manifest')
    cid = str(custodian.id)
    return {
        'provider_id': provider.id,
        'provider_name': provider.name,
        'custodian_id': custodian.id,
        'share_index': custodian.share_index,
        'enrolled': key.summary() if key else None,
        'window_open': bool(live),
        'manifest': manifest,
        'manifest_sha256': (live or {}).get('manifest_sha256'),
        'device_chr': (live or {}).get('device_chr'),
        'pinned_device_chr': cfg.get('pinned_device_chr'),
        'device_error': (live or {}).get('device_error'),
        'config_error': (live or {}).get('config_error'),
        'sas': _ceremony_sas(manifest, (live or {}).get('device_chr')) if live else None,
        'tls_spki_sha256': server_tls_spki_sha256(),
        'approved': cid in ((live or {}).get('approved') or []),
        'authenticated': cid in ((live or {}).get('authenticated') or []),
        'quorum': {
            'authenticated': len((live or {}).get('authenticated') or []),
            'required': int(cfg.get('threshold_n') or 0),
            'unlocked': bool((live or {}).get('unlocked')),
        },
    }


def keyholder_approve(provider: HsmProvider, user_id: int, signature_b64: str) -> dict:
    custodian = _custodian_for_user(provider, user_id)
    result = _bridge_pka(provider, 'pka_approve', {
        'custodian_id': str(custodian.id), 'signature_b64': signature_b64 or '',
    })
    return {'ok': True, 'pka': result.get('pka')}


def keyholder_challenge(provider: HsmProvider, user_id: int) -> dict:
    custodian = _custodian_for_user(provider, user_id)
    result = _bridge_pka(provider, 'pka_challenge', {'custodian_id': str(custodian.id)})
    return result.get('result') or {}


def keyholder_authenticate(provider: HsmProvider, user_id: int, signature_b64: str) -> dict:
    custodian = _custodian_for_user(provider, user_id)
    result = _bridge_pka(provider, 'pka_authenticate', {
        'custodian_id': str(custodian.id), 'signature_b64': signature_b64 or '',
    })
    return result.get('result') or {}


def generate_pka_root_key(provider: HsmProvider, confirm: str, bits: int = 2048) -> dict:
    """Generate the root key inside the unlocked root HSM and record its public key."""
    cfg = provider.get_config()
    if cfg.get('public_key_pem'):
        raise ValueError('This provider already has a root key; a new root needs a new provider')
    if confirm != 'GENERATE':
        raise ValueError('Type GENERATE to create the root key')
    result = _bridge_pka(provider, 'pka_generate_root_key', {'confirm': confirm, 'bits': int(bits)})
    public_pem = result.get('public_key_pem')
    if not public_pem:
        raise HsmOperationError('the root HSM did not return a public key')
    cfg = provider.get_config()
    cfg['public_key_pem'] = public_pem
    provider.set_config(cfg)
    db.session.add(HsmKey(
        provider_id=provider.id,
        key_identifier='1',
        label=f'{provider.name} root',
        algorithm=f'RSA-{int(bits)}',
        key_type='asymmetric',
        purpose='signing',
        public_key_pem=public_pem,
        is_extractable=False,
    ))
    _set_ceremony_flags(provider, crl_stale=True, wipe_confirmed=False)
    db.session.commit()
    digest = hashlib.sha256(public_pem.encode('ascii')).hexdigest()
    return {'ok': True, 'public_key_pem': public_pem, 'public_key_sha256': digest}


def _store_transcript(provider: HsmProvider, sealed: dict) -> None:
    from services.hsm import sc_hsm_pka as pka
    entries = sealed.get('entries') or []
    final = pka.verify_transcript(entries)
    if final != sealed.get('final_hash'):
        raise HsmOperationError('the bridge returned a transcript whose hash chain does not match')
    cfg = provider.get_config()
    stored = list(cfg.get('transcripts') or [])
    stored.append({
        'ceremony_id': sealed.get('ceremony_id'),
        'final_hash': final,
        'closed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'entries': entries,
        'countersignatures': {},
    })
    cfg['transcripts'] = stored[-MAX_STORED_TRANSCRIPTS:]
    provider.set_config(cfg)
    from services.audit_service import AuditService
    AuditService.log_action(
        action='hsm_ceremony_transcript',
        resource_type='hsm_provider',
        resource_id=provider.id,
        resource_name=provider.name,
        details=f'ceremony {sealed.get("ceremony_id")} transcript sealed; entries={len(entries)} final_sha256={final}',
        success=True,
    )


def _rotate_connect_tokens(provider: HsmProvider) -> None:
    """A connect URL is good for one window only."""
    for row in provider.custodians.all():
        row.set_connect_token(secrets.token_urlsafe(32))
    cfg = provider.get_config()
    if cfg.get('root_connect_token'):
        cfg['root_connect_token'] = secrets.token_urlsafe(32)
        provider.set_config(cfg)


def get_transcript(provider: HsmProvider, ceremony_id: Optional[str] = None) -> dict:
    """The live transcript of the open window, or a stored one."""
    cfg = provider.get_config()
    if not ceremony_id and cfg.get('ceremony_active') and is_pka(provider):
        live = call_bridge('pka_transcript', sock_path=_sock(provider))
        if live.get('ok'):
            return {
                'ceremony_id': (live.get('pka') or {}).get('ceremony_id'),
                'sealed': False,
                'entries': live.get('entries') or [],
            }
    stored = cfg.get('transcripts') or []
    match = None
    for item in reversed(stored):
        if not ceremony_id or item.get('ceremony_id') == ceremony_id:
            match = item
            break
    if match is None:
        raise ValueError('No transcript found')
    return {
        'ceremony_id': match.get('ceremony_id'),
        'sealed': True,
        'final_hash': match.get('final_hash'),
        'closed_at': match.get('closed_at'),
        'entries': match.get('entries') or [],
        'countersignatures': match.get('countersignatures') or {},
    }


def countersign_transcript(provider: HsmProvider, user_id: int, ceremony_id: str, signature_b64: str) -> dict:
    """A keyholder confirms a sealed transcript with their enrolled key."""
    from services.hsm import sc_hsm_pka as pka
    custodian = _custodian_for_user(provider, user_id)
    key = keyholder_key(custodian)
    if key is None:
        raise ValueError('You have not enrolled a key')
    cfg = provider.get_config()
    stored = list(cfg.get('transcripts') or [])
    for item in stored:
        if item.get('ceremony_id') == ceremony_id:
            final = pka.verify_transcript(item.get('entries') or [])
            try:
                signature = base64.b64decode(signature_b64 or '', validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError('signature is not valid base64') from exc
            pka.verify_keyholder_signature(key, pka.transcript_message(bytes.fromhex(final)), signature)
            item.setdefault('countersignatures', {})[str(custodian.id)] = {
                'signature_b64': base64.b64encode(signature).decode('ascii'),
                'key_fingerprint': key.fingerprint,
                'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            }
            cfg['transcripts'] = stored
            provider.set_config(cfg)
            db.session.commit()
            return {'ok': True, 'final_hash': final, 'countersigned_by': sorted(item['countersignatures'])}
    raise ValueError('No sealed transcript with that ceremony id')
