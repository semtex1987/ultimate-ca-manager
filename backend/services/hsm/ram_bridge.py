"""SmartCard-HSM RAM bridge process.

Run (matches packaging/docker)::

    cd /opt/ucm/backend && /opt/ucm/venv/bin/python -m services.hsm.ram_bridge

Listens:
  * TLS ``RAM_PORT`` (default 8444) — ``POST /hsm/ram/<connect_token>``
    for ram-client (same cert as UCM: ``HTTPS_CERT_PATH`` / ``HTTPS_KEY_PATH``)
  * Unix control socket ``/opt/ucm/data/ram-bridge.sock`` (mode 600)

Speaks vpicc to local vpcd on port 35963 so OpenSC PKCS#11 APDUs reach the
assembly token over RAMOverHTTP.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
from typing import Any, Dict, List, Optional, Tuple

from listen_address import get_bind_host

from services.hsm.ram_protocol import (
    ADMIN_PROTOCOL,
    CONTENT_TYPE,
    InitiationRequest,
    RamProtocolError,
    RequestTemplate,
    ResponseTemplate,
    is_empty_keepalive,
)
from services.hsm.ram_session import (
    RamSession,
    RamSessionManager,
    SessionBusyError,
    SessionDropError,
)
from services.hsm.sc_hsm_apdu import (
    FakeAssemblyToken,
    FakeCustodianToken,
    _zeroize,
    apdu_clear_kek,
    apdu_create_dkek_domain,
    apdu_delete_ef,
    apdu_delete_key_domain,
    apdu_delete_key_file,
    apdu_get_key_domain_status,
    apdu_initialize,
    apdu_verify_user_pin,
    apdu_import_dkek_share,
    apdu_read_share,
    SHARE_EF_FID,
    apdu_select_hsm,
    apdu_select_share_ef,
    apdu_unwrap_key,
    apdu_update_share,
    apdu_wrap_key,
    classify_token_state,
    interpret_share_probe,
    generate_dkek_shares,
    shares_to_import,
    parse_key_domain_status,
    parse_sw,
    sw_ok,
)
from utils.app_log import install_follower_handler
from services.hsm import sc_hsm_pka as pka
from services.hsm.pka_engine import ROOT_SLOT_ID, PkaCeremony, PkaRefused
from services.hsm.vpcd_card import (
    DEFAULT_VPCD_HOST,
    DEFAULT_VPCD_PORT,
    VpcdClient,
    VpcdVirtualCard,
)

logger = logging.getLogger('ucm.ram_bridge')

DEFAULT_RAM_PORT = 8444
DEFAULT_SOCK_PATH = '/opt/ucm/data/ram-bridge.sock'
DEFAULT_DATA_DIR = '/opt/ucm/data'
MAX_BODY_BYTES = 256 * 1024
LONG_POLL_SECONDS = 25.0
PROBE_STALE_SECONDS = 15.0
PROBE_TIMEOUT = 2.0
ROOT_KEY_ID = 1


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _cert_paths() -> Tuple[str, str]:
    data = os.getenv('DATA_DIR', DEFAULT_DATA_DIR)
    cert = os.getenv('HTTPS_CERT_PATH', os.path.join(data, 'https_cert.pem'))
    key = os.getenv('HTTPS_KEY_PATH', os.path.join(data, 'https_key.pem'))
    return cert, key


def _sock_path() -> str:
    return os.getenv('RAM_BRIDGE_SOCK', DEFAULT_SOCK_PATH)


def _env_flag(name: str) -> bool:
    return os.getenv(name, '').strip().lower() in ('1', 'true', 'yes')


def legacy_share_ceremony_allowed() -> bool:
    """Remote DKEK-share assembly sends shares through this process in plaintext.

    It stays off unless an operator opts in. See
    docs/design/sc-hsm-remote-ceremony-pka.md, section 2.
    """
    return _env_flag('UCM_ALLOW_LEGACY_SHARE_CEREMONY')


LEGACY_REFUSAL = (
    'Remote DKEK-share ceremonies are disabled: they pass key shares through '
    'the UCM host. Use a public key authentication (pka) provider, or set '
    'UCM_ALLOW_LEGACY_SHARE_CEREMONY=1 on UCM and the RAM bridge to accept '
    'that risk. See docs/design/sc-hsm-remote-ceremony-pka.md.'
)


# ---------------------------------------------------------------------------
# Ceremony state
# ---------------------------------------------------------------------------

class CeremonyState:
    """In-process signing-window state for one CA domain."""

    def __init__(self):
        self.lock = threading.RLock()
        self.active = False
        self.ca_id: Optional[int] = None
        self.provider_id: Optional[int] = None
        self.threshold_n = 0
        self.total_m = 0
        self.device_scheme = 'shares'
        self.assembly_custodian_id: Optional[str] = None
        self.key_assembled = False
        self.root_key_id = ROOT_KEY_ID
        self.wrapped_root_b64: Optional[str] = None
        self.crl_signed_after_change = False
        self.last_change_seq = 0
        self.crl_seq_at_sign = -1
        self.wipe_verified = False
        self.error: Optional[str] = None
        self.public_key_pem: Optional[str] = None
        # Fake token used when PKCS#11/pcscd is unavailable (tests / dry-run).
        self.fake: Optional[FakeAssemblyToken] = None
        # Only the bridge's own environment turns fake mode on. A control
        # request cannot, so a misconfigured UCM cannot swap in a software key.
        self.use_fake = _env_flag('RAM_BRIDGE_FAKE')
        # Per-custodian share EF. Share bytes live here (the token), never in UCM.
        self.custodian_cards: Dict[str, FakeCustodianToken] = {}
        # User PIN of the token chosen as the assembly device for this window.
        # Not in snapshot(), not written to the provider, cleared when the window ends.
        self._user_pin = bytearray()

    def remember_user_pin(self, pin: str) -> None:
        self.clear_user_pin()
        if pin:
            self._user_pin = bytearray(pin.encode('ascii'))

    def clear_user_pin(self) -> None:
        for index in range(len(self._user_pin)):
            self._user_pin[index] = 0
        self._user_pin = bytearray()

    def user_pin(self) -> str:
        return bytes(self._user_pin).decode('ascii')

    def snapshot(self) -> dict:
        with self.lock:
            return {
                'active': self.active,
                'ca_id': self.ca_id,
                'provider_id': self.provider_id,
                'threshold_n': self.threshold_n,
                'total_m': self.total_m,
                'assembly_custodian_id': self.assembly_custodian_id,
                'key_assembled': self.key_assembled,
                'root_key_id': self.root_key_id if self.key_assembled else None,
                'public_key_pem': self.public_key_pem if self.key_assembled else None,
                'crl_ready_for_wipe': (
                    self.key_assembled
                    and self.crl_seq_at_sign >= self.last_change_seq
                    and self.crl_seq_at_sign >= 0
                ),
                'wipe_verified': self.wipe_verified,
                'error': self.error,
            }

    def mark_change(self) -> None:
        with self.lock:
            self.last_change_seq += 1
            self.crl_signed_after_change = False

    def mark_crl_signed(self) -> None:
        with self.lock:
            self.crl_seq_at_sign = self.last_change_seq
            self.crl_signed_after_change = True


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class RamBridge:
    def __init__(
        self,
        *,
        ram_port: Optional[int] = None,
        sock_path: Optional[str] = None,
        vpcd_host: str = DEFAULT_VPCD_HOST,
        vpcd_port: int = DEFAULT_VPCD_PORT,
        bind_host: Optional[str] = None,
        allow_plaintext: Optional[bool] = None,
    ):
        self.allow_plaintext = (
            allow_plaintext if allow_plaintext is not None
            else _env_flag('RAM_BRIDGE_ALLOW_PLAINTEXT')
        )
        # Public key authentication ceremony (scheme 'pka'), or None.
        self.pka: Optional[PkaCeremony] = None
        self._pka_fake: Optional[pka.FakePkaRootHsm] = None
        self._pka_fake_connected = False
        self.ram_port = ram_port if ram_port is not None else _env_int('RAM_PORT', DEFAULT_RAM_PORT)
        self.sock_path = sock_path or _sock_path()
        self.bind_host = bind_host if bind_host is not None else get_bind_host()
        self.vpcd_host = vpcd_host
        self.vpcd_port = vpcd_port
        self.sessions = RamSessionManager()
        self.ceremony = CeremonyState()
        self.sessions.on_mid_ceremony_drop(self._on_session_drop)
        self._http: Optional[ThreadingHTTPServer] = None
        self._control_sock: Optional[socket.socket] = None
        self._vpcd: Optional[VpcdClient] = None
        self._vpcd_atr = b''
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        # token → custodian metadata for URL auth
        self._token_map: Dict[str, dict] = {}
        self._token_lock = threading.Lock()
        # Set while a PKCS#11 login owns the assembly card, so a status
        # probe does not insert an APDU into that card's queue.
        self._assembly_busy = False

    # -- token registry (from begin_ceremony) ---------------------------------

    def _register_tokens(self, custodians: List[dict]) -> None:
        with self._token_lock:
            self._token_map.clear()
            for c in custodians:
                token = c['connect_token']
                cid = str(c['custodian_id'])
                self._token_map[token] = {
                    'custodian_id': cid,
                    'share_index': c.get('share_index'),
                }
                self.sessions.register_slot(cid, token)

    def resolve_token(self, connect_token: str) -> Optional[dict]:
        with self._token_lock:
            return self._token_map.get(connect_token)

    # -- assembly APDU path ---------------------------------------------------

    def _assembly_session(self) -> Optional[RamSession]:
        cid = self.ceremony.assembly_custodian_id
        if not cid:
            return None
        return self.sessions.get_by_custodian(cid)

    def transmit_assembly(self, apdu: bytes) -> bytes:
        """Send a CAPDU to the assembly token (fake or live RAM session)."""
        with self.ceremony.lock:
            fake = self.ceremony.fake
            use_fake = self.ceremony.use_fake or fake is not None
        if use_fake and fake is not None:
            return fake.transmit(apdu)
        session = self._assembly_session()
        if session is None or not session.connected:
            raise RuntimeError('assembly token not connected')
        return session.queue_transmit(apdu)

    def _pkcs11_session(self) -> Optional[RamSession]:
        """Card PKCS#11 should be talking to.

        The assembly card wins. Before one is chosen, a single connected
        card is used so a random-DKEK ceremony can be seen by OpenSC.
        Several connected cards and no assembly choice stay unanswered,
        so the wrong token is not powered up.
        """
        if self.ceremony.use_fake:
            return None
        if self.pka is not None:
            # The root HSM answers only the PKA engine. Presenting it to
            # pcscd would let any local PC/SC client send it APDUs.
            return None
        session = self._assembly_session()
        if session is not None and session.connected:
            return session
        connected = list(self.sessions.connected_custodians())
        if len(connected) == 1:
            return self.sessions.get_by_custodian(connected[0])
        return None

    def _live_pkcs11_atr(self) -> bytes:
        session = self._pkcs11_session()
        if session is not None and session.atr:
            return bytes(session.atr)
        return b''

    def _present_live_card(self) -> None:
        """Make vpcd present the connected card's own ATR.

        A stand-in ATR is rejected by OpenSC, and PKCS#11 then reports that
        no token exists. Rebuilding the virtual card is what makes the real
        ATR visible.
        """
        if self.ceremony.use_fake or self._vpcd is None:
            return
        atr = self._live_pkcs11_atr()
        if not atr:
            return
        if self._vpcd.connected and self._vpcd_atr == atr:
            return
        logger.info('presenting card to vpcd atr_len=%s', len(atr))
        self._vpcd.bounce()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self._vpcd.connected and self._vpcd_atr == atr:
                return
            time.sleep(0.2)
        logger.warning('vpcd did not present the connected card')

    def _make_vpcd_card(self) -> VpcdVirtualCard:
        session = self._pkcs11_session()
        atr = b''
        if session and session.atr:
            atr = bytes(session.atr)
        elif self.ceremony.fake is not None:
            atr = self.ceremony.fake.atr
        else:
            atr = self._live_pkcs11_atr()
        if not atr:
            # Kept only so the reader can come up before a card connects.
            # OpenSC does not treat this value as a SmartCard-HSM.
            atr = bytes.fromhex('3BFE1800008031FE4580318065B007405BFE70C3')
        self._vpcd_atr = bytes(atr)

        def transmit(apdu: bytes) -> bytes:
            # Never log APDU bytes at info — contain key material.
            logger.debug('vpcd CAPDU len=%s', len(apdu))
            with self.ceremony.lock:
                fake = self.ceremony.fake
                use_fake = self.ceremony.use_fake or fake is not None
            if use_fake and fake is not None:
                return fake.transmit(apdu)
            live = self._pkcs11_session()
            if live is None or not live.connected:
                # Answer the reader. Raising here drops the virtual card and
                # PKCS#11 goes back to seeing no token.
                return b'\x69\x82'
            try:
                return live.queue_transmit(apdu)
            except Exception:  # noqa: BLE001
                logger.exception('vpcd transmit failed')
                return b'\x6F\x00'

        def reset() -> bytes:
            live = self._pkcs11_session()
            if live is not None and live.connected:
                try:
                    got = live.queue_reset()
                    if got:
                        self._vpcd_atr = bytes(got)
                        return got
                except Exception:  # noqa: BLE001
                    logger.exception('vpcd reset failed')
            return self._vpcd_atr or atr

        return VpcdVirtualCard(atr=atr, transmit=transmit, reset=reset, powered=False)

    # -- public key authentication: root HSM slot ------------------------------

    def _root_session(self) -> Optional[RamSession]:
        return self.sessions.get_by_custodian(ROOT_SLOT_ID)

    def _root_connected(self) -> bool:
        if self._pka_fake is not None:
            return self._pka_fake_connected
        session = self._root_session()
        return bool(session is not None and session.connected)

    def _root_transmit(self, apdu: bytes) -> bytes:
        if self._pka_fake is not None:
            if not self._pka_fake_connected:
                raise RuntimeError('the root HSM is not connected')
            return self._pka_fake.transmit(apdu)
        session = self._root_session()
        if session is None or not session.connected:
            raise RuntimeError('the root HSM is not connected')
        # Key generation on the card can take a minute.
        return session.queue_transmit(apdu, timeout=120.0)

    def _root_reset(self) -> bytes:
        if self._pka_fake is not None:
            return self._pka_fake.reset()
        session = self._root_session()
        if session is None or not session.connected:
            raise RuntimeError('the root HSM is not connected')
        return session.queue_reset(timeout=30.0)

    def _sync_pka_flags(self) -> None:
        engine = self.pka
        if engine is None:
            return
        with self.ceremony.lock:
            usable = engine.quorum() and bool(engine.public_key_pem)
            self.ceremony.key_assembled = usable
            self.ceremony.public_key_pem = engine.public_key_pem
            self.ceremony.root_key_id = ROOT_KEY_ID
            if usable:
                self.ceremony.wipe_verified = False

    def _pka_attach_async(self, session_id: str) -> None:
        engine = self.pka

        def run() -> None:
            if engine is not None:
                engine.attach(session_id)

        threading.Thread(target=run, name='pka-attach', daemon=True).start()

    def _pka(self, method, *args, **kwargs) -> dict:
        """Run a PKA engine call; refusals are answers, not server errors."""
        if self.pka is None:
            return {'ok': False, 'error': 'no public key authentication ceremony is open'}
        try:
            result = method(*args, **kwargs)
        except (PkaRefused, pka.PkaError) as exc:
            logger.info('pka refused: %s', exc)
            return {'ok': False, 'error': str(exc), 'pka': self.pka.snapshot() if self.pka else None}
        finally:
            self._sync_pka_flags()
        return {'ok': True, 'result': result, 'pka': self.pka.snapshot() if self.pka else None}

    @staticmethod
    def _signature_param(params: dict) -> bytes:
        raw = params.get('signature_b64') or ''
        try:
            signature = base64.b64decode(raw, validate=True)
        except (ValueError, TypeError) as exc:
            raise pka.PkaError('signature is not valid base64') from exc
        if not signature or len(signature) > 256:
            raise pka.PkaError('signature has an invalid length')
        return signature

    def cmd_pka_pin_device(self, params: dict) -> dict:
        return self._pka(lambda: self.pka.pin_device(str(params.get('device_chr') or '')))

    def cmd_pka_approve(self, params: dict) -> dict:
        def run():
            self.pka.approve(str(params.get('custodian_id')), self._signature_param(params))
        return self._pka(run)

    def cmd_pka_challenge(self, params: dict) -> dict:
        return self._pka(lambda: self.pka.challenge(str(params.get('custodian_id'))))

    def cmd_pka_authenticate(self, params: dict) -> dict:
        def run():
            return self.pka.authenticate(str(params.get('custodian_id')), self._signature_param(params))
        return self._pka(run)

    def cmd_pka_generate_root_key(self, params: dict) -> dict:
        if params.get('confirm') != 'GENERATE':
            return {'ok': False, 'error': 'Type GENERATE to create the root key'}
        bits = int(params.get('bits') or 2048)
        result = self._pka(lambda: self.pka.generate_root_key(bits))
        if result.get('ok'):
            with self.ceremony.lock:
                self.ceremony.mark_change()
            result['public_key_pem'] = result.pop('result')
        return result

    def cmd_pka_transcript(self, _params: dict) -> dict:
        if self.pka is None:
            return {'ok': False, 'error': 'no public key authentication ceremony is open'}
        return {'ok': True, 'entries': self.pka.transcript_entries(), 'pka': self.pka.snapshot()}

    def _begin_pka(self, params: dict) -> dict:
        n = int(params.get('threshold_n') or 0)
        m = int(params.get('total_m') or 0)
        root_token = params.get('root_connect_token')
        if not root_token:
            return {'ok': False, 'error': 'root_connect_token required'}
        manifest = params.get('manifest')
        if not isinstance(manifest, dict) or not manifest.get('ceremony_id'):
            return {'ok': False, 'error': 'an approved-operations manifest is required'}
        keyholders: Dict[str, pka.KeyholderKey] = {}
        exports: List[bytes] = []
        try:
            for entry in params.get('keyholders') or []:
                blob = base64.b64decode(entry.get('export_b64') or '', validate=True)
                keyholders[str(entry['custodian_id'])] = pka.parse_pka_export(blob)
                exports.append(blob)
        except (KeyError, ValueError, TypeError, pka.PkaError) as exc:
            return {'ok': False, 'error': f'keyholder enrollment is not valid: {exc}'}
        with self.ceremony.lock:
            if self.ceremony.active and (self.ceremony.key_assembled or (self.pka and self.pka.quorum())):
                return {'ok': False, 'error': 'a window with an unlocked root HSM is already open'}
            fake = None
            if self.ceremony.use_fake:
                fake = pka.FakePkaRootHsm(threshold_n=n, total_m=m)
                for blob in exports:
                    fake.register(blob)
            self._pka_fake = fake
            self._pka_fake_connected = False
            try:
                engine = PkaCeremony(
                    provider_id=params.get('provider_id'),
                    ceremony_id=str(manifest['ceremony_id']),
                    threshold_n=n,
                    total_m=m,
                    keyholders=keyholders,
                    pinned_device_chr=params.get('pinned_device_chr'),
                    public_key_pem=params.get('public_key_pem'),
                    manifest=manifest,
                    max_signatures=int(manifest.get('max_signatures') or 0),
                    expires_at=float(params.get('expires_at') or 0),
                    transmit=self._root_transmit,
                    reset=self._root_reset,
                    connected=self._root_connected,
                )
            except (PkaRefused, ValueError) as exc:
                self._pka_fake = None
                return {'ok': False, 'error': str(exc)}
            self.pka = engine
            self.ceremony.active = True
            self.ceremony.ca_id = params.get('ca_id')
            self.ceremony.provider_id = params.get('provider_id')
            self.ceremony.threshold_n = n
            self.ceremony.total_m = m
            self.ceremony.device_scheme = 'pka'
            self.ceremony.assembly_custodian_id = None
            self.ceremony.key_assembled = False
            self.ceremony.wipe_verified = False
            self.ceremony.error = None
            self.ceremony.wrapped_root_b64 = None
            self.ceremony.public_key_pem = params.get('public_key_pem')
            self.ceremony.fake = None
            self.ceremony.custodian_cards = {}
            self.ceremony.clear_user_pin()
            self.ceremony.last_change_seq = 0
            self.ceremony.crl_seq_at_sign = -1
        self._register_tokens([{
            'connect_token': root_token,
            'custodian_id': ROOT_SLOT_ID,
            'share_index': 0,
        }])
        self.sessions.set_ceremony_active(True)
        logger.info(
            'pka ceremony begun provider=%s ceremony=%s n=%s m=%s',
            params.get('provider_id'), manifest.get('ceremony_id'), n, m,
        )
        return {'ok': True, 'ceremony': self.ceremony.snapshot(), 'pka': engine.snapshot()}

    def _on_session_drop(self, session: RamSession) -> None:
        logger.warning('custodian %s dropped mid-ceremony', session.custodian_id)
        if self.pka is not None and session.custodian_id == ROOT_SLOT_ID:
            self.pka.detach()
            self._sync_pka_flags()
            with self.ceremony.lock:
                self.ceremony.error = 'root HSM disconnected; keyholders must authenticate again'
            return
        with self.ceremony.lock:
            if not self.ceremony.active:
                return
            self.ceremony.error = f'session drop: {session.custodian_id}'
            # Fail CRL readiness; attempt wipe if key was assembled.
            self.ceremony.crl_seq_at_sign = -1
            if self.ceremony.key_assembled:
                try:
                    self._wipe_unlocked()
                except Exception as exc:  # noqa: BLE001
                    logger.exception('wipe after drop failed: %s', exc)

    # -- control methods ------------------------------------------------------

    def handle_control(self, request: dict) -> dict:
        method = request.get('method')
        params = request.get('params') or {}
        handlers = {
            'status': self.cmd_status,
            'begin_ceremony': self.cmd_begin_ceremony,
            'set_assembly': self.cmd_set_assembly,
            'import_share': self.cmd_import_share,
            'unwrap_root': self.cmd_unwrap_root,
            'sign_crl': self.cmd_sign_crl,
            'wipe_assembly': self.cmd_wipe_assembly,
            'end_ceremony': self.cmd_end_ceremony,
            'sign': self.cmd_sign,
            'mark_change': self.cmd_mark_change,
            'mark_crl_signed': self.cmd_mark_crl_signed,
            'connect_fake': self.cmd_connect_fake,
            'roll_root_key': self.cmd_roll_root_key,
            'create_root_key': self.cmd_create_root_key,
            'inspect_token': self.cmd_inspect_token,
            'prepare_token': self.cmd_prepare_token,
            'pka_pin_device': self.cmd_pka_pin_device,
            'pka_approve': self.cmd_pka_approve,
            'pka_challenge': self.cmd_pka_challenge,
            'pka_authenticate': self.cmd_pka_authenticate,
            'pka_generate_root_key': self.cmd_pka_generate_root_key,
            'pka_transcript': self.cmd_pka_transcript,
        }
        if method not in handlers:
            return {'ok': False, 'error': f'unknown method: {method}'}
        legacy_only = (
            'set_assembly', 'import_share', 'unwrap_root', 'roll_root_key',
            'create_root_key', 'inspect_token', 'prepare_token',
        )
        if self.pka is not None and method in legacy_only:
            return {'ok': False, 'error': f'{method} does not apply to a public key authentication ceremony'}
        if method in legacy_only and not legacy_share_ceremony_allowed():
            return {'ok': False, 'error': LEGACY_REFUSAL}
        if method in ('inspect_token', 'prepare_token', 'set_assembly', 'roll_root_key', 'create_root_key', 'begin_ceremony', 'wipe_assembly', 'end_ceremony') or method.startswith('pka_'):
            logger.info(
                'control %s custodian=%s',
                method,
                params.get('custodian_id') or params.get('assembly_custodian_id') or '-',
            )
        try:
            return handlers[method](params)
        except Exception as exc:  # noqa: BLE001 — always return JSON to caller
            logger.exception('control method %s failed', method)
            return {'ok': False, 'error': str(exc)}

    def _ensure_hsm(self, session, timeout: float) -> None:
        """SELECT the SmartCard-HSM applet once per connection."""
        if session.hsm_selected:
            return
        rapdu = session.queue_transmit(apdu_select_hsm(), timeout=timeout)
        _, sw1, sw2 = parse_sw(rapdu)
        if not sw_ok(sw1, sw2):
            raise RuntimeError(f'select SmartCard-HSM failed SW={sw1:02X}{sw2:02X}')
        session.hsm_selected = True

    def _share_select_error(self, sw1: int, sw2: int) -> str:
        sw = f'{sw1:02X}{sw2:02X}'
        if sw1 == 0x6A and sw2 == 0x82:
            return (
                f'select share EF failed SW={sw}: this token has no DKEK share '
                f'in EF {SHARE_EF_FID.hex().upper()}. A blank card does not '
                'contain one; Create root key writes the first share.'
            )
        return f'select share EF failed SW={sw}'

    def _probe_custodian(self, custodian_id: str, *, force: bool = False) -> None:
        """SELECT the share EF. Discard RAPDU data; keep only the status word.

        Share bytes never leave the token for this probe. 0x2F02 is the
        device certificate and is not this file.
        """
        if (
            self._assembly_busy
            and custodian_id == (self.ceremony.assembly_custodian_id or '')
        ):
            return
        session = self.sessions.get_by_custodian(custodian_id)
        if session is None or not session.connected:
            return
        now = time.monotonic()
        if not force and session.last_probe_at and (now - session.last_probe_at) < PROBE_STALE_SECONDS:
            return
        try:
            if self.ceremony.use_fake:
                card = self.ceremony.custodian_cards.get(custodian_id)
                if card is None:
                    session.record_probe(False, 'no token')
                    return
                rapdu = card.transmit(apdu_select_share_ef())
            else:
                self._ensure_hsm(session, PROBE_TIMEOUT)
                rapdu = session.queue_transmit(apdu_select_share_ef(), timeout=PROBE_TIMEOUT)
            _, sw1, sw2 = parse_sw(rapdu)
            outcome = interpret_share_probe(sw1, sw2)
            session.record_probe(
                outcome['readable'],
                outcome['probe_error'],
                outcome['probe_sw'],
            )
            if session.logged_probe_sw != outcome['probe_sw']:
                session.logged_probe_sw = outcome['probe_sw']
                logger.info('custodian %s %s', custodian_id, outcome['log'])
        except Exception as exc:  # noqa: BLE001 — probe must not fail status
            message = str(exc)[:80]
            session.record_probe(False, message)
            if session.logged_probe_sw != message:
                session.logged_probe_sw = message
                logger.info('custodian %s probe failed: %s', custodian_id, message)

    def _probe_stale_custodians(self) -> None:
        for cid in list(self.sessions.connected_custodians()):
            self._probe_custodian(cid)

    def _remember_card(self, custodian_id: str, card: dict) -> None:
        session = self.sessions.get_by_custodian(custodian_id)
        if session is None:
            return
        session.card_state = card.get('state')
        session.card_ready = bool(card.get('ready'))

    def _inspect_custodian(self, custodian_id: str) -> dict:
        """Read key-domain and share-file status. Does not change the token."""
        session = self.sessions.get_by_custodian(custodian_id)
        if session is None or not session.connected:
            return {'ok': False, 'error': f'custodian {custodian_id} is not connected'}
        if self.ceremony.use_fake:
            card_obj = self.ceremony.custodian_cards.get(custodian_id)
            share = card_obj.copy_share() if card_obj is not None else bytearray()
            try:
                has_share = len(share) > 0
            finally:
                _zeroize(share)
            if self.ceremony.device_scheme == 'random' and not has_share:
                card = classify_token_state(0x90, 0x00, bytes((0, 0)), 0x6A, 0x82)
            else:
                card = classify_token_state(
                    0x6A, 0x88, b'',
                    0x90 if has_share else 0x6A, 0x00 if has_share else 0x82,
                )
            self._remember_card(custodian_id, card)
            return {'ok': True, 'card': card}
        try:
            self._ensure_hsm(session, 15.0)
            domain = session.queue_transmit(apdu_get_key_domain_status(), timeout=15.0)
            data, sw1, sw2 = parse_sw(domain)
            selected = session.queue_transmit(apdu_select_share_ef(), timeout=15.0)
            _, share_sw1, share_sw2 = parse_sw(selected)
        except Exception as exc:  # noqa: BLE001 — report, do not log APDU bodies
            return {'ok': False, 'error': str(exc)}
        card = classify_token_state(sw1, sw2, data, share_sw1, share_sw2)
        self._remember_card(custodian_id, card)
        return {'ok': True, 'card': card}

    def cmd_inspect_token(self, params: dict) -> dict:
        cid = params.get('custodian_id')
        if cid is None:
            return {'ok': False, 'error': 'custodian_id required'}
        result = self._inspect_custodian(str(cid))
        card = result.get('card') or {}
        if result.get('ok'):
            logger.info(
                'custodian %s token state=%s ready=%s domain_sw=%s share_sw=%s',
                cid,
                card.get('state'),
                card.get('ready'),
                card.get('domain_sw'),
                card.get('share_sw'),
            )
        else:
            logger.info('custodian %s inspect failed: %s', cid, result.get('error'))
        return result

    def _ignore_missing(self, rapdu: bytes) -> None:
        _, sw1, sw2 = parse_sw(rapdu)
        if sw_ok(sw1, sw2):
            return
        if (sw1, sw2) in ((0x6A, 0x82), (0x6A, 0x88), (0x6A, 0x86), (0x69, 0x85)):
            return
        raise RuntimeError(f'prepare step failed SW={sw1:02X}{sw2:02X}')

    def cmd_prepare_token(self, params: dict) -> dict:
        """Bring one connected token to an empty key domain and no share file.

        Initialize when the card has never been initialized, or when the caller
        sets ``reinitialize`` (the CardContact initDevice path). That path
        clears every key and file and sets one device-key scheme. Otherwise
        delete the share EF and the key domain. Refuses unless ``confirm`` is
        DELETE. PINs are used only to build the initialize APDU and are not
        returned or logged.
        """
        cid = params.get('custodian_id')
        if cid is None:
            return {'ok': False, 'error': 'custodian_id required'}
        cid = str(cid)
        if self.ceremony.key_assembled:
            return {
                'ok': False,
                'error': 'Wipe the assembled root key before preparing tokens for a new scheme',
            }
        reinitialize = bool(params.get('reinitialize'))
        scheme = self._remember_scheme(params)
        inspected = self._inspect_custodian(cid)
        if not inspected.get('ok'):
            return inspected
        card = inspected['card']
        if scheme == 'random' and not reinitialize:
            if card.get('state') == 'has_dkek':
                return {'ok': True, 'already_ready': True, 'card': card}
            return {
                'ok': False,
                'error': (
                    'This card is not holding a random DKEK. Reinitialize device '
                    'to generate one. Prepare would replace it with a share domain.'
                ),
                'card': card,
            }
        if card.get('ready') and not reinitialize:
            return {'ok': True, 'already_ready': True, 'card': card}
        if params.get('confirm') != 'DELETE':
            return {
                'ok': False,
                'error': 'Type DELETE to prepare this token',
                'card': card,
            }
        share_count = int(params.get('dkek_shares') or self.ceremony.threshold_n or 1)
        key_domains = int(params.get('key_domains') or 1)
        if scheme not in ('shares', 'random') and not reinitialize and card.get('state') != 'uninitialized':
            return {
                'ok': False,
                'error': 'Reinitialize device to apply the card use saved on this provider.',
                'card': card,
            }
        so_pin = params.pop('so_pin', None) or ''
        user_pin = params.pop('user_pin', None) or ''
        try:
            if self.ceremony.use_fake:
                card_obj = self.ceremony.custodian_cards.get(cid)
                if card_obj is not None:
                    card_obj.zeroize()
            elif reinitialize or card.get('state') == 'uninitialized':
                apdu = apdu_initialize(
                    so_pin,
                    user_pin,
                    share_count,
                    scheme=scheme,
                    key_domains=key_domains,
                )
                session = self.sessions.get_by_custodian(cid)
                self._ensure_hsm(session, 15.0)
                rapdu = session.queue_transmit(apdu, timeout=30.0)
                apdu = b''
                _, sw1, sw2 = parse_sw(rapdu)
                if not sw_ok(sw1, sw2):
                    sw = f'{sw1:02X}{sw2:02X}'
                    if sw == '6A80':
                        raise RuntimeError(
                            'initialize refused SW=6A80. The card rejected the '
                            'initialization data. The SO-PIN must be the current '
                            'initialization code, and the device-key scheme must be '
                            'one choice: no DKEK, a random DKEK, DKEK shares, or key domains.'
                        )
                    if sw == '6982':
                        raise RuntimeError(
                            'initialize failed SW=6982. The SO-PIN does not match '
                            'the initialization code on the card.'
                        )
                    raise RuntimeError(f'initialize failed SW={sw}')
                verified = session.queue_transmit(apdu_verify_user_pin(user_pin), timeout=15.0)
                _, sw1, sw2 = parse_sw(verified)
                if not sw_ok(sw1, sw2):
                    raise RuntimeError(f'user PIN rejected SW={sw1:02X}{sw2:02X}')
                logger.info('custodian %s reinitialized scheme=%s', cid, scheme)
            elif scheme != 'shares':
                raise RuntimeError(
                    'Reinitialize device to apply the card use saved on this provider.'
                )
            else:
                session = self.sessions.get_by_custodian(cid)
                self._ensure_hsm(session, 15.0)
                if user_pin:
                    verified = session.queue_transmit(apdu_verify_user_pin(user_pin), timeout=15.0)
                    _, sw1, sw2 = parse_sw(verified)
                    if not sw_ok(sw1, sw2):
                        raise RuntimeError(f'user PIN rejected SW={sw1:02X}{sw2:02X}')
                self._ignore_missing(session.queue_transmit(apdu_delete_ef(SHARE_EF_FID), timeout=15.0))
                self._ignore_missing(session.queue_transmit(apdu_clear_kek(), timeout=15.0))
                self._ignore_missing(session.queue_transmit(apdu_delete_key_domain(), timeout=15.0))
                created = session.queue_transmit(apdu_create_dkek_domain(share_count), timeout=15.0)
                _, sw1, sw2 = parse_sw(created)
                # 6A86: this firmware already has the domain configured and
                # will not create a second one. An empty domain is enough.
                if not sw_ok(sw1, sw2) and (sw1, sw2) not in ((0x6A, 0x86), (0x69, 0x85)):
                    raise RuntimeError(f'create key domain failed SW={sw1:02X}{sw2:02X}')
        except ValueError as exc:
            return {'ok': False, 'error': str(exc), 'card': card}
        except Exception as exc:  # noqa: BLE001
            logger.exception('prepare token failed for custodian %s', cid)
            return {'ok': False, 'error': str(exc), 'card': card}
        finally:
            so_pin = ''
            user_pin = ''
        logger.info('custodian %s prepare finished', cid)
        return self._inspect_custodian(cid)

    def cmd_status(self, _params: dict) -> dict:
        engine = self.pka
        if engine is None:
            self._probe_stale_custodians()
        else:
            engine.refresh_status()
            self._sync_pka_flags()
        result = {
            'ok': True,
            'ceremony': self.ceremony.snapshot(),
            'custodians': self.sessions.status(),
            'vpcd_connected': bool(self._vpcd and self._vpcd.connected),
            'ram_port': self.ram_port,
        }
        if engine is not None:
            result['pka'] = engine.snapshot()
            result['root_connected'] = self._root_connected()
        return result

    def _remember_scheme(self, params: dict) -> str:
        scheme = (
            params.get('device_scheme') or params.get('scheme')
            or self.ceremony.device_scheme or 'shares'
        ).strip()
        if scheme not in ('none', 'random', 'shares', 'domains', 'pka'):
            scheme = 'shares'
        self.ceremony.device_scheme = scheme
        return scheme

    def cmd_begin_ceremony(self, params: dict) -> dict:
        if (params.get('device_scheme') or '').strip() == 'pka':
            return self._begin_pka(params)
        custodians = params.get('custodians') or []
        if not custodians:
            return {'ok': False, 'error': 'custodians required'}
        n = int(params.get('threshold_n') or len(custodians))
        m = int(params.get('total_m') or len(custodians))
        if params.get('use_fake') and not self.ceremony.use_fake:
            logger.warning('begin_ceremony asked for fake mode; ignored (RAM_BRIDGE_FAKE is not set on the bridge)')
        if not legacy_share_ceremony_allowed():
            return {'ok': False, 'error': LEGACY_REFUSAL}
        scheme = self._remember_scheme(params)
        with self.ceremony.lock:
            if self.ceremony.active and self.ceremony.key_assembled:
                return {'ok': False, 'error': 'ceremony already has an assembled key'}
            self.pka = None
            self._pka_fake = None
            self.ceremony.active = True
            self.ceremony.ca_id = params.get('ca_id')
            self.ceremony.provider_id = params.get('provider_id')
            self.ceremony.threshold_n = n
            self.ceremony.total_m = m
            self.ceremony.assembly_custodian_id = (
                str(params['assembly_custodian_id'])
                if params.get('assembly_custodian_id') is not None
                else None
            )
            self.ceremony.key_assembled = False
            self.ceremony.wipe_verified = False
            self.ceremony.error = None
            self.ceremony.wrapped_root_b64 = params.get('wrapped_root_b64')
            self.ceremony.public_key_pem = None
            self.ceremony.custodian_cards = {}
            self.ceremony.clear_user_pin()
            self.ceremony.last_change_seq = 0
            self.ceremony.crl_seq_at_sign = -1
            if self.ceremony.use_fake:
                self.ceremony.fake = FakeAssemblyToken(threshold_n=n, total_m=m)
            else:
                self.ceremony.fake = None
        self._register_tokens(custodians)
        self.sessions.set_ceremony_active(True)
        if self.ceremony.use_fake:
            if scheme == 'random':
                self.ceremony.custodian_cards = {
                    str(c['custodian_id']): FakeCustodianToken(b'')
                    for c in custodians
                }
                if self.ceremony.fake is not None:
                    self.ceremony.fake.outstanding = 0
                    self.ceremony.fake._dkek_ready = True
            else:
                self.ceremony.custodian_cards = {
                    str(c['custodian_id']): FakeCustodianToken(os.urandom(32))
                    for c in custodians
                }
        logger.info(
            'ceremony begun ca_id=%s n=%s m=%s custodians=%s',
            params.get('ca_id'), n, m, len(custodians),
        )
        return {'ok': True, 'ceremony': self.ceremony.snapshot()}

    def cmd_connect_fake(self, params: dict) -> dict:
        """Mark a custodian token connected. Refused unless the bridge is in fake mode.

        Does not accept share bytes. The share already sits on the fake card
        created at begin_ceremony.
        """
        if not self.ceremony.use_fake:
            return {'ok': False, 'error': 'connect_fake is refused unless RAM_BRIDGE_FAKE is set'}
        cid = params.get('custodian_id')
        if cid is None:
            return {'ok': False, 'error': 'custodian_id required'}
        if self.pka is not None:
            if str(cid) != ROOT_SLOT_ID or self._pka_fake is None:
                return {'ok': False, 'error': 'only the root HSM slot connects in a pka ceremony'}
            self._pka_fake_connected = True
            self.pka.attach('fake')
            return {'ok': True, 'pka': self.pka.snapshot()}
        session = self.sessions.get_by_custodian(str(cid))
        if session is None:
            return {'ok': False, 'error': f'unknown custodian {cid}'}
        if not session.connected:
            atr = self.ceremony.fake.atr if self.ceremony.fake is not None else bytes.fromhex('3BFE1800008031FE4580318065')
            session.mark_connected(atr)
        self._probe_custodian(str(cid), force=True)
        return {'ok': True, 'custodians': self.sessions.status()}

    def _read_share(self, custodian_id: str) -> bytearray:
        """Copy one share out of that custodian's token. Caller must zeroize."""
        if self.ceremony.use_fake:
            card = self.ceremony.custodian_cards.get(custodian_id)
            if card is None:
                raise RuntimeError(f'no share on custodian {custodian_id}')
            return card.copy_share()
        session = self.sessions.get_by_custodian(custodian_id)
        if session is None or not session.connected:
            raise RuntimeError(f'custodian {custodian_id} is not connected')
        self._ensure_hsm(session, 30.0)
        _, sw1, sw2 = parse_sw(session.queue_transmit(apdu_select_share_ef()))
        if not sw_ok(sw1, sw2):
            raise RuntimeError(self._share_select_error(sw1, sw2))
        # Le=0 reads the short EF (up to 256 bytes), which covers a 32-byte
        # XOR share and a Shamir share with its x-coordinate prefix.
        data, sw1, sw2 = parse_sw(session.queue_transmit(apdu_read_share(length=0)))
        if not sw_ok(sw1, sw2) or not data:
            raise RuntimeError(f'read share failed SW={sw1:02X}{sw2:02X}')
        return bytearray(data)

    def _write_share(self, custodian_id: str, share: bytes) -> None:
        if self.ceremony.use_fake:
            card = self.ceremony.custodian_cards.get(custodian_id)
            if card is None:
                raise RuntimeError(f'no token for custodian {custodian_id}')
            card.replace_share(share)
            return
        session = self.sessions.get_by_custodian(custodian_id)
        if session is None or not session.connected:
            raise RuntimeError(f'custodian {custodian_id} is not connected')
        self._ensure_hsm(session, 30.0)
        _, sw1, sw2 = parse_sw(session.queue_transmit(apdu_update_share(share)))
        if (sw1, sw2) == (0x69, 0x82) and str(custodian_id) == str(self.ceremony.assembly_custodian_id or ''):
            # Key generation logs the assembly card out. The share write for a
            # later roll needs that card's user PIN presented again.
            pin = self.ceremony.user_pin()
            if pin:
                verified = session.queue_transmit(apdu_verify_user_pin(pin))
                _, v1, v2 = parse_sw(verified)
                if not sw_ok(v1, v2):
                    raise RuntimeError(
                        f'verify user PIN failed SW={v1:02X}{v2:02X} on custodian {custodian_id}. '
                        'Enter that assembly card\'s user PIN and run the roll again.'
                    )
                _, sw1, sw2 = parse_sw(session.queue_transmit(apdu_update_share(share)))
        if not sw_ok(sw1, sw2):
            sw = f'{sw1:02X}{sw2:02X}'
            if sw == '6982':
                if str(custodian_id) == str(self.ceremony.assembly_custodian_id or ''):
                    raise RuntimeError(
                        f'write share failed SW=6982 on custodian {custodian_id}. '
                        'Enter that assembly card\'s user PIN and run the roll again.'
                    )
                raise RuntimeError(
                    f'write share failed SW=6982 on custodian {custodian_id}. '
                    'The user PIN is not verified on that token. Reinitialize '
                    'it in this window before creating the root key.'
                )
            raise RuntimeError(f'write share failed SW={sw} on custodian {custodian_id}')

    def _import_threshold(self, custodian_ids: list, threshold: int) -> None:
        """Read ``threshold`` share files and import 32-byte pieces into the card.

        Share files may be Shamir blobs. The card only accepts a 32-byte
        DKEK share, and it XORs exactly ``threshold`` of them.
        """
        blobs = []
        pieces = []
        try:
            for cid in list(custodian_ids)[:threshold]:
                blobs.append(self._read_share(cid))
            pieces = shares_to_import(blobs, threshold)
            for piece in pieces:
                self._import_share_bytes(bytearray(piece))
        finally:
            for blob in blobs:
                _zeroize(blob)
            for piece in pieces:
                _zeroize(bytearray(piece))

    def _import_share_bytes(self, share: bytearray) -> None:
        try:
            rapdu = self.transmit_assembly(apdu_import_dkek_share(bytes(share)))
            _, sw1, sw2 = parse_sw(rapdu)
            if not sw_ok(sw1, sw2):
                sw = f'{sw1:02X}{sw2:02X}'
                if sw == '6700':
                    raise RuntimeError(
                        'import share failed SW=6700. The card accepts one '
                        '32-byte DKEK share per import.'
                    )
                if sw == '6982':
                    raise RuntimeError(
                        'import share failed SW=6982. The user PIN is not '
                        'verified on the assembly token.'
                    )
                if sw == '6985':
                    raise RuntimeError(
                        'import share failed SW=6985. The assembly card '
                        'already has a device key and will not take another '
                        'share. Reinitialize that token in this window, then '
                        'create the root key again.'
                    )
                raise RuntimeError(f'import share failed SW={sw}')
        finally:
            _zeroize(share)

    def _abort_partial_assembly(self) -> None:
        """Drop a half-created key. Leave the default DKEK domain in place."""
        try:
            self._ignore_missing(self.transmit_assembly(apdu_delete_key_file(ROOT_KEY_ID)))
            if self.ceremony.device_scheme != 'random':
                self._ignore_missing(self.transmit_assembly(apdu_clear_kek()))
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.exception('failed to clear partial key')
        with self.ceremony.lock:
            self.ceremony.key_assembled = False
            self.ceremony.public_key_pem = None
            self.ceremony.assembly_custodian_id = None

    def _remember_public_key(self) -> None:
        fake = self.ceremony.fake
        if fake is not None and fake.root_key_id is not None:
            self.ceremony.public_key_pem = fake.public_pem()

    def cmd_set_assembly(self, params: dict) -> dict:
        """Choose the assembly token and import shares into it until the key exists.

        Share bytes are read from each custodian token inside this process and
        wiped after that share's import APDU. They are not returned to the caller.
        """
        cid = params.get('assembly_custodian_id')
        if cid is None:
            return {'ok': False, 'error': 'assembly_custodian_id required'}
        cid = str(cid)
        with self.ceremony.lock:
            if not self.ceremony.active:
                return {'ok': False, 'error': 'no active ceremony'}
            if self.ceremony.key_assembled:
                return {'ok': False, 'error': 'root key is already assembled'}
            threshold = self.ceremony.threshold_n
        connected = self.sessions.connected_custodians()
        if cid not in connected:
            return {
                'ok': False,
                'error': 'assembly token is not connected',
                'ceremony': self.ceremony.snapshot(),
            }
        scheme = self._remember_scheme(params)
        if scheme != 'random' and len(connected) < threshold:
            return {
                'ok': False,
                'error': (
                    f'need {threshold} connected tokens, have {len(connected)}'
                ),
                'ceremony': self.ceremony.snapshot(),
            }
        user_pin = params.pop('user_pin', None) or ''
        if user_pin:
            self.ceremony.remember_user_pin(user_pin)
        if scheme == 'random':
            return self._assemble_device_dkek(cid)
        ordered = [cid] + sorted(c for c in connected if c != cid)
        chosen = ordered[:threshold]
        with self.ceremony.lock:
            self.ceremony.assembly_custodian_id = cid
            self.ceremony.error = None
        try:
            self._import_threshold(chosen, threshold)
            wrapped = self.ceremony.wrapped_root_b64
            if not wrapped:
                if not self.ceremony.use_fake:
                    raise RuntimeError('wrapped root blob is required')
                wrapped = base64.b64encode(os.urandom(32)).decode('ascii')
            unwrapped = self.cmd_unwrap_root({'wrapped_root_b64': wrapped})
            if not unwrapped.get('ok'):
                raise RuntimeError(unwrapped.get('error') or 'unwrap failed')
            self._remember_public_key()
            if self.ceremony.use_fake and self.ceremony.fake is not None:
                if self.ceremony.root_key_id not in self.ceremony.fake.list_key_ids():
                    raise RuntimeError('assembled key was not listed after unwrap')
        except Exception as exc:  # noqa: BLE001 — clear a half-imported domain
            logger.exception('assembly failed')
            self._abort_partial_assembly()
            return {'ok': False, 'error': str(exc), 'ceremony': self.ceremony.snapshot()}
        return {'ok': True, 'ceremony': self.ceremony.snapshot()}

    def cmd_import_share(self, params: dict) -> dict:
        share_b64 = params.get('share_b64')
        if not share_b64:
            return {'ok': False, 'error': 'share_b64 required'}
        share = base64.b64decode(share_b64)
        try:
            key_domain = int(params.get('key_domain_idx') or 0)
            apdu = apdu_import_dkek_share(share, key_domain)
            # Zeroize caller's view after building APDU — share lives in APDU briefly.
            rapdu = self.transmit_assembly(apdu)
            data, sw1, sw2 = parse_sw(rapdu)
            if not sw_ok(sw1, sw2):
                return {
                    'ok': False,
                    'error': f'import share failed SW={sw1:02X}{sw2:02X}',
                }
            status = parse_key_domain_status(data)
            self.ceremony.mark_change()
            return {'ok': True, 'key_domain': status}
        finally:
            # Best-effort wipe of local share bytes
            share = b'\x00' * len(share)

    def cmd_unwrap_root(self, params: dict) -> dict:
        wrapped_b64 = params.get('wrapped_root_b64') or self.ceremony.wrapped_root_b64
        if not wrapped_b64:
            return {'ok': False, 'error': 'wrapped_root_b64 required'}
        key_id = int(params.get('key_id') or self.ceremony.root_key_id)
        # Fake path: just mark assembled. Live path: write EF + unwrap APDU.
        with self.ceremony.lock:
            if self.ceremony.use_fake and self.ceremony.fake is not None:
                self.ceremony.fake.wrapped_blob = base64.b64decode(wrapped_b64)
                self.ceremony.fake._dkek_ready = (
                    self.ceremony.fake.outstanding == 0
                    or len(self.ceremony.fake.shares) >= self.ceremony.threshold_n
                )
                if not self.ceremony.fake._dkek_ready:
                    return {
                        'ok': False,
                        'error': (
                            f'need {self.ceremony.threshold_n} shares, '
                            f'have {len(self.ceremony.fake.shares)}'
                        ),
                    }
                rapdu = self.ceremony.fake.transmit(apdu_unwrap_key(key_id))
                _, sw1, sw2 = parse_sw(rapdu)
                if not sw_ok(sw1, sw2):
                    return {'ok': False, 'error': f'unwrap failed SW={sw1:02X}{sw2:02X}'}
                self.ceremony.key_assembled = True
                self.ceremony.root_key_id = key_id
                self.ceremony.wipe_verified = False
                self._remember_public_key()
                self.ceremony.mark_change()
                return {'ok': True, 'key_id': key_id, 'ceremony': self.ceremony.snapshot()}

        # Live: OpenSC would write EF.2F10 then unwrap; we send unwrap after the
        # wrapped blob is staged via PKCS#11/sc-hsm-tool outside this MVP path,
        # or transmit a simplified unwrap when the session already holds DKEK.
        rapdu = self.transmit_assembly(apdu_unwrap_key(key_id))
        _, sw1, sw2 = parse_sw(rapdu)
        if not sw_ok(sw1, sw2):
            return {'ok': False, 'error': f'unwrap failed SW={sw1:02X}{sw2:02X}'}
        with self.ceremony.lock:
            self.ceremony.key_assembled = True
            self.ceremony.root_key_id = key_id
            self.ceremony.wipe_verified = False
            self._remember_public_key()
            self.ceremony.mark_change()
        return {'ok': True, 'key_id': key_id, 'ceremony': self.ceremony.snapshot()}

    def cmd_sign_crl(self, params: dict) -> dict:
        """Sign TBS bytes (CRL or other) with the assembled root key.

        Params: ``data_b64`` — raw bytes the PKCS#11 layer will hash+sign.
        Also marks the CRL as regenerated after the latest ceremony change.
        """
        signed = self._window_sign(params, default_label='CRL')
        if not signed.get('ok'):
            return signed
        # Signing the CRL is what regenerates it — mark seq.
        if params.get('is_crl', True):
            self.ceremony.mark_crl_signed()
        signed['ceremony'] = self.ceremony.snapshot()
        return signed

    def cmd_sign(self, params: dict) -> dict:
        """Generic sign used by ScHsmCloudProvider.sign during the window."""
        signed = self._window_sign(params)
        if signed.get('ok'):
            self.ceremony.mark_change()
        return signed

    def _window_sign(self, params: dict, *, default_label: str = '') -> dict:
        """Sign with the root key of the open window, for that provider only."""
        requested = params.get('provider_id')
        with self.ceremony.lock:
            if not self.ceremony.active:
                return {'ok': False, 'error': 'signing refused: no signing window is open'}
            window_provider = self.ceremony.provider_id
            if (
                requested is not None and window_provider is not None
                and str(requested) != str(window_provider)
            ):
                return {'ok': False, 'error': 'signing refused: the window is open for a different provider'}
            if self.pka is None and not self.ceremony.key_assembled:
                return {'ok': False, 'error': 'signing refused: ceremony key not assembled'}
        data_b64 = params.get('data_b64')
        if not data_b64:
            return {'ok': False, 'error': 'data_b64 required'}
        data = base64.b64decode(data_b64)
        hash_name = params.get('hash_algorithm') or 'sha256'
        if self.pka is not None:
            result = self._pka(
                self.pka.sign, data, hash_name,
                label=str(params.get('label') or default_label),
                provider_id=requested,
            )
            if not result.get('ok'):
                return {'ok': False, 'error': result.get('error')}
            sig = result['result']
        else:
            sig = self._sign_raw(data, hash_name)
        return {'ok': True, 'signature_b64': base64.b64encode(sig).decode('ascii')}

    def cmd_mark_change(self, _params: dict) -> dict:
        self.ceremony.mark_change()
        return {'ok': True, 'ceremony': self.ceremony.snapshot()}

    def cmd_mark_crl_signed(self, _params: dict) -> dict:
        self.ceremony.mark_crl_signed()
        return {'ok': True, 'ceremony': self.ceremony.snapshot()}

    def _sign_raw(self, data: bytes, hash_algorithm: str) -> bytes:
        """Sign via fake HMAC-like stub or PKCS#11.

        Fake mode returns a deterministic digest-sized blob so unit tests
        exercise the ceremony without pcscd. Live mode uses opensc-pkcs11.
        """
        with self.ceremony.lock:
            use_fake = self.ceremony.use_fake
            key_id = self.ceremony.root_key_id
        if use_fake:
            if self.ceremony.fake is None or self.ceremony.fake.root_key_id is None:
                raise RuntimeError('assembly token has no root key')
            return self.ceremony.fake.sign_pkcs1(data, hash_algorithm)

        return self._pkcs11_sign(data, hash_algorithm)

    def _find_pkcs11_token(self, lib, token_label: str):
        """Return the first PKCS#11 token, waiting briefly for the virtual reader.

        An empty label matches whatever token the reader presents. pcscd takes
        a moment after the card ATR is published.
        """
        deadline = time.monotonic() if self.ceremony.use_fake else time.monotonic() + 8
        last_detail = 'no token matched'
        while True:
            slots = list(lib.get_slots())
            if not slots:
                last_detail = 'no PKCS#11 slots (pcscd is not serving a reader)'
            else:
                errors = []
                for slot in slots:
                    try:
                        candidate = slot.get_token()
                    except Exception as exc:  # noqa: BLE001
                        errors.append(str(exc).strip() or type(exc).__name__)
                        continue
                    if not token_label:
                        return candidate
                    label = (getattr(candidate, 'label', '') or '').strip()
                    if label == token_label:
                        return candidate
                last_detail = '; '.join(errors) if errors else 'no token matched'
            if time.monotonic() >= deadline:
                break
            time.sleep(0.3)
        raise RuntimeError(f'token {token_label!r} not found ({last_detail})')

    def _pkcs11_sign(self, data: bytes, hash_algorithm: str) -> bytes:
        try:
            import pkcs11
            from pkcs11 import Mechanism
        except ImportError as exc:
            raise RuntimeError('python-pkcs11 not installed') from exc

        module_path = os.getenv(
            'OPENSC_PKCS11_PATH',
            '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
        )
        lib = pkcs11.lib(module_path)
        token_label = os.getenv('SC_HSM_TOKEN_LABEL', '')
        pin = self._pkcs11_login_pin()
        if not self.ceremony.use_fake:
            self._present_live_card()
        token = self._find_pkcs11_token(lib, token_label)
        mech_map = {
            'sha256': Mechanism.SHA256_RSA_PKCS,
            'sha384': Mechanism.SHA384_RSA_PKCS,
            'sha512': Mechanism.SHA512_RSA_PKCS,
        }
        mechanism = mech_map.get(hash_algorithm, Mechanism.SHA256_RSA_PKCS)
        key_ref = bytes(((self.ceremony.root_key_id or ROOT_KEY_ID) & 0xFF,))
        with token.open(user_pin=pin or None) as session:
            # Select the root key by its id. Another private key on the
            # card must never be used in its place.
            keys = list(session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.Attribute.ID: key_ref,
            }))
            if len(keys) != 1:
                raise RuntimeError(
                    f'expected one private key with id {key_ref.hex()} on the assembly token, found {len(keys)}'
                )
            return keys[0].sign(data, mechanism=mechanism)

    def _pkcs11_roll_key(self) -> Tuple[str, bytes]:
        """Generate the root key and wrap it as two separate logins.

        Called only after the new DKEK shares have been imported, so the wrap
        blob is recoverable with those shares. The first login generates the
        key and logs out. The second login presents the same user PIN again
        and sends the wrap command before that session logs out. A wrap after
        logout is refused by the card with SW=6982.
        """
        try:
            import pkcs11
            from pkcs11 import Attribute, KeyType
        except ImportError as exc:
            raise RuntimeError('python-pkcs11 not installed') from exc

        module_path = os.getenv(
            'OPENSC_PKCS11_PATH',
            '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
        )
        lib = pkcs11.lib(module_path)
        token_label = os.getenv('SC_HSM_TOKEN_LABEL', '')
        pin = self._pkcs11_login_pin()
        if not self.ceremony.use_fake:
            self._present_live_card()
        token = self._find_pkcs11_token(lib, token_label)
        key_id = self.ceremony.root_key_id or ROOT_KEY_ID
        key_ref = bytes((key_id,))
        self._assembly_busy = True
        try:
            # Key generation is a write. The default PKCS#11 session is
            # read-only and the card returns CKR_SESSION_READ_ONLY.
            with token.open(rw=True, user_pin=pin) as session:
                public, _private = session.generate_keypair(
                    KeyType.RSA,
                    2048,
                    store=True,
                    label='ucm-root',
                    public_template={
                        Attribute.VERIFY: True,
                        Attribute.ID: key_ref,
                    },
                    private_template={
                        Attribute.SIGN: True,
                        Attribute.ID: key_ref,
                    },
                )
                modulus = int.from_bytes(public[Attribute.MODULUS], 'big')
                exponent = int.from_bytes(public[Attribute.PUBLIC_EXPONENT], 'big')
            public_key = rsa_mod.RSAPublicNumbers(exponent, modulus).public_key()
            public_pem = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('ascii')
            with token.open(rw=True, user_pin=pin) as session:
                # This login exists so the wrap is authenticated. It ends
                # only after the card has answered.
                if session is None:
                    raise RuntimeError('wrap login failed')
                rapdu = self.transmit_assembly(apdu_wrap_key(key_id))
            data, sw1, sw2 = parse_sw(rapdu)
            if not sw_ok(sw1, sw2) or not data:
                sw = f'{sw1:02X}{sw2:02X}'
                if sw == '6985':
                    raise RuntimeError(
                        'wrap key failed SW=6985. The card will not export this '
                        'key. It has to be in the DKEK domain created when the '
                        'token was initialized.'
                    )
                raise RuntimeError(f'wrap key failed SW={sw}')
            return public_pem, data
        finally:
            self._assembly_busy = False

    def _pkcs11_login_pin(self) -> str:
        """User PIN of the assembly token for this window.

        Custodians do not have access to the UCM host. The PIN is the one
        entered for the card that is present and selected, not a server
        environment variable.
        """
        pin = self.ceremony.user_pin()
        if not pin:
            raise RuntimeError(
                'Enter the user PIN of the token selected as the assembly device. '
                'It is kept for this signing window only.'
            )
        return pin

    def _wipe_unlocked(self) -> bool:
        """Delete rebuilt key; return True only when verified gone."""
        key_id = self.ceremony.root_key_id
        if self.ceremony.use_fake and self.ceremony.fake is not None:
            ok = self.ceremony.fake.wipe_root()
            remaining = self.ceremony.fake.list_key_ids()
            verified = ok and key_id not in remaining
            self.ceremony.key_assembled = not verified
            self.ceremony.wipe_verified = verified
            if verified:
                self.ceremony.public_key_pem = None
            return verified

        rapdu = self.transmit_assembly(apdu_delete_key_file(key_id))
        _, sw1, sw2 = parse_sw(rapdu)
        if not sw_ok(sw1, sw2) and not (sw1 == 0x6A and sw2 == 0x82):
            self.ceremony.wipe_verified = False
            return False
        if self.ceremony.device_scheme != 'random':
            # The imported shares rebuilt the DKEK on this card. Left in
            # place, this one card plus the stored wrapped blob would unwrap
            # the root again without the other custodians.
            cleared = self.transmit_assembly(apdu_clear_kek())
            _, sw1, sw2 = parse_sw(cleared)
            if not sw_ok(sw1, sw2) and (sw1, sw2) not in ((0x6A, 0x88), (0x6A, 0x82)):
                logger.warning('clear DKEK after wipe failed SW=%02X%02X', sw1, sw2)
                self.ceremony.wipe_verified = False
                return False
        # Verified wipe: list via PKCS#11 when available; else trust delete SW.
        verified = True
        try:
            import pkcs11
            module_path = os.getenv(
                'OPENSC_PKCS11_PATH',
                '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
            )
            lib = pkcs11.lib(module_path)
            for slot in lib.get_slots():
                try:
                    t = slot.get_token()
                    with t.open() as session:
                        keys = list(session.get_objects({
                            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                        }))
                        if keys:
                            verified = False
                except Exception:  # noqa: BLE001
                    continue
        except ImportError:
            pass
        self.ceremony.wipe_verified = verified
        if verified:
            self.ceremony.key_assembled = False
            self.ceremony.public_key_pem = None
        return verified

    def cmd_wipe_assembly(self, params: dict) -> dict:
        with self.ceremony.lock:
            if not self.ceremony.key_assembled and self.ceremony.wipe_verified:
                return {'ok': True, 'already_wiped': True, 'ceremony': self.ceremony.snapshot()}
            # Refuse wipe until CRL regenerated after latest change (unless forced).
            if not params.get('force'):
                if (
                    self.ceremony.key_assembled
                    and self.ceremony.last_change_seq > 0
                    and self.ceremony.crl_seq_at_sign < self.ceremony.last_change_seq
                ):
                    return {
                        'ok': False,
                        'error': 'CRL must be regenerated after the latest change before wipe',
                        'ceremony': self.ceremony.snapshot(),
                    }
            if self.pka is not None:
                return self._pka_lock()
            # If nothing was ever assembled, treat wipe as success (nothing to delete).
            if not self.ceremony.key_assembled:
                self.ceremony.wipe_verified = True
                return {
                    'ok': True,
                    'already_wiped': True,
                    'wipe_verified': True,
                    'ceremony': self.ceremony.snapshot(),
                }
            verified = self._wipe_unlocked()
            if not verified:
                return {
                    'ok': False,
                    'error': 'wipe could not be verified; window stays open',
                    'ceremony': self.ceremony.snapshot(),
                }
            return {'ok': True, 'wipe_verified': True, 'ceremony': self.ceremony.snapshot()}

    def _pka_lock(self) -> dict:
        """End root key use: reset the root HSM and read back zero authentications."""
        engine = self.pka
        try:
            verified = engine.lock_device()
        except (PkaRefused, pka.PkaError, RuntimeError, TimeoutError) as exc:
            verified = False
            self.ceremony.error = f'lock failed: {exc}'
        self._sync_pka_flags()
        with self.ceremony.lock:
            self.ceremony.wipe_verified = verified
            if verified:
                self.ceremony.key_assembled = False
        if not verified:
            return {
                'ok': False,
                'error': (
                    'the root HSM could not be confirmed locked; keep the window open, '
                    'reconnect the root HSM and lock again, or power it off at the site'
                ),
                'ceremony': self.ceremony.snapshot(),
                'pka': engine.snapshot(),
            }
        return {'ok': True, 'wipe_verified': True, 'ceremony': self.ceremony.snapshot(), 'pka': engine.snapshot()}

    def _roster_custodian_ids(self) -> List[str]:
        with self._token_lock:
            metas = list(self._token_map.values())
        metas.sort(key=lambda meta: (int(meta.get('share_index') or 0), str(meta.get('custodian_id'))))
        ids: List[str] = []
        for meta in metas:
            cid = str(meta['custodian_id'])
            if cid not in ids:
                ids.append(cid)
        return ids

    def _domain_waiting_for_shares(self) -> bool:
        """True when the default domain still expects every configured share."""
        rapdu = self.transmit_assembly(apdu_get_key_domain_status())
        data, sw1, sw2 = parse_sw(rapdu)
        if not sw_ok(sw1, sw2):
            return False
        parsed = parse_key_domain_status(data)
        outstanding = parsed.get('outstanding_shares')
        configured = parsed.get('dkek_shares')
        return bool(outstanding and configured and outstanding == configured)

    def _clear_kek_ready(self) -> bool:
        """Clear the DKEK. SW=6985 is success only while the domain is still empty."""
        cleared = self.transmit_assembly(apdu_clear_kek())
        _, sw1, sw2 = parse_sw(cleared)
        if sw_ok(sw1, sw2):
            return True
        if (sw1, sw2) in ((0x6A, 0x88), (0x6A, 0x82), (0x6A, 0x86)):
            return True
        if (sw1, sw2) == (0x69, 0x85):
            return self._domain_waiting_for_shares()
        raise RuntimeError(f'clear DKEK failed SW={sw1:02X}{sw2:02X}')

    def _reset_assembly_domain(self, share_count: int) -> None:
        """Clear the initialized domain so it can take a new set of shares.

        PKCS#11 places the new key in the default domain created by device
        initialization. Deleting that domain and creating another one leaves
        the key outside the exportable DKEK, and WRAP returns SW=6985.
        A completed device key also makes CLEAR KEK and IMPORT return SW=6985.
        The stored root key is removed first, then the domain is cleared.
        ``share_count`` is the threshold the card was initialized with.
        """
        del share_count
        if self._clear_kek_ready():
            return
        self._ignore_missing(self.transmit_assembly(apdu_delete_key_file(ROOT_KEY_ID)))
        if self._clear_kek_ready():
            return
        raise RuntimeError(
            'The assembly card already has a device key and will not import '
            'a new share (SW=6985). Reinitialize that token in this window, '
            'then create the root key again.'
        )

    def _mark_device_dkek_ready(self) -> None:
        fake = self.ceremony.fake
        if fake is None:
            return
        fake.outstanding = 0
        fake._dkek_ready = True

    def _store_installed_root(self, public_pem: str, wrapped: bytes, shares_written: int) -> dict:
        with self.ceremony.lock:
            self.ceremony.wrapped_root_b64 = base64.b64encode(wrapped).decode('ascii')
            self.ceremony.public_key_pem = public_pem
            self.ceremony.key_assembled = True
            if self.ceremony.fake is not None and self.ceremony.fake.root_key_id is not None:
                self.ceremony.root_key_id = self.ceremony.fake.root_key_id
            self.ceremony.wipe_verified = False
            self.ceremony.mark_change()
        return {
            'ok': True,
            'public_key_pem': public_pem,
            'wrapped_root_b64': self.ceremony.wrapped_root_b64,
            'shares_written': shares_written,
            'ceremony': self.ceremony.snapshot(),
        }

    def _generate_on_device_dkek(self) -> Tuple[str, bytes]:
        """Generate and wrap a key under the DKEK already on the card.

        A random DKEK never leaves the token. Clearing it or importing shares
        would replace that device key.
        """
        with self.ceremony.lock:
            use_fake = self.ceremony.use_fake and self.ceremony.fake is not None
        if use_fake:
            self._mark_device_dkek_ready()
            return self.ceremony.fake.rotate_signing_key()
        self._ignore_missing(self.transmit_assembly(apdu_delete_key_file(ROOT_KEY_ID)))
        return self._pkcs11_roll_key()

    def _install_device_dkek_root(self, assembly_custodian_id: str) -> dict:
        connected = self.sessions.connected_custodians()
        if assembly_custodian_id not in connected:
            return {'ok': False, 'error': 'assembly token is not connected'}
        with self.ceremony.lock:
            self.ceremony.assembly_custodian_id = assembly_custodian_id
            self.ceremony.error = None
        try:
            public_pem, wrapped = self._generate_on_device_dkek()
        except Exception as exc:  # noqa: BLE001
            logger.exception('create root key failed')
            self._abort_partial_assembly()
            message = str(exc).strip() or type(exc).__name__
            return {'ok': False, 'error': message, 'ceremony': self.ceremony.snapshot()}
        logger.info('root key created on custodian %s under device DKEK', assembly_custodian_id)
        return self._store_installed_root(public_pem, wrapped, 0)

    def _assemble_device_dkek(self, assembly_custodian_id: str) -> dict:
        with self.ceremony.lock:
            self.ceremony.assembly_custodian_id = assembly_custodian_id
            self.ceremony.error = None
            use_fake = self.ceremony.use_fake and self.ceremony.fake is not None
        try:
            if use_fake:
                self._mark_device_dkek_ready()
            unwrapped = self.cmd_unwrap_root({})
            if not unwrapped.get('ok'):
                raise RuntimeError(unwrapped.get('error') or 'unwrap failed')
            self._remember_public_key()
        except Exception as exc:  # noqa: BLE001
            logger.exception('assembly failed')
            self._abort_partial_assembly()
            return {'ok': False, 'error': str(exc), 'ceremony': self.ceremony.snapshot()}
        return {'ok': True, 'ceremony': self.ceremony.snapshot()}

    def _roll_device_dkek(self) -> dict:
        cid = self.ceremony.assembly_custodian_id
        if not cid or cid not in self.sessions.connected_custodians():
            return {'ok': False, 'error': 'assembly token is not connected'}
        try:
            public_pem, wrapped = self._generate_on_device_dkek()
        except Exception as exc:  # noqa: BLE001
            logger.exception('key roll failed')
            return {'ok': False, 'error': str(exc), 'ceremony': self.ceremony.snapshot()}
        return self._store_installed_root(public_pem, wrapped, 0)

    def _install_new_root(self, assembly_custodian_id: str) -> dict:
        """Write one share per custodian, import the threshold, and generate the key.

        Share bytes are not returned. The wrapped blob is, so UCM can store it.
        """
        with self.ceremony.lock:
            threshold = self.ceremony.threshold_n
            total = self.ceremony.total_m
            use_fake = self.ceremony.use_fake and self.ceremony.fake is not None
        connected = self.sessions.connected_custodians()
        if assembly_custodian_id not in connected:
            return {'ok': False, 'error': 'assembly token is not connected'}
        if len(connected) < total:
            return {
                'ok': False,
                'error': (
                    f'every custodian must be connected; '
                    f'need {total}, have {len(connected)}'
                ),
            }
        with self.ceremony.lock:
            self.ceremony.assembly_custodian_id = assembly_custodian_id
            self.ceremony.error = None
        shares = generate_dkek_shares(threshold, total)
        try:
            custodian_ids = self._roster_custodian_ids()
            if len(custodian_ids) != len(shares):
                raise RuntimeError('custodian roster does not match share count')
            try:
                for cid, share in zip(custodian_ids, shares):
                    self._write_share(cid, share)
                if use_fake:
                    public_pem, wrapped = self.ceremony.fake.rotate_signing_key()
                self._reset_assembly_domain(threshold)
                self._import_threshold(custodian_ids, threshold)
                if use_fake:
                    key_id = self.ceremony.root_key_id or ROOT_KEY_ID
                    rapdu = self.transmit_assembly(apdu_unwrap_key(key_id))
                    _, sw1, sw2 = parse_sw(rapdu)
                    if not sw_ok(sw1, sw2):
                        raise RuntimeError(f'unwrap after create failed SW={sw1:02X}{sw2:02X}')
                else:
                    public_pem, wrapped = self._pkcs11_roll_key()
            finally:
                for share in shares:
                    _zeroize(bytearray(share))
            with self.ceremony.lock:
                self.ceremony.wrapped_root_b64 = base64.b64encode(wrapped).decode('ascii')
                self.ceremony.public_key_pem = public_pem
                self.ceremony.key_assembled = True
                if self.ceremony.fake is not None and self.ceremony.fake.root_key_id is not None:
                    self.ceremony.root_key_id = self.ceremony.fake.root_key_id
                self.ceremony.wipe_verified = False
                self.ceremony.mark_change()
            logger.info(
                'root key created on custodian %s shares_written=%s',
                assembly_custodian_id,
                len(custodian_ids),
            )
            return {
                'ok': True,
                'public_key_pem': public_pem,
                'wrapped_root_b64': self.ceremony.wrapped_root_b64,
                'shares_written': len(custodian_ids),
                'ceremony': self.ceremony.snapshot(),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception('create root key failed')
            self._abort_partial_assembly()
            message = str(exc).strip() or type(exc).__name__
            return {'ok': False, 'error': message, 'ceremony': self.ceremony.snapshot()}

    def cmd_create_root_key(self, params: dict) -> dict:
        """First key for this scheme. Does not require a share file or a wrapped root."""
        if params.get('confirm') != 'DELETE':
            return {'ok': False, 'error': 'Type DELETE to create the root key'}
        cid = params.get('assembly_custodian_id')
        if cid is None:
            return {'ok': False, 'error': 'assembly_custodian_id required'}
        cid = str(cid)
        with self.ceremony.lock:
            if not self.ceremony.active:
                return {'ok': False, 'error': 'no active ceremony'}
            if self.ceremony.key_assembled:
                return {'ok': False, 'error': 'root key is already assembled'}
        user_pin = params.pop('user_pin', None) or ''
        if user_pin:
            self.ceremony.remember_user_pin(user_pin)
        if self._remember_scheme(params) == 'random':
            return self._install_device_dkek_root(cid)
        if self.ceremony.device_scheme not in ('shares', 'random'):
            return {
                'ok': False,
                'error': 'Create root key applies to an n-of-m share provider or a random DKEK',
            }
        return self._install_new_root(cid)

    def cmd_roll_root_key(self, params: dict) -> dict:
        """Generate a new root key on the assembly token, wrap it, and replace shares.

        New share blobs are written onto the connected custodian tokens and then
        zeroized in this process. They are not included in the response. The
        wrapped blob is returned so UCM can replace the stored copy.
        """
        with self.ceremony.lock:
            if not self.ceremony.active or not self.ceremony.key_assembled:
                return {'ok': False, 'error': 'root key is not assembled'}
            threshold = self.ceremony.threshold_n
            total = self.ceremony.total_m
            use_fake = self.ceremony.use_fake and self.ceremony.fake is not None
        connected = self.sessions.connected_custodians()
        scheme = self._remember_scheme(params or {})
        if scheme != 'random' and len(connected) < total:
            return {
                'ok': False,
                'error': (
                    f'key roll hands a new share to every custodian; '
                    f'need {total} connected tokens, have {len(connected)}'
                ),
            }
        user_pin = (params or {}).pop('user_pin', None) or ''
        if user_pin:
            self.ceremony.remember_user_pin(user_pin)
        if scheme == 'random':
            return self._roll_device_dkek()
        try:
            shares = generate_dkek_shares(threshold, total)
            # Same share_index order as create. _token_map is keyed by connect
            # token, so iterating it does not follow the roster.
            custodian_ids = self._roster_custodian_ids()
            if len(custodian_ids) != len(shares):
                raise RuntimeError('custodian roster does not match share count')
            try:
                for cid, share in zip(custodian_ids, shares):
                    self._write_share(cid, share)
                # New shares first, then a key domain that contains only those
                # shares, then the new key. On the fake chip the RSA key object
                # survives delete-domain; a live token generates the key after
                # the new DKEK is imported so the wrap matches the new shares.
                if use_fake:
                    public_pem, wrapped = self.ceremony.fake.rotate_signing_key()
                self._reset_assembly_domain(threshold)
                self._import_threshold(custodian_ids, threshold)
                if use_fake:
                    key_id = self.ceremony.root_key_id or ROOT_KEY_ID
                    rapdu = self.transmit_assembly(apdu_unwrap_key(key_id))
                    _, sw1, sw2 = parse_sw(rapdu)
                    if not sw_ok(sw1, sw2):
                        raise RuntimeError(f'unwrap after roll failed SW={sw1:02X}{sw2:02X}')
                else:
                    public_pem, wrapped = self._pkcs11_roll_key()
            finally:
                for share in shares:
                    buf = bytearray(share)
                    _zeroize(buf)
            with self.ceremony.lock:
                self.ceremony.wrapped_root_b64 = base64.b64encode(wrapped).decode('ascii')
                self.ceremony.public_key_pem = public_pem
                self.ceremony.key_assembled = True
                if self.ceremony.fake is not None and self.ceremony.fake.root_key_id is not None:
                    self.ceremony.root_key_id = self.ceremony.fake.root_key_id
                self.ceremony.wipe_verified = False
                self.ceremony.mark_change()
            return {
                'ok': True,
                'public_key_pem': public_pem,
                'wrapped_root_b64': self.ceremony.wrapped_root_b64,
                'shares_written': len(custodian_ids),
                'ceremony': self.ceremony.snapshot(),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception('key roll failed')
            return {'ok': False, 'error': str(exc), 'ceremony': self.ceremony.snapshot()}

    def cmd_end_ceremony(self, params: dict) -> dict:
        engine = self.pka
        sealed = None
        if engine is not None:
            ever_authenticated = engine.unlocked_logged or bool(engine.authenticated)
            if ever_authenticated and not engine.locked_verified and not params.get('force'):
                return {
                    'ok': False,
                    'error': 'lock the root HSM before closing the window',
                    'ceremony': self.ceremony.snapshot(),
                    'pka': engine.snapshot(),
                }
            sealed = engine.seal()
            with self.ceremony.lock:
                self.pka = None
                self._pka_fake = None
                self._pka_fake_connected = False
                self.ceremony.key_assembled = False
                self.ceremony.wipe_verified = True
        with self.ceremony.lock:
            if self.ceremony.key_assembled and not self.ceremony.wipe_verified:
                if not params.get('force'):
                    return {
                        'ok': False,
                        'error': 'assembled key still present; wipe_assembly first',
                        'ceremony': self.ceremony.snapshot(),
                    }
            self.ceremony.active = False
            self.ceremony.key_assembled = False
            self.ceremony.assembly_custodian_id = None
            self.ceremony.clear_user_pin()
            self.ceremony.public_key_pem = None
            self.ceremony.fake = None
            cards = list(self.ceremony.custodian_cards.values())
            self.ceremony.custodian_cards = {}
        for card in cards:
            card.zeroize()
        self.sessions.set_ceremony_active(False)
        self.sessions.drop_all('end_ceremony')
        with self._token_lock:
            self._token_map.clear()
        result = {'ok': True, 'ceremony': self.ceremony.snapshot()}
        if sealed is not None:
            result['transcript'] = sealed
        return result

    # -- servers --------------------------------------------------------------

    def start(self) -> None:
        self._start_control_socket()
        self._start_vpcd_client()
        self._start_http()
        logger.info(
            'ram-bridge ready RAM_PORT=%s sock=%s vpcd=%s:%s',
            self.ram_port, self.sock_path, self.vpcd_host, self.vpcd_port,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._vpcd is not None:
            self._vpcd.stop()
            self._vpcd = None
        if self._http is not None:
            try:
                self._http.shutdown()
            except Exception:  # noqa: BLE001
                pass
            self._http = None
        if self._control_sock is not None:
            try:
                self._control_sock.close()
            except OSError:
                pass
            self._control_sock = None
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except OSError:
            pass
        self.sessions.drop_all('bridge_stop')

    def _start_vpcd_client(self) -> None:
        self._vpcd = VpcdClient(
            host=self.vpcd_host,
            port=self.vpcd_port,
            card_factory=self._make_vpcd_card,
        )
        self._vpcd.start()

    def _start_control_socket(self) -> None:
        path = self.sock_path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Create the socket file 0600 from the start. A chmod after bind
        # leaves a moment where another local user could connect.
        previous_umask = os.umask(0o177)
        try:
            sock.bind(path)
        finally:
            os.umask(previous_umask)
        try:
            os.chmod(path, 0o600)
        except OSError:
            logger.warning('could not chmod 600 %s', path)
        sock.listen(32)
        sock.settimeout(1.0)
        self._control_sock = sock
        t = threading.Thread(target=self._control_loop, name='ram-control', daemon=True)
        t.start()
        self._threads.append(t)
        logger.info('control socket %s mode 600', path)

    def _control_loop(self) -> None:
        assert self._control_sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._control_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._serve_control_conn,
                args=(conn,),
                name='ram-control-conn',
                daemon=True,
            ).start()

    def _serve_control_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(60.0)
            buf = b''
            while b'\n' not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_BODY_BYTES:
                    raise ValueError('control request too large')
            line = buf.split(b'\n', 1)[0]
            request = json.loads(line.decode('utf-8'))
            response = self.handle_control(request)
            conn.sendall((json.dumps(response) + '\n').encode('utf-8'))
        except Exception as exc:  # noqa: BLE001
            try:
                conn.sendall(
                    (json.dumps({'ok': False, 'error': str(exc)}) + '\n').encode('utf-8')
                )
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _start_http(self) -> None:
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, fmt, *args):  # noqa: N802
                logger.debug('ram-http: ' + fmt, *args)

            def do_POST(self):  # noqa: N802
                path = self.path.split('?', 1)[0]
                prefix = '/hsm/ram/'
                if not path.startswith(prefix):
                    self.send_error(404)
                    return
                token = path[len(prefix):].strip('/')
                if not token or '/' in token:
                    self.send_error(404)
                    return
                raw_length = (self.headers.get('Content-Length') or '0').strip()
                if not raw_length.isdigit():
                    self.send_error(400)
                    return
                length = int(raw_length)
                if length > MAX_BODY_BYTES:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else b''
                meta = bridge.resolve_token(token)
                if meta is None:
                    self.send_error(404)
                    return
                try:
                    status, out = bridge.handle_ram_post(token, body)
                except SessionBusyError:
                    self.send_response(409)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'slot occupied')
                    return
                except Exception:  # noqa: BLE001
                    logger.exception('RAM POST failed')
                    self.send_error(500)
                    return
                self.send_response(status)
                if status == 200:
                    self.send_header('Content-Type', CONTENT_TYPE)
                    self.send_header('X-Admin-Protocol', ADMIN_PROTOCOL)
                    self.send_header('Content-Length', str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                elif status == 204:
                    self.end_headers()
                else:
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(out or b'')

        cert, key = _cert_paths()
        have_tls = os.path.isfile(cert) and os.path.isfile(key)
        if not have_tls and not self.allow_plaintext:
            # Fail closed: the RAM channel carries card traffic.
            raise RuntimeError(
                f'RAM listener needs a TLS certificate ({cert}, {key}). '
                'Set HTTPS_CERT_PATH/HTTPS_KEY_PATH, or RAM_BRIDGE_ALLOW_PLAINTEXT=1 '
                'for local development only.'
            )
        httpd = ThreadingHTTPServer((self.bind_host, self.ram_port), Handler)
        if have_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=cert, keyfile=key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            logger.info('TLS enabled with %s', cert)
        else:
            logger.warning(
                'RAM_BRIDGE_ALLOW_PLAINTEXT is set; listening without TLS (development only)',
            )
        self._http = httpd
        t = threading.Thread(target=httpd.serve_forever, name='ram-http', daemon=True)
        t.start()
        self._threads.append(t)

    def handle_ram_post(self, connect_token: str, body: bytes) -> Tuple[int, bytes]:
        """Process one ram-client POST. Returns (http_status, body)."""
        session = self.sessions.get_by_token(connect_token)
        if session is None:
            return 404, b'unknown token'

        # Initiation: E8 template with ATR
        if body and body[0] == 0xE8:
            initiation = InitiationRequest.decode(body)
            session = self.sessions.accept_client(connect_token, initiation)
            logger.info(
                'ram-client connected custodian %s atr_len=%s',
                session.custodian_id,
                len(session.atr or b''),
            )
            if self.pka is not None and session.custodian_id == ROOT_SLOT_ID:
                # Identify the device on a worker thread: its APDUs travel
                # through this client's next long-poll requests.
                self._pka_attach_async(session.session_id)
            else:
                self._present_live_card()
            # First reply: keepalive or pending work
            tmpl = session.build_request(keepalive_if_idle=True)
            return 200, tmpl.encode()

        # Subsequent: AB response template, then wait for next AA
        if body and body[0] == 0xAB:
            response = ResponseTemplate.decode(body)
            session.apply_response(response)
        elif body:
            raise RamProtocolError(f'unexpected body tag 0x{body[0]:02X}')

        if session.state.value == 'closed':
            return 204, b''

        # Long-poll for work or keepalive
        session.wait_for_work(LONG_POLL_SECONDS)
        if session.state.value == 'closed':
            return 204, b''
        tmpl = session.build_request(keepalive_if_idle=True)
        if is_empty_keepalive(tmpl) and self._stop.is_set():
            return 204, b''
        return 200, tmpl.encode()

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        finally:
            self.stop()


def main(argv: Optional[List[str]] = None) -> int:
    level_name = os.getenv('RAM_BRIDGE_LOG', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)
    log_path = install_follower_handler(root, formatter)
    if log_path is not None:
        logger.info('application log %s', log_path)
    bridge = RamBridge()

    def _shutdown(signum, _frame):
        logger.info('signal %s, shutting down', signum)
        bridge._stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        bridge.serve_forever()
    except Exception:
        logger.exception('ram-bridge crashed')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
