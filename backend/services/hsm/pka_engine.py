"""Root-HSM side of a public key authentication ceremony (runs in the RAM bridge).

The bridge relays APDUs to one root SmartCard-HSM. Keyholders never connect a
card to the bridge: they sign challenges on their own machines and UCM hands
the signatures over. See ``docs/design/sc-hsm-remote-ceremony-pka.md``.

Everything here fails closed. A wrong device, a PKA configuration that does
not match the provider, an expired window, an exhausted signature budget or a
missing quorum refuses the operation.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from services.hsm import sc_hsm_pka as pka
from services.hsm.sc_hsm_apdu import apdu_select_hsm, parse_sw, sw_ok

logger = logging.getLogger('ucm.ram_bridge.pka')

ROOT_SLOT_ID = 'root'
ROOT_KEY_ID = 1
CHALLENGE_TTL_SECONDS = 120.0
STATUS_REFRESH_SECONDS = 5.0
ROOT_KEY_CHR = 'UCMROOT00001'


class PkaRefused(RuntimeError):
    """An operation the ceremony state does not allow."""


class PkaCeremony:
    def __init__(
        self,
        *,
        provider_id: Optional[int],
        ceremony_id: str,
        threshold_n: int,
        total_m: int,
        keyholders: Dict[str, pka.KeyholderKey],
        pinned_device_chr: Optional[str],
        public_key_pem: Optional[str],
        manifest: dict,
        max_signatures: int,
        expires_at: float,
        transmit: Callable[[bytes], bytes],
        reset: Callable[[], bytes],
        connected: Callable[[], bool],
    ):
        if threshold_n < 1 or threshold_n > total_m:
            raise PkaRefused('threshold must be between 1 and the number of keyholders')
        if len(keyholders) != total_m:
            raise PkaRefused(
                f'every keyholder must be enrolled before a window opens; '
                f'have {len(keyholders)} of {total_m}'
            )
        chrs = [key.chr for key in keyholders.values()]
        if len(set(chrs)) != len(chrs):
            raise PkaRefused('two keyholders share the same key reference')
        self.lock = threading.RLock()
        self.provider_id = provider_id
        self.ceremony_id = ceremony_id
        self.threshold_n = threshold_n
        self.total_m = total_m
        self.keyholders = keyholders
        self.pinned_device_chr = pinned_device_chr or None
        self.public_key_pem = public_key_pem or None
        self.manifest = manifest
        self.manifest_digest = pka.manifest_hash(manifest)
        self.max_signatures = int(max_signatures)
        self.signatures_used = 0
        self.expires_at = float(expires_at)
        self._transmit = transmit
        self._reset = reset
        self._connected = connected
        self.device_chr: Optional[str] = None
        self.device_error: Optional[str] = None
        self.hsm_status: Optional[dict] = None
        self.config_error: Optional[str] = None
        self._status_at = 0.0
        self._device_session: Optional[str] = None
        self.approvals: Set[str] = set()
        self.authenticated: Set[str] = set()
        self._challenge: Optional[dict] = None
        self.unlocked_logged = False
        self.locked_verified = False
        self.transcript = pka.Transcript()
        self.transcript.append('opened', {
            'ceremony_id': ceremony_id,
            'provider_id': provider_id,
            'manifest_sha256': self.manifest_digest.hex(),
            'threshold_n': threshold_n,
            'total_m': total_m,
            'max_signatures': self.max_signatures,
            'pinned_device_chr': self.pinned_device_chr,
            'keyholders': {
                cid: key.fingerprint for cid, key in sorted(keyholders.items())
            },
        })

    # -- card I/O -----------------------------------------------------------

    def _apdu(self, apdu: bytes, what: str) -> bytes:
        data, sw1, sw2 = parse_sw(self._transmit(apdu))
        if not sw_ok(sw1, sw2):
            raise PkaRefused(f'{what} failed SW={sw1:02X}{sw2:02X}')
        return data

    def _read_device_chain(self) -> bytes:
        self._apdu(apdu_select_hsm(), 'select SmartCard-HSM')
        self._apdu(pka.apdu_select_ef(pka.DEVICE_CERT_FID), 'select device certificate')
        data = b''
        for _ in range(32):
            chunk = self._apdu(pka.apdu_read_binary(len(data)), 'read device certificate')
            data += chunk
            if len(chunk) < 0xE0:
                break
        return data

    def _read_status(self) -> dict:
        status = pka.parse_pka_status(self._apdu(pka.apdu_pka_status(), 'read PKA status'))
        self.hsm_status = status
        self._status_at = time.monotonic()
        problems = []
        if status['total'] != self.total_m:
            problems.append(f"device has {status['total']} keyholder slots, provider has {self.total_m}")
        if status['required'] != self.threshold_n:
            problems.append(f"device requires {status['required']}, provider threshold is {self.threshold_n}")
        if status['missing']:
            problems.append(f"{status['missing']} keyholder keys are not registered on the device")
        self.config_error = '; '.join(problems) or None
        return status

    def attach(self, session_id: str) -> None:
        """Read the device identity once per root connection.

        A device that still reports authenticated keyholders from an earlier
        session is reset so nothing carries over into this window.
        """
        with self.lock:
            if self._device_session == session_id and self.device_chr:
                return
            self.device_chr = None
            self.device_error = None
            self.authenticated.clear()
            self._challenge = None
            try:
                device, _dica = pka.parse_device_certificate(self._read_device_chain())
                self.device_chr = device.chr
                status = self._read_status()
                if status['authenticated']:
                    self._reset()
                    self._apdu(apdu_select_hsm(), 'select SmartCard-HSM')
                    status = self._read_status()
                    self.transcript.append('stale_authentication_cleared', {})
                    if status['authenticated']:
                        raise PkaRefused('device still reports authenticated keyholders after reset')
            except (PkaRefused, pka.PkaError, RuntimeError, TimeoutError) as exc:
                self.device_error = str(exc)[:200]
                logger.warning('root HSM attach failed: %s', self.device_error)
                return
            self._device_session = session_id
            mismatch = bool(self.pinned_device_chr and self.device_chr != self.pinned_device_chr)
            if mismatch:
                self.device_error = (
                    f'connected device {self.device_chr} is not the pinned root HSM '
                    f'{self.pinned_device_chr}'
                )
            self.transcript.append('device', {
                'device_chr': self.device_chr,
                'pinned': self.pinned_device_chr,
                'matches_pin': not mismatch if self.pinned_device_chr else None,
                'pka_status': self.hsm_status,
            })
            logger.info('root HSM attached device=%s pka=%s', self.device_chr, self.hsm_status)

    def detach(self) -> None:
        with self.lock:
            had_quorum = bool(self.authenticated)
            self.authenticated.clear()
            self._challenge = None
            self._device_session = None
            self.hsm_status = None
            if had_quorum or not self.locked_verified:
                self.transcript.append('root_disconnected', {})

    def refresh_status(self) -> Optional[dict]:
        with self.lock:
            if not self._connected() or not self.device_chr:
                return self.hsm_status
            if time.monotonic() - self._status_at < STATUS_REFRESH_SECONDS:
                return self.hsm_status
            try:
                return self._read_status()
            except (PkaRefused, RuntimeError, TimeoutError) as exc:
                self.device_error = str(exc)[:200]
                return self.hsm_status

    # -- checks -----------------------------------------------------------------

    def _require_device(self) -> None:
        if not self._connected():
            raise PkaRefused('the root HSM is not connected')
        if not self.device_chr:
            raise PkaRefused(self.device_error or 'the root HSM has not been identified yet')
        if not self.pinned_device_chr:
            raise PkaRefused('pin the root HSM device before keyholders authenticate')
        if self.device_chr != self.pinned_device_chr:
            raise PkaRefused(
                f'connected device {self.device_chr} is not the pinned root HSM {self.pinned_device_chr}'
            )
        if self.device_error:
            raise PkaRefused(self.device_error)
        if self.config_error:
            raise PkaRefused(f'root HSM configuration does not match the provider: {self.config_error}')

    def _require_open(self) -> None:
        if time.time() > self.expires_at:
            raise PkaRefused('the ceremony manifest has expired; close this window and open a new one')

    def _keyholder(self, custodian_id: str) -> pka.KeyholderKey:
        key = self.keyholders.get(str(custodian_id))
        if key is None:
            raise PkaRefused('not a keyholder of this provider')
        return key

    def quorum(self) -> bool:
        status = self.hsm_status or {}
        return (
            len(self.authenticated) >= self.threshold_n
            and int(status.get('authenticated') or 0) >= self.threshold_n
        )

    # -- keyholder steps -------------------------------------------------------

    def pin_device(self, device_chr: str) -> str:
        with self.lock:
            if not self.device_chr:
                raise PkaRefused(self.device_error or 'the root HSM has not been identified yet')
            if device_chr != self.device_chr:
                raise PkaRefused('the confirmed device reference does not match the connected device')
            if self.pinned_device_chr and self.pinned_device_chr != device_chr:
                raise PkaRefused('a different root HSM is already pinned for this provider')
            self.pinned_device_chr = device_chr
            self.device_error = None
            self.transcript.append('device_pinned', {'device_chr': device_chr})
            return device_chr

    def approve(self, custodian_id: str, signature: bytes) -> None:
        with self.lock:
            self._require_open()
            key = self._keyholder(custodian_id)
            pka.verify_keyholder_signature(key, pka.approval_message(self.manifest_digest), signature)
            if custodian_id in self.approvals:
                return
            self.approvals.add(custodian_id)
            self.transcript.append('manifest_approved', {
                'custodian_id': custodian_id,
                'key_fingerprint': key.fingerprint,
                'manifest_sha256': self.manifest_digest.hex(),
                'signature_sha256': hashlib.sha256(signature).hexdigest(),
            })

    def challenge(self, custodian_id: str) -> dict:
        with self.lock:
            self._require_open()
            self._require_device()
            key = self._keyholder(custodian_id)
            if custodian_id not in self.approvals:
                raise PkaRefused('approve the manifest before authenticating')
            if custodian_id in self.authenticated:
                raise PkaRefused('this keyholder has already authenticated in this window')
            pending = self._challenge
            now = time.monotonic()
            if (
                pending
                and pending['custodian_id'] != custodian_id
                and now - pending['at'] < CHALLENGE_TTL_SECONDS
            ):
                raise PkaRefused('another keyholder is authenticating; try again in a moment')
            self._apdu(pka.apdu_select_auth_key(key.chr), 'select keyholder key')
            value = self._apdu(pka.apdu_get_challenge(), 'get challenge')
            if len(value) != 8:
                raise PkaRefused('device returned a challenge of unexpected length')
            self._challenge = {'custodian_id': custodian_id, 'challenge': value, 'at': now}
            device_id = pka.device_id_bytes(self.device_chr or '')
            return {
                'challenge_b64': base64.b64encode(value).decode('ascii'),
                'device_chr': self.device_chr,
                'device_id_b64': base64.b64encode(device_id).decode('ascii'),
                'expires_in': int(CHALLENGE_TTL_SECONDS),
            }

    def authenticate(self, custodian_id: str, signature: bytes) -> dict:
        with self.lock:
            self._require_open()
            self._require_device()
            key = self._keyholder(custodian_id)
            pending = self._challenge
            if not pending or pending['custodian_id'] != custodian_id:
                raise PkaRefused('no challenge is outstanding for this keyholder')
            self._challenge = None
            if time.monotonic() - pending['at'] >= CHALLENGE_TTL_SECONDS:
                raise PkaRefused('the challenge expired; request a new one')
            message = pka.auth_message(pka.device_id_bytes(self.device_chr or ''), pending['challenge'])
            try:
                pka.verify_keyholder_signature(key, message, signature)
            except pka.PkaError:
                self.transcript.append('authentication_rejected', {
                    'custodian_id': custodian_id, 'by': 'ucm',
                })
                raise
            rapdu = self._transmit(pka.apdu_external_authenticate(pka.card_signature(key, signature)))
            _, sw1, sw2 = parse_sw(rapdu)
            if not sw_ok(sw1, sw2):
                self.transcript.append('authentication_rejected', {
                    'custodian_id': custodian_id, 'by': 'device', 'sw': f'{sw1:02X}{sw2:02X}',
                })
                raise PkaRefused(f'the root HSM rejected the authentication SW={sw1:02X}{sw2:02X}')
            self.authenticated.add(custodian_id)
            status = self._read_status()
            self.transcript.append('authenticated', {
                'custodian_id': custodian_id,
                'key_fingerprint': key.fingerprint,
                'device_authenticated': status['authenticated'],
            })
            if self.quorum() and not self.unlocked_logged:
                self.unlocked_logged = True
                self.transcript.append('unlocked', {
                    'authenticated': sorted(self.authenticated),
                })
            return {'authenticated': len(self.authenticated), 'required': self.threshold_n, 'unlocked': self.quorum()}

    # -- root key operations ------------------------------------------------------

    def _require_unlocked(self) -> None:
        self._require_open()
        self._require_device()
        self._read_status()
        if not self.quorum():
            raise PkaRefused(
                f'{len(self.authenticated)} of {self.threshold_n} keyholders have authenticated'
            )

    def _manifest_allows(self, op_type: str) -> bool:
        return any(op.get('type') == op_type for op in self.manifest.get('operations') or [])

    def generate_root_key(self, bits: int = 2048) -> str:
        with self.lock:
            self._require_unlocked()
            if not self._manifest_allows('generate_root_key'):
                raise PkaRefused('the approved manifest does not include root key generation')
            if self.public_key_pem:
                raise PkaRefused('this provider already has a root key; a new root needs a new provider')
            listing = self._apdu(pka.apdu_enumerate_objects(), 'list device objects')
            if bytes((0xCC, ROOT_KEY_ID)) in pka.parse_object_list(listing):
                raise PkaRefused('the root HSM already holds key 1; refusing to overwrite it')
            response = self._apdu(
                pka.apdu_generate_rsa(ROOT_KEY_ID, bits, ROOT_KEY_CHR), 'generate root key',
            )
            public = pka.parse_generated_rsa(response)
            pem = pka.public_key_pem(public)
            self.public_key_pem = pem
            self.transcript.append('key_generated', {
                'key_id': ROOT_KEY_ID,
                'bits': public.key_size,
                'public_key_sha256': hashlib.sha256(pem.encode('ascii')).hexdigest(),
            })
            return pem

    def sign(self, data: bytes, hash_name: str, *, label: str = '', provider_id=None) -> bytes:
        with self.lock:
            if provider_id is not None and self.provider_id is not None and int(provider_id) != int(self.provider_id):
                raise PkaRefused('signing refused: the window is open for a different provider')
            self._require_unlocked()
            if not self.public_key_pem:
                raise PkaRefused('no root key is recorded for this provider')
            if self.signatures_used >= self.max_signatures:
                raise PkaRefused(
                    f'signature budget exhausted ({self.max_signatures}); '
                    'close this window and open one with a new manifest'
                )
            from cryptography.hazmat.primitives import serialization
            public = serialization.load_pem_public_key(self.public_key_pem.encode('ascii'))
            info = pka.digest_info(hash_name, data)
            signature = self._apdu(pka.apdu_sign_pkcs1(ROOT_KEY_ID, info), 'sign')
            pka.verify_rsa_pkcs1(public, data, signature, hash_name)
            self.signatures_used += 1
            self.transcript.append('signed', {
                'label': (label or '')[:200],
                'hash': (hash_name or 'sha256').lower(),
                'tbs_sha256': hashlib.sha256(data).hexdigest(),
                'signature_sha256': hashlib.sha256(signature).hexdigest(),
                'used': self.signatures_used,
                'budget': self.max_signatures,
            })
            return signature

    def lock_device(self) -> bool:
        """Reset the root HSM and confirm no keyholder is still authenticated."""
        with self.lock:
            self.authenticated.clear()
            self._challenge = None
            if not self._connected():
                if not self.unlocked_logged:
                    # The quorum was never reached in this window, so the
                    # device never granted key use. A partial authentication
                    # left on the card is cleared when it next attaches.
                    self.locked_verified = True
                    self.transcript.append('locked', {
                        'verified': True,
                        'reason': 'quorum never reached; root HSM not connected',
                        'signatures_used': self.signatures_used,
                    })
                    return True
                # The device was unlocked and cannot be read back now.
                self.locked_verified = False
                self.transcript.append('lock_unverified', {'reason': 'root HSM not connected'})
                return False
            self._reset()
            self._apdu(apdu_select_hsm(), 'select SmartCard-HSM')
            status = self._read_status()
            self.locked_verified = status['authenticated'] == 0
            self.transcript.append('locked', {
                'device_authenticated': status['authenticated'],
                'verified': self.locked_verified,
                'signatures_used': self.signatures_used,
            })
            return self.locked_verified

    def seal(self) -> dict:
        with self.lock:
            final = self.transcript.seal()
            return {
                'ceremony_id': self.ceremony_id,
                'final_hash': final,
                'entries': self.transcript.to_list(),
            }

    def snapshot(self) -> dict:
        with self.lock:
            status = self.hsm_status or {}
            return {
                'ceremony_id': self.ceremony_id,
                'manifest': self.manifest,
                'manifest_sha256': self.manifest_digest.hex(),
                'device_chr': self.device_chr,
                'pinned_device_chr': self.pinned_device_chr,
                'device_error': self.device_error,
                'config_error': self.config_error,
                'hsm_status': status or None,
                'approved': sorted(self.approvals),
                'authenticated': sorted(self.authenticated),
                'unlocked': self.quorum(),
                'challenge_pending_for': (self._challenge or {}).get('custodian_id'),
                'signatures_used': self.signatures_used,
                'max_signatures': self.max_signatures,
                'expires_at': self.expires_at,
                'has_root_key': bool(self.public_key_pem),
                'locked_verified': self.locked_verified,
                'transcript_head': self.transcript.head.hex(),
                'transcript_entries': len(self.transcript.entries),
            }

    def transcript_entries(self) -> List[dict]:
        with self.lock:
            return self.transcript.to_list()
