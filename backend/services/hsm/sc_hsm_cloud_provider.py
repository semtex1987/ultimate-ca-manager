"""SmartCard-HSM remote provider (``sc-hsm-cloud``).

Proxies BaseHsmProvider methods to the RAM bridge Unix control socket.
Outside a ceremony it reports offline. Signing is refused unless a ceremony
has assembled the key. There is no software-key fallback.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
from typing import Any, Dict, List, Optional

from services.hsm.base_provider import (
    BaseHsmProvider,
    HsmConfigError,
    HsmConnectionError,
    HsmKeyInfo,
    HsmOperationError,
)

logger = logging.getLogger(__name__)

DEFAULT_SOCK = '/opt/ucm/data/ram-bridge.sock'


def is_available() -> bool:
    """Always registerable — the bridge may be down until a ceremony."""
    return True


def call_bridge(
    method: str,
    params: Optional[dict] = None,
    *,
    sock_path: Optional[str] = None,
    timeout: float = 120.0,
) -> dict:
    """One JSON line request / one JSON line response over the control socket."""
    path = sock_path or os.getenv('RAM_BRIDGE_SOCK', DEFAULT_SOCK)
    payload = json.dumps({'method': method, 'params': params or {}}) + '\n'
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(path)
    except OSError as exc:
        raise HsmConnectionError(f'RAM bridge socket unavailable ({path}): {exc}') from exc
    try:
        sock.sendall(payload.encode('utf-8'))
        buf = b''
        while b'\n' not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf:
            raise HsmConnectionError('RAM bridge closed without a response')
        return json.loads(buf.split(b'\n', 1)[0].decode('utf-8'))
    finally:
        try:
            sock.close()
        except OSError:
            pass


class ScHsmCloudProvider(BaseHsmProvider):
    """Remote SmartCard-HSM via the ucm-ram-bridge process.

    Config keys:
      token_label:   PKCS#11 token label of the assembly domain
      threshold_n:   shares required to rebuild the DKEK
      total_m:       total custodians / shares
      module_path:   OpenSC PKCS#11 path (hint for the bridge)
      socket_path:   override for the control socket
      wrapped_root:  encrypted DKEK-wrapped root blob (sensitive)
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.token_label = config.get('token_label') or ''
        self.threshold_n = int(config.get('threshold_n') or 0)
        self.total_m = int(config.get('total_m') or 0)
        self.module_path = config.get('module_path') or ''
        self.socket_path = config.get('socket_path') or os.getenv(
            'RAM_BRIDGE_SOCK', DEFAULT_SOCK,
        )
        if self.threshold_n and self.total_m and self.threshold_n > self.total_m:
            raise HsmConfigError('threshold_n cannot exceed total_m')

    def _call(self, method: str, params: Optional[dict] = None) -> dict:
        return call_bridge(method, params, sock_path=self.socket_path)

    def connect(self) -> bool:
        try:
            status = self._call('status')
        except HsmConnectionError:
            self._connected = False
            raise
        self._connected = bool(status.get('ok'))
        return self._connected

    def disconnect(self) -> None:
        self._connected = False

    def test_connection(self) -> Dict[str, Any]:
        try:
            status = self._call('status')
        except HsmConnectionError as exc:
            return {'success': False, 'message': str(exc)}
        ceremony = status.get('ceremony') or {}
        connected = [
            cid for cid, info in (status.get('custodians') or {}).items()
            if info.get('connected')
        ]
        if ceremony.get('active'):
            msg = (
                f"ceremony open: {len(connected)}/{ceremony.get('total_m') or self.total_m} "
                f"tokens connected; key_assembled={ceremony.get('key_assembled')}"
            )
        else:
            msg = 'offline (no signing window)'
        return {
            'success': True,
            'message': msg,
            'details': {
                'ceremony': ceremony,
                'connected_custodians': connected,
                'vpcd_connected': status.get('vpcd_connected'),
            },
        }

    def ceremony_status(self) -> dict:
        status = self._call('status')
        if not status.get('ok'):
            raise HsmOperationError(status.get('error') or 'status failed')
        return status

    def signing_window_open(self) -> bool:
        try:
            status = self._call('status')
        except HsmConnectionError:
            return False
        ceremony = status.get('ceremony') or {}
        return bool(ceremony.get('active') and ceremony.get('key_assembled'))

    def begin_ceremony(self, params: dict) -> dict:
        result = self._call('begin_ceremony', params)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'begin_ceremony failed')
        return result

    def import_share(self, share: bytes, **kwargs) -> dict:
        params = {
            'share_b64': base64.b64encode(share).decode('ascii'),
            **kwargs,
        }
        result = self._call('import_share', params)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'import_share failed')
        return result

    def unwrap_root(self, wrapped_root: bytes, **kwargs) -> dict:
        params = {
            'wrapped_root_b64': base64.b64encode(wrapped_root).decode('ascii'),
            **kwargs,
        }
        result = self._call('unwrap_root', params)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'unwrap_root failed')
        return result

    def sign_crl(self, data: bytes, **kwargs) -> bytes:
        params = {
            'data_b64': base64.b64encode(data).decode('ascii'),
            'is_crl': True,
            **kwargs,
        }
        result = self._call('sign_crl', params)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'sign_crl failed')
        return base64.b64decode(result['signature_b64'])

    def wipe_assembly(self, **kwargs) -> dict:
        result = self._call('wipe_assembly', kwargs)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'wipe_assembly failed')
        return result

    def end_ceremony(self, **kwargs) -> dict:
        result = self._call('end_ceremony', kwargs)
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'end_ceremony failed')
        return result

    def list_keys(self) -> List[HsmKeyInfo]:
        status = self.ceremony_status()
        ceremony = status.get('ceremony') or {}
        if not ceremony.get('key_assembled'):
            return []
        key_id = ceremony.get('root_key_id')
        return [HsmKeyInfo(
            key_identifier=str(key_id),
            label=self.token_label or 'sc-hsm-root',
            algorithm='RSA-2048',
            key_type='asymmetric',
            purpose='signing',
            public_key_pem=None,
            is_extractable=False,
        )]

    def generate_key(
        self,
        label: str,
        algorithm: str,
        purpose: str = 'signing',
        extractable: bool = False,
    ) -> HsmKeyInfo:
        raise HsmOperationError(
            'sc-hsm-cloud generates keys only during a key-roll ceremony on the assembly token'
        )

    def delete_key(self, key_identifier: str) -> bool:
        raise HsmOperationError('use wipe_assembly during a signing window')

    def get_public_key(self, key_identifier: str) -> str:
        status = self.ceremony_status()
        ceremony = status.get('ceremony') or {}
        pem = ceremony.get('public_key_pem')
        if not pem:
            raise HsmOperationError(
                'public key is available only while the root key is assembled'
            )
        return pem

    def roll_root_key(self) -> dict:
        result = self._call('roll_root_key')
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'roll_root_key failed')
        return result

    def sign(
        self,
        key_identifier: str,
        data: bytes,
        algorithm: Optional[str] = None,
        hash_algorithm: Optional[str] = None,
    ) -> bytes:
        if not self.signing_window_open():
            raise HsmOperationError(
                'signing refused: SmartCard-HSM signing window is not open'
            )
        result = self._call('sign', {
            'data_b64': base64.b64encode(data).decode('ascii'),
            'key_identifier': key_identifier,
            'algorithm': algorithm,
            'hash_algorithm': hash_algorithm or 'sha256',
        })
        if not result.get('ok'):
            raise HsmOperationError(result.get('error') or 'sign failed')
        return base64.b64decode(result['signature_b64'])
