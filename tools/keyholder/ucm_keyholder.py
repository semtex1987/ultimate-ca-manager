#!/usr/bin/env python3
"""UCM keyholder agent for remote root-key ceremonies (SmartCard-HSM PKA).

Runs on the keyholder's own machine, next to their own SmartCard-HSM. It
talks to the UCM API with the keyholder's API key and signs on the local
card through OpenSC PKCS#11. The card PIN is typed here (or on a PIN-pad
reader) and goes to the card only.

What it signs, and only after the keyholder confirms:

* manifest approval  "UCM-PKA-MANIFEST-APPROVAL-v1\\0" || SHA-256(manifest)
* HSM authentication device_id || 8-byte challenge from the root HSM
* transcript         "UCM-PKA-TRANSCRIPT-v1\\0" || final transcript hash

Everything shown before a signature is recomputed locally from what the
server sent: the manifest hash, the short authentication string (SAS) read
aloud on the call, and the root HSM device reference, which is pinned on
first use.

Requirements: python3 >= 3.9, cryptography, python-pkcs11, OpenSC.
Design: docs/design/sc-hsm-remote-ceremony-pka.md
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
import ssl
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

APPROVAL_PREFIX = b'UCM-PKA-MANIFEST-APPROVAL-v1\x00'
TRANSCRIPT_PREFIX = b'UCM-PKA-TRANSCRIPT-v1\x00'
SAS_PREFIX = b'UCM-PKA-SAS-v1\x00'
DEFAULT_MODULE = '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'
PIN_FILE = os.path.join(
    os.getenv('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config'),
    'ucm-keyholder', 'device-pins.json',
)


class AgentError(RuntimeError):
    pass


# -- message formats (must match backend/services/hsm/sc_hsm_pka.py) ---------

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def manifest_hash(manifest: dict) -> bytes:
    return hashlib.sha256(canonical_json(manifest)).digest()


def approval_message(digest: bytes) -> bytes:
    return APPROVAL_PREFIX + digest


def transcript_message(final_hash: bytes) -> bytes:
    return TRANSCRIPT_PREFIX + final_hash


def compute_sas(ceremony_id: str, digest: bytes, device_chr: str, tls_spki_sha256: str) -> str:
    material = (
        SAS_PREFIX
        + ceremony_id.encode('ascii') + b'\x00'
        + digest
        + device_chr.encode('ascii') + b'\x00'
        + (tls_spki_sha256 or '').lower().encode('ascii')
    )
    number = int.from_bytes(hashlib.sha256(material).digest()[:8], 'big') % 1_000_000
    text = f'{number:06d}'
    return f'{text[:3]}-{text[3:]}'


def verify_transcript(entries: List[dict]) -> str:
    prev = b'\x00' * 32
    for index, entry in enumerate(entries):
        if entry.get('seq') != index or entry.get('prev') != prev.hex():
            raise AgentError(f'transcript entry {index} is out of order')
        body = {k: v for k, v in entry.items() if k != 'hash'}
        expected = hashlib.sha256(prev + canonical_json(body)).digest()
        if entry.get('hash') != expected.hex():
            raise AgentError(f'transcript entry {index} hash does not match')
        prev = expected
    return prev.hex()


def device_id_matches(device_id: bytes, device_chr: str) -> bool:
    """The device id the server asks us to sign must be the device we verified."""
    raw = device_chr.encode('ascii')
    return device_id == raw or (device_id.endswith(raw) and device_id[:2] == b'\x5f\x20')


# -- HTTPS ---------------------------------------------------------------------

class Api:
    def __init__(self, base_url: str, api_key: str, *, ca_file: Optional[str], spki_pin: Optional[str]):
        parts = urlsplit(base_url)
        if parts.scheme != 'https':
            raise AgentError('the UCM URL must use https')
        self.host = parts.hostname or ''
        self.port = parts.port or 443
        self.prefix = parts.path.rstrip('/')
        self.api_key = api_key
        self.context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.spki_pin = (spki_pin or '').lower().replace(':', '') or None
        self.observed_spki: Optional[str] = None

    def _spki(self, der_cert: bytes) -> str:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_der_x509_certificate(der_cert)
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki).hexdigest()

    def request(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=60)
        try:
            payload = json.dumps(body).encode('utf-8') if body is not None else None
            headers = {'X-API-Key': self.api_key, 'Accept': 'application/json'}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            conn.request(method, self.prefix + path, body=payload, headers=headers)
            spki = self._spki(conn.sock.getpeercert(binary_form=True))
            if self.spki_pin and spki != self.spki_pin:
                raise AgentError(
                    f'server key {spki} does not match --pin-sha256; stop and report this on the call'
                )
            self.observed_spki = spki
            response = conn.getresponse()
            raw = response.read()
        finally:
            conn.close()
        try:
            data = json.loads(raw.decode('utf-8')) if raw else {}
        except ValueError:
            data = {'message': raw[:200].decode('utf-8', 'replace')}
        if response.status >= 400:
            message = data.get('message') or data.get('detail') or data.get('error') or response.reason
            raise AgentError(f'{method} {path}: HTTP {response.status}: {message}')
        return data.get('data', data) if isinstance(data, dict) else data

    def raw_get(self, path: str) -> bytes:
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=60)
        try:
            conn.request('GET', self.prefix + path, headers={'X-API-Key': self.api_key})
            response = conn.getresponse()
            return response.read()
        finally:
            conn.close()


# -- card ------------------------------------------------------------------------

class Card:
    """The keyholder's own SmartCard-HSM, through OpenSC PKCS#11."""

    def __init__(self, module: str, key_id: Optional[str], key_label: Optional[str], token_label: Optional[str]):
        try:
            import pkcs11  # noqa: F401
        except ImportError as exc:
            raise AgentError('python-pkcs11 is required: pip install python-pkcs11') from exc
        self.module = module
        self.key_id = bytes.fromhex(key_id) if key_id else None
        self.key_label = key_label
        self.token_label = token_label

    def _token(self):
        import pkcs11
        lib = pkcs11.lib(self.module)
        tokens = [slot.get_token() for slot in lib.get_slots(token_present=True)]
        if self.token_label:
            tokens = [t for t in tokens if (t.label or '').strip() == self.token_label]
        if len(tokens) != 1:
            raise AgentError(f'expected one card, found {len(tokens)}; use --token-label')
        return tokens[0]

    def _key_filter(self, object_class) -> Dict:
        import pkcs11
        attrs = {pkcs11.Attribute.CLASS: object_class, pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC}
        if self.key_id is not None:
            attrs[pkcs11.Attribute.ID] = self.key_id
        if self.key_label:
            attrs[pkcs11.Attribute.LABEL] = self.key_label
        return attrs

    def public_point(self) -> bytes:
        import pkcs11
        token = self._token()
        with token.open() as session:
            keys = list(session.get_objects(self._key_filter(pkcs11.ObjectClass.PUBLIC_KEY)))
            if len(keys) != 1:
                raise AgentError(f'expected one EC public key, found {len(keys)}; use --key-id')
            point = keys[0][pkcs11.Attribute.EC_POINT]
        return unwrap_ec_point(bytes(point))

    def sign(self, messages: List[bytes], *, pinpad: bool) -> List[bytes]:
        with self.signer(pinpad=pinpad) as sign:
            return [sign(message) for message in messages]

    def signer(self, *, pinpad: bool):
        """Context manager: one card login, a function signing ECDSA-SHA256 as plain r||s."""
        import contextlib
        import pkcs11

        @contextlib.contextmanager
        def session_scope():
            token = self._token()
            if pinpad:
                pin = getattr(pkcs11, 'PROTECTED_AUTH', None)
                if pin is None:
                    raise AgentError('this python-pkcs11 has no PIN-pad support; omit --pinpad')
            else:
                pin = getpass.getpass('Card PIN (sent to your card only): ')
            try:
                with token.open(user_pin=pin) as session:
                    pin = None
                    keys = list(session.get_objects(self._key_filter(pkcs11.ObjectClass.PRIVATE_KEY)))
                    if len(keys) != 1:
                        raise AgentError(f'expected one EC private key, found {len(keys)}; use --key-id')
                    key = keys[0]
                    yield lambda message: bytes(
                        key.sign(hashlib.sha256(message).digest(), mechanism=pkcs11.Mechanism.ECDSA)
                    )
            finally:
                pin = None

        return session_scope()


def unwrap_ec_point(value: bytes) -> bytes:
    """CKA_EC_POINT is a DER OCTET STRING around the point; some modules omit it."""
    if len(value) > 2 and value[0] == 0x04:
        first = value[1]
        if first < 0x80:
            header, length = 2, first
        elif first == 0x81 and len(value) > 3:
            header, length = 3, value[2]
        elif first == 0x82 and len(value) > 4:
            header, length = 4, int.from_bytes(value[2:4], 'big')
        else:
            header, length = 0, -1
        inner = value[header:]
        if header and length == len(inner) and inner[:1] == b'\x04' and len(inner) % 2 == 1:
            return inner
    return value


# -- local device pins -------------------------------------------------------------

def _load_pins() -> Dict[str, str]:
    try:
        with open(PIN_FILE, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _save_pins(pins: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(PIN_FILE), mode=0o700, exist_ok=True)
    tmp = PIN_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(pins, handle, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PIN_FILE)


def check_device_pin(api_url: str, provider_id: int, device_chr: str, *, assume_yes: bool = False) -> None:
    key = f'{api_url.rstrip("/")}#{provider_id}'
    pins = _load_pins()
    pinned = pins.get(key)
    if pinned == device_chr:
        print(f'Root HSM device: {device_chr} (matches your pinned device)')
        return
    if pinned:
        raise AgentError(
            f'the root HSM is {device_chr}, but you pinned {pinned}. Stop and report this on the call.'
        )
    print(f'Root HSM device: {device_chr} (first time seen)')
    print('Compare it with the value the site operator reads aloud from sc-hsm-tool.')
    if not assume_yes:
        typed = input('Type the device reference to pin it: ').strip()
        if typed != device_chr:
            raise AgentError('device reference not confirmed')
    pins[key] = device_chr
    _save_pins(pins)


# -- commands ------------------------------------------------------------------------

def _point_fingerprint(point: bytes) -> str:
    return hashlib.sha256(point).hexdigest()


def cmd_fingerprint(args, card: Card, _api) -> int:
    print(f'Key fingerprint (read this aloud): {_point_fingerprint(card.public_point())}')
    return 0


def cmd_enroll(args, card: Card, api: Api) -> int:
    with open(args.export_file, 'rb') as handle:
        export = handle.read()
    local = _point_fingerprint(card.public_point())
    result = api.request('POST', f'/api/v2/hsm/providers/{args.provider}/ceremony/keyholder/enroll', {
        'export_b64': base64.b64encode(export).decode('ascii'),
    })
    print(f"Enrolled key {result.get('chr')} from device {result.get('device_chr')}")
    print(f"Server fingerprint: {result.get('fingerprint')}")
    print(f'Card fingerprint:   {local}')
    if result.get('fingerprint') != local:
        raise AgentError('the export file is not for the key on this card')
    print('Read the fingerprint aloud on the enrollment call.')
    return 0


def _show_manifest(manifest: dict) -> None:
    print('')
    print(f"Provider:   {manifest.get('provider_name')} (id {manifest.get('provider_id')})")
    print(f"Ceremony:   {manifest.get('ceremony_id')}")
    print(f"Opened by:  {manifest.get('opened_by')} at {manifest.get('opened_at')}")
    print(f"Expires:    {manifest.get('expires_at')}")
    print(f"Threshold:  {manifest.get('threshold_n')} of {manifest.get('total_m')}")
    print(f"Budget:     at most {manifest.get('max_signatures')} signatures")
    print('Planned operations:')
    for op in manifest.get('operations') or []:
        suffix = f" (CA {op['ca_id']})" if op.get('ca_id') is not None else ''
        print(f"  - [{op.get('type')}] {op.get('label')}{suffix}")
    print('')


def cmd_approve(args, card: Card, api: Api) -> int:
    base = f'/api/v2/hsm/providers/{args.provider}/ceremony/keyholder'
    context = api.request('GET', base)
    if not context.get('window_open'):
        raise AgentError('no signing window is open for this provider')
    if context.get('authenticated'):
        print('You have already authenticated in this window.')
        return 0
    manifest = context.get('manifest') or {}
    digest = manifest_hash(manifest)
    if digest.hex() != context.get('manifest_sha256'):
        raise AgentError('the manifest does not match its hash; stop and report this on the call')
    device_chr = context.get('device_chr') or ''
    if not device_chr:
        raise AgentError(context.get('device_error') or 'the root HSM is not connected yet')
    if manifest.get('device_chr') and manifest['device_chr'] != device_chr:
        raise AgentError('the connected root HSM is not the device named in the manifest')
    check_device_pin(args.url, args.provider, device_chr, assume_yes=False)
    enrolled = context.get('enrolled') or {}
    local = _point_fingerprint(card.public_point())
    if enrolled.get('fingerprint') != local:
        raise AgentError('this card is not the key enrolled for you on this provider')
    _show_manifest(manifest)
    sas = compute_sas(str(manifest.get('ceremony_id')), digest, device_chr, api.observed_spki or '')
    print(f'Manifest SHA-256: {digest.hex()}')
    print(f'Read aloud:  SAS {sas}')
    if context.get('sas') and context['sas'] != sas:
        print('WARNING: the server computed a different SAS. Do not approve; report it on the call.')
        return 2
    print('The operator\'s screen must show the same SAS.')
    if input('Type APPROVE to approve this manifest and authenticate: ').strip() != 'APPROVE':
        print('Not approved.')
        return 1
    # One card login covers the approval and the challenge response.
    with card.signer(pinpad=args.pinpad) as sign:
        if not context.get('approved'):
            approval = sign(approval_message(digest))
            api.request('POST', f'{base}/approve', {'signature_b64': base64.b64encode(approval).decode('ascii')})
            print('Manifest approval recorded.')
        issued = api.request('POST', f'{base}/challenge')
        device_id = base64.b64decode(issued['device_id_b64'])
        challenge = base64.b64decode(issued['challenge_b64'])
        if issued.get('device_chr') != device_chr or not device_id_matches(device_id, device_chr):
            raise AgentError('the challenge is for a different device; stop and report this on the call')
        if len(challenge) != 8:
            raise AgentError('unexpected challenge length')
        signature = sign(device_id + challenge)
    result = api.request('POST', f'{base}/authenticate', {'signature_b64': base64.b64encode(signature).decode('ascii')})
    print(f"Authenticated: {result.get('authenticated')} of {result.get('required')} required"
          f"{' — root HSM unlocked' if result.get('unlocked') else ''}")
    return 0


def cmd_transcript(args, card: Optional[Card], api: Api) -> int:
    path = f'/api/v2/hsm/providers/{args.provider}/ceremony/transcript'
    if args.ceremony_id:
        path += f'?ceremony_id={args.ceremony_id}'
    transcript = api.request('GET', path)
    entries = transcript.get('entries') or []
    final = verify_transcript(entries)
    if transcript.get('sealed') and transcript.get('final_hash') != final:
        raise AgentError('the stored final hash does not match the entries')
    for entry in entries:
        data = entry.get('data') or {}
        detail = ''
        if entry['event'] == 'signed':
            detail = f"{data.get('label') or '-'} tbs_sha256={data.get('tbs_sha256')} ({data.get('used')}/{data.get('budget')})"
        elif entry['event'] in ('authenticated', 'manifest_approved'):
            detail = f"custodian {data.get('custodian_id')} key {str(data.get('key_fingerprint'))[:16]}…"
        elif entry['event'] in ('device', 'device_pinned'):
            detail = str(data.get('device_chr'))
        elif entry['event'] == 'locked':
            detail = f"verified={data.get('verified')}"
        print(f"{entry['seq']:>3} {entry['at']} {entry['event']:<24} {detail}")
    print(f'\nChain verified. Final hash: {final}')
    if not args.countersign:
        return 0
    if not transcript.get('sealed'):
        raise AgentError('only a sealed transcript can be countersigned')
    if input('Type CONFIRM to countersign this transcript: ').strip() != 'CONFIRM':
        return 1
    signature, = card.sign([transcript_message(bytes.fromhex(final))], pinpad=args.pinpad)
    api.request('POST', f'{path.split("?")[0]}/countersign', {
        'ceremony_id': transcript.get('ceremony_id'),
        'signature_b64': base64.b64encode(signature).decode('ascii'),
    })
    print('Countersignature recorded.')
    return 0


def agent_sha256() -> str:
    """SHA-256 of this file, to compare with the published value on the call."""
    with open(os.path.abspath(__file__), 'rb') as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class _VersionAction(argparse.Action):
    """Print the agent's own hash and exit, before any card or network use."""

    def __init__(self, option_strings, dest, **kwargs):
        kwargs.setdefault('nargs', 0)
        kwargs.setdefault('default', argparse.SUPPRESS)
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(f'ucm_keyholder.py sha256 {agent_sha256()}')
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--version', action=_VersionAction,
                        help="print this agent's SHA-256 to compare with the published value, and exit")
    parser.add_argument('--url', default=os.getenv('UCM_URL'), help='UCM base URL, https://… (env UCM_URL)')
    parser.add_argument('--provider', type=int, default=int(os.getenv('UCM_PROVIDER_ID') or 0) or None)
    parser.add_argument('--api-key-file', default=os.getenv('UCM_API_KEY_FILE'),
                        help='file holding your UCM API key (or env UCM_API_KEY)')
    parser.add_argument('--ca-file', default=os.getenv('UCM_CA_FILE'), help='CA bundle for the UCM certificate')
    parser.add_argument('--pin-sha256', default=os.getenv('UCM_SPKI_SHA256'),
                        help='expected SHA-256 of the server public key (SPKI)')
    parser.add_argument('--module', default=os.getenv('PKCS11_MODULE', DEFAULT_MODULE))
    parser.add_argument('--token-label')
    parser.add_argument('--key-id', help='CKA_ID of your authentication key, hex')
    parser.add_argument('--key-label')
    parser.add_argument('--pinpad', action='store_true', help='enter the PIN on the reader')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('fingerprint', help='print the fingerprint of the key on your card')
    enroll = sub.add_parser('enroll', help='upload your sc-hsm-tool --export-for-pub-key-auth file')
    enroll.add_argument('export_file')
    sub.add_parser('approve', help='review the ceremony, approve it and authenticate')
    transcript = sub.add_parser('transcript', help='verify (and optionally countersign) a transcript')
    transcript.add_argument('--ceremony-id')
    transcript.add_argument('--countersign', action='store_true')
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    card = Card(args.module, args.key_id, args.key_label, args.token_label)
    if args.command == 'fingerprint':
        return cmd_fingerprint(args, card, None)
    if not args.url or not args.provider:
        raise AgentError('--url and --provider are required')
    api_key = os.getenv('UCM_API_KEY', '')
    if args.api_key_file:
        with open(args.api_key_file, encoding='utf-8') as handle:
            api_key = handle.read().strip()
    if not api_key:
        raise AgentError('provide your API key with --api-key-file or UCM_API_KEY')
    api = Api(args.url, api_key, ca_file=args.ca_file, spki_pin=args.pin_sha256)
    handlers = {'enroll': cmd_enroll, 'approve': cmd_approve, 'transcript': cmd_transcript}
    return handlers[args.command](args, card, api)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except AgentError as exc:
        print(f'error: {exc}', file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
