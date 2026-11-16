"""SmartCard-HSM public key authentication (n-of-m) for remote ceremonies.

Design: ``docs/design/sc-hsm-remote-ceremony-pka.md``.

Keyholders never send key material. Each one proves possession of an ECC key
generated in their own SmartCard-HSM by signing ``device_id || challenge``.
The challenge comes from the root HSM, which checks the signature against a
key registered at setup. This module holds everything that does not need a
live card:

* BER-TLV and card-verifiable-certificate (CVC) parsing
* parsing of ``sc-hsm-tool --export-for-pub-key-auth`` files
* APDU builders for status, authentication, key generation and signing
* the UCM message formats keyholders sign (manifest approval, transcript)
* the short authentication string (SAS) read aloud on the ceremony call
* the hash-chained ceremony transcript
* ``FakePkaRootHsm``, a software root HSM that implements the same protocol
  and really verifies signatures, for tests and ``RAM_BRIDGE_FAKE`` dry runs

Encodings that still need a hardware check are listed in section 13 of the
design and can be switched with ``UCM_PKA_SIGNATURE_FORMAT`` and
``UCM_PKA_DEVICE_ID_FORMAT``.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


class PkaError(ValueError):
    """Malformed PKA data or a failed PKA check."""


# ---------------------------------------------------------------------------
# BER-TLV
# ---------------------------------------------------------------------------

@dataclass
class Tlv:
    tag: int
    value: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        first = self.tag
        while first > 0xFF:
            first >>= 8
        return bool(first & 0x20)

    def children(self) -> List['Tlv']:
        return parse_tlvs(self.value)


def _read_tag(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise PkaError('truncated tag')
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        while True:
            if offset >= len(data):
                raise PkaError('truncated tag')
            byte = data[offset]
            tag = (tag << 8) | byte
            offset += 1
            if not byte & 0x80:
                break
            if tag > 0xFFFFFF:
                raise PkaError('tag too long')
    return tag, offset


def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise PkaError('truncated length')
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 3:
        raise PkaError('unsupported length form')
    if offset + count > len(data):
        raise PkaError('truncated length')
    value = int.from_bytes(data[offset:offset + count], 'big')
    return value, offset + count


def parse_tlvs(data: bytes, *, allow_padding: bool = False) -> List[Tlv]:
    """Top-level TLVs. ``allow_padding`` stops at 00/FF filler after the last item."""
    items: List[Tlv] = []
    offset = 0
    while offset < len(data):
        if allow_padding and items and data[offset] in (0x00, 0xFF):
            if all(byte == data[offset] for byte in data[offset:]):
                break
        start = offset
        tag, offset = _read_tag(data, offset)
        length, offset = _read_length(data, offset)
        end = offset + length
        if end > len(data):
            raise PkaError(f'TLV {tag:X} value truncated')
        items.append(Tlv(tag=tag, value=bytes(data[offset:end]), raw=bytes(data[start:end])))
        offset = end
    return items


def parse_single(data: bytes, expected_tag: Optional[int] = None) -> Tlv:
    items = parse_tlvs(data)
    if len(items) != 1:
        raise PkaError(f'expected one TLV, got {len(items)}')
    if expected_tag is not None and items[0].tag != expected_tag:
        raise PkaError(f'expected tag {expected_tag:X}, got {items[0].tag:X}')
    return items[0]


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    if length <= 0xFF:
        return bytes((0x81, length))
    if length <= 0xFFFF:
        return bytes((0x82, length >> 8, length & 0xFF))
    if length <= 0xFFFFFF:
        return bytes((0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF))
    raise PkaError('TLV too long')


def encode_tlv(tag: int, value: bytes) -> bytes:
    if tag > 0xFFFF:
        tag_bytes = tag.to_bytes(3, 'big')
    elif tag > 0xFF:
        tag_bytes = tag.to_bytes(2, 'big')
    else:
        tag_bytes = bytes((tag,))
    return tag_bytes + encode_length(len(value)) + value


def find(items: List[Tlv], tag: int) -> Optional[Tlv]:
    for item in items:
        if item.tag == tag:
            return item
    return None


def require(items: List[Tlv], tag: int, what: str) -> Tlv:
    item = find(items, tag)
    if item is None:
        raise PkaError(f'{what} (tag {tag:X}) missing')
    return item


def decode_oid(raw: bytes) -> str:
    if not raw:
        raise PkaError('empty OID')
    first = raw[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return '.'.join(parts)


def encode_oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split('.')]
    out = bytearray((40 * arcs[0] + arcs[1],))
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


# ---------------------------------------------------------------------------
# Card-verifiable certificates
# ---------------------------------------------------------------------------

TAG_CVC = 0x7F21
TAG_BODY = 0x7F4E
TAG_CPI = 0x5F29
TAG_CAR = 0x42
TAG_PUBKEY = 0x7F49
TAG_CHR = 0x5F20
TAG_SIGNATURE = 0x5F37
TAG_AUTH_REQUEST = 0x67

# BSI TR-03110 terminal-authentication algorithm OIDs.
OID_TA_ECDSA = '0.4.0.127.0.7.2.2.2.2'
OID_TA_RSA_V15 = '0.4.0.127.0.7.2.2.2.1'
OID_RSA_V15_SHA256 = OID_TA_RSA_V15 + '.2'
OID_ECDSA_SHA256 = OID_TA_ECDSA + '.3'

_ECDSA_HASHES = {
    '2': hashes.SHA224,
    '3': hashes.SHA256,
    '4': hashes.SHA384,
    '5': hashes.SHA512,
}


@dataclass
class Cvc:
    raw: bytes
    car: Optional[str]
    chr: str
    oid: str
    public_key: Dict[int, bytes]
    signature: bytes


def _printable(tlv: Optional[Tlv]) -> Optional[str]:
    if tlv is None:
        return None
    try:
        return tlv.value.decode('ascii')
    except UnicodeDecodeError as exc:
        raise PkaError('certificate reference is not ASCII') from exc


def parse_cvc(raw: bytes) -> Cvc:
    """Parse one ``7F21`` card-verifiable certificate or certificate request."""
    cert = parse_single(raw, TAG_CVC)
    parts = cert.children()
    body = require(parts, TAG_BODY, 'certificate body')
    signature = require(parts, TAG_SIGNATURE, 'certificate signature')
    fields = body.children()
    chr_value = _printable(require(fields, TAG_CHR, 'certificate holder reference'))
    pubkey = require(fields, TAG_PUBKEY, 'public key')
    key_fields = pubkey.children()
    oid = decode_oid(require(key_fields, 0x06, 'public key algorithm').value)
    return Cvc(
        raw=cert.raw,
        car=_printable(find(fields, TAG_CAR)),
        chr=chr_value or '',
        oid=oid,
        public_key={item.tag: item.value for item in key_fields if item.tag != 0x06},
        signature=signature.value,
    )


@dataclass
class AuthenticatedRequest:
    raw: bytes
    request: Cvc
    outer_car: str
    outer_signature: bytes


def parse_authenticated_request(raw: bytes) -> AuthenticatedRequest:
    outer = parse_single(raw, TAG_AUTH_REQUEST)
    parts = outer.children()
    inner = require(parts, TAG_CVC, 'inner request')
    outer_car = _printable(require(parts, TAG_CAR, 'outer CAR'))
    return AuthenticatedRequest(
        raw=outer.raw,
        request=parse_cvc(inner.raw),
        outer_car=outer_car or '',
        outer_signature=require(parts, TAG_SIGNATURE, 'outer signature').value,
    )


# ---------------------------------------------------------------------------
# Keyholder keys
# ---------------------------------------------------------------------------

_CURVES = [
    ec.SECP256R1, ec.BrainpoolP256R1, ec.SECP256K1,
    ec.SECP384R1, ec.BrainpoolP384R1,
    ec.SECP521R1, ec.BrainpoolP512R1,
    ec.SECP224R1, ec.SECP192R1,
]


def detect_curve(point: bytes, prime: Optional[bytes] = None) -> ec.EllipticCurve:
    """Return the one supported curve that ``point`` lies on.

    The point is decoded against each candidate curve; OpenSSL rejects a
    point that is not on the curve. A prime, when the CVC includes one, must
    have the curve's bit length. Ambiguity is refused.
    """
    if not point or point[0] != 0x04 or len(point) % 2 != 1:
        raise PkaError('public point must be uncompressed')
    coord = (len(point) - 1) // 2
    matches = []
    for curve_cls in _CURVES:
        curve = curve_cls()
        if (curve.key_size + 7) // 8 != coord:
            continue
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
        except (ValueError, TypeError):
            continue
        except Exception:  # noqa: BLE001 — curve unsupported by this OpenSSL
            continue
        matches.append(curve)
    if prime:
        bits = int.from_bytes(prime, 'big').bit_length()
        matches = [curve for curve in matches if curve.key_size == bits]
    if len(matches) != 1:
        raise PkaError('could not identify the elliptic curve of the keyholder key')
    return matches[0]


@dataclass
class KeyholderKey:
    """A keyholder's PKA public key, parsed from an export file."""
    export: bytes
    chr: str
    outer_car: str
    device_chr: str
    dica_chr: str
    curve: str
    hash_name: str
    point: bytes
    request: bytes
    device_cert: bytes
    dica_cert: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.point).hexdigest()

    def public_key(self) -> ec.EllipticCurvePublicKey:
        curve = next(c() for c in _CURVES if c().name == self.curve)
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, self.point)

    def hash_algorithm(self) -> hashes.HashAlgorithm:
        return {
            'sha224': hashes.SHA224, 'sha256': hashes.SHA256,
            'sha384': hashes.SHA384, 'sha512': hashes.SHA512,
        }[self.hash_name]()

    def summary(self) -> dict:
        return {
            'chr': self.chr,
            'device_chr': self.device_chr,
            'dica_chr': self.dica_chr,
            'curve': self.curve,
            'hash': self.hash_name,
            'fingerprint': self.fingerprint,
        }


def _collect(items: List[Tlv], requests: List[Tlv], certs: List[Tlv], depth: int = 0) -> None:
    for item in items:
        if item.tag == TAG_AUTH_REQUEST:
            requests.append(item)
        elif item.tag == TAG_CVC:
            certs.append(item)
        elif item.constructed and depth < 2 and item.tag in (0x61, 0x62, 0x63, 0x30):
            _collect(item.children(), requests, certs, depth + 1)


MAX_EXPORT_BYTES = 8192


def parse_pka_export(blob: bytes) -> KeyholderKey:
    """Parse ``sc-hsm-tool --export-for-pub-key-auth`` output.

    Both layouts OpenSC reads are accepted: ``30 { 67, 7F21 device, 7F21 DICA }``
    and ``30 { 06 OID, 61 {DICA}, 62 {device}, 63 {67} }``. The certificate
    chain signatures are checked by the root HSM at registration (it embeds the
    CardContact scheme root); here the structure and the CAR/CHR links are
    checked, and the key must be ECC because PKA accepts only ECC keys.
    """
    if not blob or len(blob) > MAX_EXPORT_BYTES:
        raise PkaError('export file is empty or too large')
    outer = parse_single(blob, 0x30)
    requests: List[Tlv] = []
    certs: List[Tlv] = []
    _collect(outer.children(), requests, certs)
    if len(requests) != 1:
        raise PkaError('export must contain exactly one authenticated request')
    if len(certs) != 2:
        raise PkaError('export must contain the device and device issuer certificates')
    request = parse_authenticated_request(requests[0].raw)
    parsed = [parse_cvc(cert.raw) for cert in certs]
    device = next((c for c in parsed if c.chr == request.outer_car), None)
    if device is None:
        raise PkaError('request is not signed by the included device certificate')
    dica = next(c for c in parsed if c is not device)
    if device.car != dica.chr:
        raise PkaError('device certificate is not issued by the included device issuer CA')
    key = request.request
    if not key.oid.startswith(OID_TA_ECDSA + '.'):
        raise PkaError('public key authentication accepts only ECC keys')
    hash_cls = _ECDSA_HASHES.get(key.oid.rsplit('.', 1)[1])
    if hash_cls is None:
        raise PkaError('unsupported signature hash for the keyholder key (SHA-224 or stronger is required)')
    point = key.public_key.get(0x86)
    if not point:
        raise PkaError('keyholder key has no public point')
    curve = detect_curve(point, key.public_key.get(0x81))
    if not key.chr:
        raise PkaError('keyholder key has no holder reference')
    return KeyholderKey(
        export=bytes(blob),
        chr=key.chr,
        outer_car=request.outer_car,
        device_chr=device.chr,
        dica_chr=dica.chr,
        curve=curve.name,
        hash_name=hash_cls.name,
        point=point,
        request=request.raw,
        device_cert=device.raw,
        dica_cert=dica.raw,
    )


def _plain_to_der(signature: bytes, coord: int) -> bytes:
    r = int.from_bytes(signature[:coord], 'big')
    s = int.from_bytes(signature[coord:], 'big')
    return encode_dss_signature(r, s)


def der_to_plain(signature: bytes, coord: int) -> bytes:
    r, s = decode_dss_signature(signature)
    return r.to_bytes(coord, 'big') + s.to_bytes(coord, 'big')


def verify_keyholder_signature(key: KeyholderKey, message: bytes, signature: bytes) -> None:
    """Raise PkaError unless ``signature`` (plain r||s or DER) is valid."""
    public = key.public_key()
    coord = (public.curve.key_size + 7) // 8
    if len(signature) == 2 * coord:
        der = _plain_to_der(signature, coord)
    else:
        der = signature
    try:
        public.verify(der, message, ec.ECDSA(key.hash_algorithm()))
    except (InvalidSignature, ValueError) as exc:
        raise PkaError('keyholder signature is not valid') from exc


def card_signature(key: KeyholderKey, signature: bytes) -> bytes:
    """Encode a keyholder signature the way EXTERNAL AUTHENTICATE expects it."""
    coord = (key.public_key().curve.key_size + 7) // 8
    fmt = os.getenv('UCM_PKA_SIGNATURE_FORMAT', 'plain').strip().lower()
    plain = signature if len(signature) == 2 * coord else der_to_plain(signature, coord)
    if fmt == 'der':
        return _plain_to_der(plain, coord)
    return plain


def device_id_bytes(device_chr: str) -> bytes:
    """Device id the keyholder signs in front of the challenge."""
    fmt = os.getenv('UCM_PKA_DEVICE_ID_FORMAT', 'chr').strip().lower()
    raw = device_chr.encode('ascii')
    if fmt == 'chr_tlv':
        return encode_tlv(TAG_CHR, raw)
    return raw


# ---------------------------------------------------------------------------
# APDUs
# ---------------------------------------------------------------------------

def build_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b'', le: Optional[int] = None) -> bytes:
    """ISO 7816-4 APDU, short when it fits, extended otherwise."""
    header = bytes((cla, ins, p1, p2))
    extended = len(data) > 255 or (le is not None and le > 256)
    if not extended:
        out = header
        if data:
            out += bytes((len(data),)) + data
        if le is not None:
            out += bytes((0 if le == 256 else le,))
        return out
    out = header + b'\x00'
    if data:
        out += len(data).to_bytes(2, 'big') + data
    if le is not None:
        out += (b'\x00\x00' if le >= 65536 else le.to_bytes(2, 'big'))
    return out


def apdu_pka_status() -> bytes:
    return build_apdu(0x80, 0x54, 0x00, 0x00, le=4)


def apdu_select_auth_key(chr_value: str) -> bytes:
    """MANAGE SECURITY ENVIRONMENT: SET for EXTERNAL AUTHENTICATE, key by CHR."""
    return build_apdu(0x00, 0x22, 0x81, 0xA4, encode_tlv(0x83, chr_value.encode('ascii')))


def apdu_get_challenge() -> bytes:
    return build_apdu(0x00, 0x84, 0x00, 0x00, le=8)


def apdu_external_authenticate(signature: bytes) -> bytes:
    return build_apdu(0x00, 0x82, 0x00, 0x00, signature)


def apdu_enumerate_objects() -> bytes:
    return build_apdu(0x80, 0x58, 0x00, 0x00, le=65536)


DEVICE_CERT_FID = b'\x2F\x02'


def apdu_select_ef(fid: bytes) -> bytes:
    return build_apdu(0x00, 0xA4, 0x00, 0x00, fid, le=256)


def apdu_read_binary(offset: int, length: int = 0xE0) -> bytes:
    """Odd-INS READ BINARY of the selected EF from ``offset``."""
    body = bytes((0x54, 0x02)) + offset.to_bytes(2, 'big')
    return build_apdu(0x00, 0xB1, 0x00, 0x00, body, le=length)


RSA_GAKP_CAR = 'UTCA00001'


def gakp_rsa_body(bits: int, chr_value: str, car: str = RSA_GAKP_CAR) -> bytes:
    """Request body for GENERATE ASYMMETRIC KEY PAIR (RSA, e = 65537).

    Same fields and order as OpenSC ``sc_hsm_encode_gakp_rsa`` /
    ``sc_pkcs15emu_sc_hsm_encode_cvc``.
    """
    if bits not in (2048, 3072, 4096):
        raise PkaError('RSA key size must be 2048, 3072 or 4096')
    pubkey = (
        encode_tlv(0x06, encode_oid(OID_RSA_V15_SHA256))
        + encode_tlv(0x82, b'\x01\x00\x01')
        + encode_tlv(0x02, bits.to_bytes(2, 'big'))
    )
    return (
        encode_tlv(TAG_CPI, b'\x00')
        + encode_tlv(TAG_CAR, car.encode('ascii'))
        + encode_tlv(TAG_PUBKEY, pubkey)
        + encode_tlv(TAG_CHR, chr_value.encode('ascii'))
    )


def apdu_generate_rsa(key_id: int, bits: int, chr_value: str) -> bytes:
    return build_apdu(0x00, 0x46, key_id & 0xFF, 0x00, gakp_rsa_body(bits, chr_value), le=65536)


ALGO_RSA_PKCS1 = 0x30

_DIGEST_INFO_PREFIX = {
    'sha256': bytes.fromhex('3031300d060960864801650304020105000420'),
    'sha384': bytes.fromhex('3041300d060960864801650304020205000430'),
    'sha512': bytes.fromhex('3051300d060960864801650304020305000440'),
}


def digest_info(hash_name: str, data: bytes) -> bytes:
    name = (hash_name or 'sha256').lower().replace('-', '')
    if name not in _DIGEST_INFO_PREFIX:
        raise PkaError(f'unsupported hash {hash_name}')
    return _DIGEST_INFO_PREFIX[name] + hashlib.new(name, data).digest()


def apdu_sign_pkcs1(key_id: int, digest_info_bytes: bytes) -> bytes:
    return build_apdu(0x80, 0x68, key_id & 0xFF, ALGO_RSA_PKCS1, digest_info_bytes, le=65536)


def parse_pka_status(data: bytes) -> dict:
    if len(data) < 4:
        raise PkaError('PKA status response too short')
    return {
        'total': data[0],
        'missing': data[1],
        'required': data[2],
        'authenticated': data[3],
    }


def parse_object_list(data: bytes) -> List[bytes]:
    return [bytes(data[i:i + 2]) for i in range(0, len(data) - 1, 2)]


def parse_generated_rsa(response: bytes) -> rsa.RSAPublicKey:
    """Public key from the GENERATE ASYMMETRIC KEY PAIR response."""
    item = parse_single(response)
    if item.tag == TAG_AUTH_REQUEST:
        cvc = parse_authenticated_request(item.raw).request
    elif item.tag == TAG_CVC:
        cvc = parse_cvc(item.raw)
    else:
        raise PkaError(f'unexpected key generation response tag {item.tag:X}')
    modulus = cvc.public_key.get(0x81)
    exponent = cvc.public_key.get(0x82)
    if not modulus or not exponent:
        raise PkaError('key generation response has no RSA public key')
    return rsa.RSAPublicNumbers(
        int.from_bytes(exponent, 'big'), int.from_bytes(modulus, 'big'),
    ).public_key()


def parse_device_certificate(ef_2f02: bytes) -> Tuple[Cvc, Optional[Cvc]]:
    """Split EF 2F02 into C_DevAut and the device issuer CA certificate."""
    items = [item for item in parse_tlvs(ef_2f02, allow_padding=True) if item.tag == TAG_CVC]
    if not items:
        raise PkaError('device certificate EF has no certificate')
    device = parse_cvc(items[0].raw)
    dica = parse_cvc(items[1].raw) if len(items) > 1 else None
    return device, dica


def public_key_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('ascii')


def verify_rsa_pkcs1(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes, hash_name: str) -> None:
    algorithm = {'sha256': hashes.SHA256, 'sha384': hashes.SHA384, 'sha512': hashes.SHA512}[
        (hash_name or 'sha256').lower().replace('-', '')
    ]()
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), algorithm)
    except InvalidSignature as exc:
        raise PkaError('root HSM signature does not verify under the recorded public key') from exc


# ---------------------------------------------------------------------------
# Ceremony messages
# ---------------------------------------------------------------------------

APPROVAL_PREFIX = b'UCM-PKA-MANIFEST-APPROVAL-v1\x00'
TRANSCRIPT_PREFIX = b'UCM-PKA-TRANSCRIPT-v1\x00'
SAS_PREFIX = b'UCM-PKA-SAS-v1\x00'

MANIFEST_OPERATIONS = (
    'generate_root_key',
    'publish_crl',
    'revoke_certificate',
    'issue_subordinate_ca',
    'sign_csr',
    'renew_root_certificate',
    'issue_ocsp_responder',
    'other',
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def manifest_hash(manifest: dict) -> bytes:
    return hashlib.sha256(canonical_json(manifest)).digest()


def approval_message(manifest_digest: bytes) -> bytes:
    return APPROVAL_PREFIX + manifest_digest


def transcript_message(final_hash: bytes) -> bytes:
    return TRANSCRIPT_PREFIX + final_hash


def auth_message(device_id: bytes, challenge: bytes) -> bytes:
    if len(challenge) != 8:
        raise PkaError('challenge must be 8 bytes')
    return device_id + challenge


def compute_sas(ceremony_id: str, manifest_digest: bytes, device_chr: str, tls_spki_sha256: str) -> str:
    """Six-digit code both sides compute independently and read aloud."""
    material = (
        SAS_PREFIX
        + ceremony_id.encode('ascii') + b'\x00'
        + manifest_digest
        + device_chr.encode('ascii') + b'\x00'
        + (tls_spki_sha256 or '').lower().encode('ascii')
    )
    number = int.from_bytes(hashlib.sha256(material).digest()[:8], 'big') % 1_000_000
    text = f'{number:06d}'
    return f'{text[:3]}-{text[3:]}'


def validate_manifest_request(operations: Any, max_signatures: Any) -> Tuple[List[dict], int]:
    """Normalize the operator's planned operations for a new window."""
    if not isinstance(operations, list) or not operations:
        raise PkaError('the manifest needs at least one planned operation')
    if len(operations) > 50:
        raise PkaError('too many planned operations')
    normalized = []
    for entry in operations:
        if not isinstance(entry, dict):
            raise PkaError('each planned operation must be an object')
        op_type = str(entry.get('type') or '').strip()
        if op_type not in MANIFEST_OPERATIONS:
            raise PkaError(f'unknown operation type: {op_type or "(empty)"}')
        label = str(entry.get('label') or '').strip()
        if not label or len(label) > 300:
            raise PkaError('each planned operation needs a label of at most 300 characters')
        item = {'type': op_type, 'label': label}
        if entry.get('ca_id') not in (None, ''):
            item['ca_id'] = int(entry['ca_id'])
        normalized.append(item)
    try:
        budget = int(max_signatures)
    except (TypeError, ValueError) as exc:
        raise PkaError('max_signatures must be a number') from exc
    if budget < 1 or budget > 1000:
        raise PkaError('max_signatures must be between 1 and 1000')
    return normalized, budget


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------

GENESIS = b'\x00' * 32


def _entry_hash(prev: bytes, entry: dict) -> bytes:
    return hashlib.sha256(prev + canonical_json(entry)).digest()


class Transcript:
    """Hash-chained record of one ceremony window."""

    def __init__(self) -> None:
        self.entries: List[dict] = []
        self.sealed = False

    @property
    def head(self) -> bytes:
        if not self.entries:
            return GENESIS
        return bytes.fromhex(self.entries[-1]['hash'])

    def append(self, event: str, data: Optional[dict] = None) -> dict:
        if self.sealed:
            raise PkaError('transcript is sealed')
        entry = {
            'seq': len(self.entries),
            'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event': event,
            'data': data or {},
            'prev': self.head.hex(),
        }
        entry['hash'] = _entry_hash(self.head, {k: v for k, v in entry.items()}).hex()
        self.entries.append(entry)
        return entry

    def seal(self) -> str:
        if not self.sealed:
            self.append('sealed', {'entries': len(self.entries)})
            self.sealed = True
        return self.head.hex()

    def to_list(self) -> List[dict]:
        return [dict(entry) for entry in self.entries]


def verify_transcript(entries: List[dict]) -> str:
    """Check the chain and return the final hash (hex)."""
    prev = GENESIS
    for index, entry in enumerate(entries):
        if entry.get('seq') != index or entry.get('prev') != prev.hex():
            raise PkaError(f'transcript entry {index} is out of order')
        body = {k: v for k, v in entry.items() if k != 'hash'}
        expected = _entry_hash(prev, body)
        if entry.get('hash') != expected.hex():
            raise PkaError(f'transcript entry {index} hash does not match')
        prev = expected
    return prev.hex()


# ---------------------------------------------------------------------------
# Test fixtures: keyholder exports and a software root HSM
# ---------------------------------------------------------------------------

def _fake_cvc(car: str, chr_value: str, point: bytes) -> bytes:
    pubkey = encode_tlv(0x06, encode_oid(OID_ECDSA_SHA256)) + encode_tlv(0x86, point)
    body = (
        encode_tlv(TAG_CPI, b'\x00')
        + encode_tlv(TAG_CAR, car.encode('ascii'))
        + encode_tlv(TAG_PUBKEY, pubkey)
        + encode_tlv(TAG_CHR, chr_value.encode('ascii'))
    )
    return encode_tlv(TAG_CVC, encode_tlv(TAG_BODY, body) + encode_tlv(TAG_SIGNATURE, b'\x00' * 64))


def _point(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )


def build_fake_device_chain(device_chr: str, dica_chr: str = 'DEDICA00001') -> bytes:
    """EF 2F02 content for a software device: C_DevAut followed by the DICA."""
    device_key = ec.generate_private_key(ec.SECP256R1())
    dica_key = ec.generate_private_key(ec.SECP256R1())
    return (
        _fake_cvc(dica_chr, device_chr, _point(device_key))
        + _fake_cvc('DESRCA00001', dica_chr, _point(dica_key))
    )


def build_fake_pka_export(
    private_key: ec.EllipticCurvePrivateKey,
    chr_value: str,
    device_chr: str = 'DECC0000000001',
    dica_chr: str = 'DEDICA00001',
) -> bytes:
    """An export file shaped like ``sc-hsm-tool --export-for-pub-key-auth``.

    Certificate signatures are placeholders: only a real root HSM checks them.
    """
    point = _point(private_key)
    pubkey = encode_tlv(0x06, encode_oid(OID_ECDSA_SHA256)) + encode_tlv(0x86, point)
    body = (
        encode_tlv(TAG_CPI, b'\x00')
        + encode_tlv(TAG_PUBKEY, pubkey)
        + encode_tlv(TAG_CHR, chr_value.encode('ascii'))
    )
    inner = encode_tlv(TAG_CVC, encode_tlv(TAG_BODY, body) + encode_tlv(TAG_SIGNATURE, b'\x00' * 64))
    request = encode_tlv(
        TAG_AUTH_REQUEST,
        inner + encode_tlv(TAG_CAR, device_chr.encode('ascii')) + encode_tlv(TAG_SIGNATURE, b'\x00' * 64),
    )
    chain = build_fake_device_chain(device_chr, dica_chr)
    return encode_tlv(0x30, request + chain)


def sign_plain(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign as a SmartCard-HSM keyholder card would: ECDSA-SHA256, plain r||s."""
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    coord = (private_key.curve.key_size + 7) // 8
    return der_to_plain(der, coord)


def split_apdu(apdu: bytes) -> Tuple[int, int, int, int, bytes, Optional[int]]:
    """Inverse of :func:`build_apdu` (cases 1-4, short and extended)."""
    if len(apdu) < 4:
        raise PkaError('APDU too short')
    cla, ins, p1, p2 = apdu[:4]
    rest = apdu[4:]
    if not rest:
        return cla, ins, p1, p2, b'', None
    if len(rest) == 1:
        return cla, ins, p1, p2, b'', rest[0] or 256
    if rest[0] != 0:
        lc = rest[0]
        data = rest[1:1 + lc]
        tail = rest[1 + lc:]
        le = (tail[0] or 256) if tail else None
        return cla, ins, p1, p2, bytes(data), le
    if len(rest) == 3:
        return cla, ins, p1, p2, b'', int.from_bytes(rest[1:3], 'big') or 65536
    lc = int.from_bytes(rest[1:3], 'big')
    data = rest[3:3 + lc]
    tail = rest[3 + lc:]
    le = (int.from_bytes(tail, 'big') or 65536) if tail else None
    return cla, ins, p1, p2, bytes(data), le


@dataclass
class FakePkaRootHsm:
    """Software root HSM speaking the PKA APDUs above. Tests and dry runs only."""
    threshold_n: int
    total_m: int
    device_chr: str = 'DECC0000000099'
    atr: bytes = bytes.fromhex('3BFE1800008131FE458031815448534D31738021408107FA')
    _registered: Dict[str, KeyholderKey] = field(default_factory=dict)
    _authenticated: set = field(default_factory=set)
    _selected: Optional[str] = None
    _challenge: Optional[bytes] = None
    _keys: Dict[int, rsa.RSAPrivateKey] = field(default_factory=dict)
    _selected_ef: Optional[bytes] = None
    _device_chain: bytes = b''

    def __post_init__(self) -> None:
        self._device_chain = build_fake_device_chain(self.device_chr)

    # setup (done with sc-hsm-tool at the HSM site on a real device)
    def register(self, export: bytes) -> None:
        key = parse_pka_export(export)
        if len(self._registered) >= self.total_m:
            raise PkaError('all public keys are already registered')
        self._registered[key.chr] = key

    def reset(self) -> bytes:
        self._authenticated.clear()
        self._selected = None
        self._challenge = None
        self._selected_ef = None
        return self.atr

    @property
    def unlocked(self) -> bool:
        return len(self._registered) == self.total_m and len(self._authenticated) >= self.threshold_n

    def transmit(self, apdu: bytes) -> bytes:
        try:
            cla, ins, p1, p2, data, _le = split_apdu(apdu)
        except PkaError:
            return b'\x67\x00'
        if cla == 0x00 and ins == 0xA4:
            if p1 == 0x04:
                return b'\x90\x00'
            self._selected_ef = data
            if data == DEVICE_CERT_FID:
                return b'\x90\x00'
            return b'\x6A\x82'
        if cla == 0x00 and ins == 0xB1:
            if self._selected_ef != DEVICE_CERT_FID or len(data) < 4:
                return b'\x69\x86'
            offset = int.from_bytes(data[2:4], 'big')
            length = _le or 256
            return self._device_chain[offset:offset + length] + b'\x90\x00'
        if cla == 0x80 and ins == 0x54 and not data:
            return bytes((
                self.total_m,
                self.total_m - len(self._registered),
                self.threshold_n,
                len(self._authenticated),
            )) + b'\x90\x00'
        if cla == 0x00 and ins == 0x22 and p1 == 0x81 and p2 == 0xA4:
            try:
                ref = parse_single(data, 0x83).value.decode('ascii')
            except (PkaError, UnicodeDecodeError):
                return b'\x6A\x80'
            if ref not in self._registered:
                return b'\x6A\x88'
            self._selected = ref
            self._challenge = None
            return b'\x90\x00'
        if cla == 0x00 and ins == 0x84:
            self._challenge = secrets.token_bytes(8)
            return self._challenge + b'\x90\x00'
        if cla == 0x00 and ins == 0x82:
            if self._selected is None or self._challenge is None:
                return b'\x69\x85'
            key = self._registered[self._selected]
            challenge, self._challenge = self._challenge, None
            try:
                verify_keyholder_signature(
                    key, auth_message(device_id_bytes(self.device_chr), challenge), data,
                )
            except PkaError:
                return b'\x63\x00'
            self._authenticated.add(self._selected)
            return b'\x90\x00'
        if cla == 0x80 and ins == 0x58:
            listing = b''.join(bytes((0xCC, key_id)) for key_id in sorted(self._keys))
            return listing + b'\x90\x00'
        if cla == 0x00 and ins == 0x46:
            if not self.unlocked:
                return b'\x69\x82'
            if p1 in self._keys:
                return b'\x6A\x89'
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._keys[p1] = private
            numbers = private.public_key().public_numbers()
            n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
            pubkey = (
                encode_tlv(0x06, encode_oid(OID_RSA_V15_SHA256))
                + encode_tlv(0x81, n_bytes)
                + encode_tlv(0x82, b'\x01\x00\x01')
            )
            body = (
                encode_tlv(TAG_CPI, b'\x00')
                + encode_tlv(TAG_CAR, RSA_GAKP_CAR.encode('ascii'))
                + encode_tlv(TAG_PUBKEY, pubkey)
                + encode_tlv(TAG_CHR, b'UCMROOT00001')
            )
            inner = encode_tlv(TAG_CVC, encode_tlv(TAG_BODY, body) + encode_tlv(TAG_SIGNATURE, b'\x00' * 32))
            response = encode_tlv(
                TAG_AUTH_REQUEST,
                inner + encode_tlv(TAG_CAR, self.device_chr.encode('ascii')) + encode_tlv(TAG_SIGNATURE, b'\x00' * 32),
            )
            return response + b'\x90\x00'
        if cla == 0x80 and ins == 0x68:
            if not self.unlocked:
                return b'\x69\x82'
            private = self._keys.get(p1)
            if private is None:
                return b'\x6A\x88'
            if p2 != ALGO_RSA_PKCS1:
                return b'\x6A\x81'
            signature = _raw_pkcs1_sign(private, data)
            return signature + b'\x90\x00'
        return b'\x6D\x00'


def _raw_pkcs1_sign(private: rsa.RSAPrivateKey, digest_info_bytes: bytes) -> bytes:
    """PKCS#1 v1.5 type-1 padding over a DigestInfo, then the RSA operation."""
    numbers = private.private_numbers()
    k = (numbers.public_numbers.n.bit_length() + 7) // 8
    if len(digest_info_bytes) > k - 11:
        raise PkaError('DigestInfo too long')
    padded = b'\x00\x01' + b'\xff' * (k - len(digest_info_bytes) - 3) + b'\x00' + digest_info_bytes
    value = pow(int.from_bytes(padded, 'big'), numbers.d, numbers.public_numbers.n)
    return value.to_bytes(k, 'big')
