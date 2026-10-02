"""SmartCard-HSM APDU helpers (OpenSC card-sc-hsm.c).

Used by the RAM bridge for DKEK share import, unwrap, and wipe. Share files
stay compatible with ``sc-hsm-tool --create-dkek-share`` / ``--import-dkek-share``.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Manage key domain (CLA 0x80, INS 0x52)
# P1 = operation - 1 for import/create/delete/clear (see cardctl.h)
OP_GET_STATUS = 0
OP_IMPORT_DKEK_SHARE = 1
OP_CREATE_DKEK = 2
OP_DELETE_KEY_DOMAIN = 4
OP_CLEAR_KEK = 5

KEY_PREFIX = 0xCC  # Hi byte in file identifier for key objects


def _len_byte(n: int) -> bytes:
    if n < 0 or n > 255:
        raise ValueError('Lc/Le out of range for short APDU')
    return bytes((n,))


def apdu_get_key_domain_status(key_domain_idx: int = 0) -> bytes:
    # CASE_2_SHORT: CLA INS P1 P2 Le
    return bytes((0x80, 0x52, 0x00, key_domain_idx & 0xFF, 0x00))


def apdu_import_dkek_share(share: bytes, key_domain_idx: int = 0) -> bytes:
    # The card's IMPORT_DKEK_SHARE data field is exactly one AES-256 share.
    # A longer blob (the x-coordinate prefix on a Shamir share) is SW=6700.
    if len(share) != 32:
        raise ValueError('DKEK share must be 32 bytes')
    p1 = OP_IMPORT_DKEK_SHARE - 1  # 0
    return bytes((0x80, 0x52, p1, key_domain_idx & 0xFF)) + _len_byte(len(share)) + share + b'\x00'


def apdu_delete_key_domain(key_domain_idx: int = 0) -> bytes:
    p1 = OP_DELETE_KEY_DOMAIN - 1  # 3
    return bytes((0x80, 0x52, p1, key_domain_idx & 0xFF, 0x00))


def apdu_clear_kek(key_domain_idx: int = 0) -> bytes:
    p1 = OP_CLEAR_KEK - 1  # 4
    return bytes((0x80, 0x52, p1, key_domain_idx & 0xFF, 0x00))


def apdu_create_dkek_domain(share_count: int, key_domain_idx: int = 0) -> bytes:
    """Create an empty key domain that will accept ``share_count`` imports."""
    if share_count < 1 or share_count > 16:
        raise ValueError('dkek share count out of range')
    p1 = OP_CREATE_DKEK - 1  # 1
    return bytes((0x80, 0x52, p1, key_domain_idx & 0xFF, 0x01, share_count & 0xFF, 0x00))


def apdu_initialize(
    so_pin_hex: str,
    user_pin: str,
    dkek_shares: int = 1,
    *,
    scheme: str = 'shares',
    key_domains: int = 1,
    retry: int = 3,
) -> bytes:
    """INITIALIZE DEVICE. Clears keys and files. The APDU contains both PINs.

    ``scheme`` matches the CardContact key-manager choices. Only one device-key
    scheme tag is sent. Firmware 4.0 rejects a block that sets DKEK shares and
    key domains together (SW=6A80). Callers must not log the returned bytes.

    The initialization code is the current SO-PIN. On a factory card that is
    the 16 hex characters printed on the card.
    """
    so_hex = (so_pin_hex or '').strip()
    if len(so_hex) != 16 or any(c not in '0123456789abcdefABCDEF' for c in so_hex):
        raise ValueError('SO-PIN must be 16 hexadecimal characters')
    pin = user_pin or ''
    if not pin.isascii() or not (6 <= len(pin) <= 16):
        raise ValueError('User PIN must be 6 to 16 ASCII characters')
    if retry < 1 or retry > 10:
        raise ValueError('PIN retry counter must be between 1 and 10')
    if scheme not in ('none', 'random', 'shares', 'domains'):
        raise ValueError('unknown device key scheme')
    if scheme == 'shares' and (dkek_shares < 1 or dkek_shares > 16):
        raise ValueError('dkek share count out of range')
    if scheme == 'domains' and (key_domains < 1 or key_domains > 16):
        raise ValueError('key domain count out of range')
    so = bytes.fromhex(so_hex)
    pin_bytes = pin.encode('ascii')
    parts = [
        bytes((0x80, 0x02, 0x00, 0x01)),  # RESET RETRY COUNTER enabled
        bytes((0x81, len(pin_bytes))) + pin_bytes,
        bytes((0x82, 0x08)) + so,
        bytes((0x91, 0x01, retry & 0xFF)),
    ]
    if scheme == 'random':
        parts.append(bytes((0x92, 0x01, 0x00)))
    elif scheme == 'shares':
        parts.append(bytes((0x92, 0x01, dkek_shares & 0xFF)))
    elif scheme == 'domains':
        parts.append(bytes((0x97, 0x01, key_domains & 0xFF)))
    body = b''.join(parts)
    return bytes((0x80, 0x50, 0x00, 0x00, len(body))) + body


def apdu_verify_user_pin(user_pin: str) -> bytes:
    """ISO VERIFY for the SmartCard-HSM user PIN (P2=0x81). Do not log the result."""
    pin = user_pin or ''
    if not pin.isascii() or not (6 <= len(pin) <= 16):
        raise ValueError('User PIN must be 6 to 16 ASCII characters')
    raw = pin.encode('ascii')
    return bytes((0x00, 0x20, 0x00, 0x81, len(raw))) + raw


def interpret_share_probe(sw1: int, sw2: int) -> dict:
    """What a SELECT of the share EF means for the ceremony panel and the log.

    SW 6A82 is file-not-found. The token answered; it just has no share file.
    That is the normal state of a blank, initialized, or wiped card.
    """
    sw = f'{sw1:02X}{sw2:02X}'
    fid = SHARE_EF_FID.hex().upper()
    if sw1 == 0x90 and sw2 == 0x00:
        return {
            'readable': True,
            'probe_error': None,
            'probe_sw': sw,
            'log': f'share EF {fid} present (SW={sw})',
        }
    if sw1 == 0x6A and sw2 == 0x82:
        return {
            'readable': False,
            'probe_error': None,
            'probe_sw': sw,
            'log': (
                f'card answered; share EF {fid} is absent (SW={sw}). '
                'A blank or wiped token has no share file until Create root key writes one.'
            ),
        }
    return {
        'readable': False,
        'probe_error': f'SW={sw}',
        'probe_sw': sw,
        'log': f'share EF {fid} select failed SW={sw}',
    }


def apdu_delete_ef(fid: bytes) -> bytes:
    if len(fid) != 2:
        raise ValueError('EF id must be 2 bytes')
    return bytes((0x00, 0xE4, 0x02, 0x00, 0x02)) + fid


def classify_token_state(
    domain_sw1: int,
    domain_sw2: int,
    domain_data: bytes,
    share_sw1: int,
    share_sw2: int,
) -> dict:
    """Map status words to the state a new n-of-m scheme needs.

    Ready means initialized, no share file, and a key domain that has not
    accepted any share yet (empty slot, or every configured share still
    outstanding). A completed or partial DKEK is not ready.
    """
    has_share = share_sw1 == 0x90 and share_sw2 == 0x00
    domain_sw = (domain_sw1 << 8) | domain_sw2
    outstanding = None
    configured = None
    if domain_sw == 0x9000:
        parsed = parse_key_domain_status(domain_data)
        outstanding = parsed.get('outstanding_shares')
        configured = parsed.get('dkek_shares')
        if outstanding and configured and outstanding == configured:
            kind = 'awaiting_shares'
        elif outstanding and outstanding > 0:
            kind = 'dkek_pending'
        else:
            kind = 'has_dkek'
    elif domain_sw == 0x6A88:
        kind = 'ready'
    elif domain_sw in (0x6D00, 0x6985, 0x6A86, 0x6A81, 0x6984):
        kind = 'uninitialized'
    else:
        kind = 'unknown'
    if has_share and kind in ('ready', 'awaiting_shares'):
        kind = 'has_share'
    ready = kind == 'awaiting_shares' or (kind == 'ready' and not has_share)
    if kind == 'ready' and not has_share:
        ready = True
    return {
        'state': kind,
        'ready': ready,
        'destructive': not ready,
        'has_share': has_share,
        'outstanding_shares': outstanding,
        'configured_shares': configured,
        'domain_sw': f'{domain_sw1:02X}{domain_sw2:02X}',
        'share_sw': f'{share_sw1:02X}{share_sw2:02X}',
    }


def apdu_unwrap_key(key_id: int) -> bytes:
    # After EF.2F10 write: CLA=0x80 INS=0x74 P1=key_id P2=0x93
    return bytes((0x80, 0x74, key_id & 0xFF, 0x93))


def apdu_wrap_key(key_id: int) -> bytes:
    """WRAP KEY under the DKEK.

    CardContact requests 65536 bytes (extended Le ``00 00 00``). A wrapped
    RSA-2048 key does not fit in a short response.
    """
    return bytes((0x80, 0x72, key_id & 0xFF, 0x92, 0x00, 0x00, 0x00))


def apdu_delete_key_file(key_id: int) -> bytes:
    """DELETE FILE for the PKCS#15 key EF (fid = 0xCC00 | key_id)."""
    fid = bytes(((KEY_PREFIX), key_id & 0xFF))
    # INS 0xE4 P1=0x02 P2=0x00 Lc=2 Data=FID
    return bytes((0x00, 0xE4, 0x02, 0x00, 0x02)) + fid


# Application AID. A token that has not selected it yet rejects file commands.
SC_HSM_AID = bytes.fromhex('E82B0601040181C31F0201')

# Readable data object (OpenSC DATA_PREFIX 0xCF). 0x2F02 is EF.C_DevAut, the
# device certificate, and must not be read or written as a share.
SHARE_EF_FID = b'\xCF\x01'
SHARE_LEN = 32


def apdu_select_hsm() -> bytes:
    """SELECT the SmartCard-HSM applet. P2=0x00 and Le=0x00.

    P2=0x0C (no response data) is status 6A86 on this card.
    """
    return bytes((0x00, 0xA4, 0x04, 0x00, len(SC_HSM_AID))) + SC_HSM_AID + b'\x00'


def apdu_select_share_ef() -> bytes:
    """SELECT the share EF by file id. P2=0x00 and Le=0x00, same as OpenSC."""
    return bytes((0x00, 0xA4, 0x00, 0x00, 0x02)) + SHARE_EF_FID + b'\x00'


def apdu_read_share(length: int = 0) -> bytes:
    """Odd-INS READ BINARY of the selected EF.

    ``length`` 0 means Le=0 (up to 256 bytes). The offset is TLV tag 0x54,
    which is the form SmartCard-HSM implements. ISO READ BINARY (INS 0xB0)
    is not.
    """
    if length < 0 or length > 255:
        raise ValueError('share length out of range')
    return bytes((0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02, 0x00, 0x00, length & 0xFF))


def apdu_update_share(share: bytes) -> bytes:
    """Odd-INS UPDATE BINARY. The file id in P1-P2 creates the EF if needed."""
    if not share or len(share) > 127:
        raise ValueError('share length out of range')
    body = bytes((0x54, 0x02, 0x00, 0x00, 0x53, len(share))) + share
    return bytes((0x00, 0xD7, SHARE_EF_FID[0], SHARE_EF_FID[1], len(body))) + body


def _zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _gf_pow(a: int, n: int) -> int:
    result = 1
    base = a & 0xFF
    while n:
        if n & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        n >>= 1
    return result


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ValueError('division by zero in share reconstruction')
    return _gf_pow(a, 254)


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(256) with the AES polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def generate_dkek_shares(threshold_n: int, total_m: int, length: int = SHARE_LEN) -> List[bytes]:
    """Build ``total_m`` shares of which any ``threshold_n`` reconstruct the DKEK.

    n-of-n is an XOR split (32-byte shares). n-of-m is Shamir over GF(256),
    each share prefixed with its x-coordinate so the blob is what
    IMPORT_DKEK_SHARE will later receive. Callers must zeroize the returned
    buffers after the import APDU is built.
    """
    if threshold_n < 1 or total_m < 1 or threshold_n > total_m:
        raise ValueError('threshold_n/total_m out of range')
    secret = bytearray(os.urandom(length))
    try:
        if threshold_n == total_m:
            shares: List[bytearray] = []
            acc = bytearray(secret)
            for _ in range(total_m - 1):
                part = bytearray(os.urandom(length))
                shares.append(part)
                for j in range(length):
                    acc[j] ^= part[j]
            shares.append(acc)
            return [bytes(part) for part in shares]
        # Shamir: for each secret byte, degree (n-1), evaluate at x = 1..m.
        # Share layout: x || y[0] .. y[length-1]
        ys = [bytearray(length) for _ in range(total_m)]
        for byte_index in range(length):
            coeffs = [secret[byte_index]]
            coeffs.extend(os.urandom(threshold_n - 1))
            for x in range(1, total_m + 1):
                y = 0
                x_pow = 1
                for coeff in coeffs:
                    y ^= _gf_mul(coeff, x_pow)
                    x_pow = _gf_mul(x_pow, x)
                ys[x - 1][byte_index] = y
        return [bytes((x,)) + bytes(ys[x - 1]) for x in range(1, total_m + 1)]
    finally:
        _zeroize(secret)


def reconstruct_dkek(shares: List[bytes]) -> bytes:
    """Rebuild the 32-byte DKEK from XOR shares or from Shamir shares.

    XOR shares are 32 bytes. Shamir shares are ``x || 32 y-bytes``. The
    result is the value the card must receive, not the on-token file.
    """
    chosen = [bytes(part) for part in shares]
    if not chosen:
        raise ValueError('not enough shares')
    if all(len(part) == SHARE_LEN for part in chosen):
        acc = bytearray(SHARE_LEN)
        for part in chosen:
            for index, byte in enumerate(part):
                acc[index] ^= byte
        try:
            return bytes(acc)
        finally:
            _zeroize(acc)
    secret = bytearray(SHARE_LEN)
    xs = []
    ys = []
    for part in chosen:
        if len(part) != SHARE_LEN + 1:
            raise ValueError('DKEK share must be 32 bytes')
        xs.append(part[0])
        ys.append(part[1:])
    for byte_index in range(SHARE_LEN):
        value = 0
        for index, x_i in enumerate(xs):
            numerator = 1
            denominator = 1
            for other, x_j in enumerate(xs):
                if index == other:
                    continue
                numerator = _gf_mul(numerator, x_j)
                denominator = _gf_mul(denominator, x_i ^ x_j)
            basis = _gf_mul(numerator, _gf_inv(denominator))
            value ^= _gf_mul(ys[index][byte_index], basis)
        secret[byte_index] = value
    try:
        return bytes(secret)
    finally:
        _zeroize(secret)


def shares_to_import(shares: List[bytes], threshold: int) -> List[bytes]:
    """Return exactly ``threshold`` 32-byte blobs for IMPORT_DKEK_SHARE.

    The card XORs that many 32-byte shares. A Shamir file is longer than
    that, so it is reconstructed here and then split into card-sized pieces.
    """
    chosen = [bytes(part) for part in list(shares)[:threshold]]
    if len(chosen) < threshold:
        raise ValueError('not enough shares to import')
    if all(len(part) == SHARE_LEN for part in chosen):
        return chosen
    secret = bytearray(reconstruct_dkek(chosen))
    acc = bytearray(secret)
    parts: List[bytes] = []
    try:
        if threshold == 1:
            return [bytes(secret)]
        for _ in range(threshold - 1):
            part = bytearray(os.urandom(SHARE_LEN))
            parts.append(bytes(part))
            for index in range(SHARE_LEN):
                acc[index] ^= part[index]
            _zeroize(part)
        parts.append(bytes(acc))
        return parts
    finally:
        _zeroize(secret)
        _zeroize(acc)


class FakeCustodianToken:
    """One custodian card: holds a single share EF and no signing key."""

    def __init__(self, share: bytes):
        self._share = bytearray(share)

    def copy_share(self) -> bytearray:
        return bytearray(self._share)

    def replace_share(self, share: bytes) -> None:
        _zeroize(self._share)
        self._share = bytearray(share)

    def zeroize(self) -> None:
        _zeroize(self._share)
        self._share = bytearray()

    def transmit(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return b'\x6D\x00'
        cla, ins = apdu[0], apdu[1]
        data = b''
        if len(apdu) > 5:
            lc = apdu[4]
            data = apdu[5:5 + lc]
        if cla == 0x00 and ins == 0xA4:
            if data == SHARE_EF_FID:
                return b'\x90\x00'
            return b'\x6A\x82'
        if cla == 0x00 and ins == 0xB0:
            if not self._share:
                return b'\x6A\x82'
            return bytes(self._share) + b'\x90\x00'
        if cla == 0x00 and ins == 0xD6:
            if not data:
                return b'\x6A\x80'
            self.replace_share(data)
            return b'\x90\x00'
        return b'\x6D\x00'


def parse_sw(rapdu: bytes) -> Tuple[bytes, int, int]:
    if len(rapdu) < 2:
        raise ValueError('RAPDU too short')
    return rapdu[:-2], rapdu[-2], rapdu[-1]


def sw_ok(sw1: int, sw2: int) -> bool:
    return sw1 == 0x90 and sw2 == 0x00


def parse_key_domain_status(data: bytes) -> dict:
    """Status bytes after GET_STATUS / IMPORT: shares, outstanding, KCV…"""
    if len(data) < 2:
        return {'dkek_shares': None, 'outstanding_shares': None}
    return {
        'dkek_shares': data[0],
        'outstanding_shares': data[1],
        'key_check_value_hex': data[2:5].hex() if len(data) >= 5 else '',
    }


class FakeAssemblyToken:
    """In-memory stand-in for the assembly SmartCard-HSM (unit tests / CI)."""

    def __init__(self, *, threshold_n: int = 4, total_m: int = 4, atr: Optional[bytes] = None):
        self.threshold_n = threshold_n
        self.total_m = total_m
        self.atr = atr or bytes.fromhex('3BFE1800008031FE4580318065')
        self.shares: List[bytes] = []
        self.outstanding = threshold_n
        self.wrapped_blob: Optional[bytes] = None
        self.keys: dict = {}  # key_id -> label
        self.root_key_id: Optional[int] = None
        self._dkek_ready = False
        self._private = None

    def transmit(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return b'\x6D\x00'
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        data = b''
        if len(apdu) > 5:
            lc = apdu[4]
            data = apdu[5:5 + lc]

        if cla == 0x80 and ins == 0x52:
            if p1 == OP_GET_STATUS:  # actually GET uses P1=0 which equals import-1
                # Ambiguous with import P1=0 — distinguish by presence of data.
                if not data:
                    status = bytes((self.total_m, self.outstanding)) + b'\x00\x00\x00'
                    return status + b'\x90\x00'
                # import share
                self.shares.append(bytes(data))
                self.outstanding = max(0, self.threshold_n - len(self.shares))
                if self.outstanding == 0:
                    self._dkek_ready = True
                status = bytes((self.total_m, self.outstanding)) + b'\x11\x22\x33'
                return status + b'\x90\x00'
            if p1 == OP_DELETE_KEY_DOMAIN - 1:
                self.shares.clear()
                self.outstanding = self.threshold_n
                self._dkek_ready = False
                self.wrapped_blob = None
                return b'\x90\x00'
            if p1 == OP_CLEAR_KEK - 1:
                self.shares.clear()
                self.outstanding = self.threshold_n
                self._dkek_ready = False
                return b'\x90\x00'
            return b'\x6A\x86'

        if cla == 0x80 and ins == 0x74 and p2 == 0x93:
            if not self._dkek_ready:
                return b'\x69\x85'
            key_id = p1
            self.ensure_key()
            self.keys[key_id] = 'root'
            self.root_key_id = key_id
            return b'\x90\x00'

        if cla == 0x80 and ins == 0x72 and p2 == 0x92:
            if p1 not in self.keys:
                return b'\x6A\x88'
            blob = self.wrapped_blob or b'\x00' * 32
            return blob + b'\x90\x00'

        if cla == 0x00 and ins == 0xE4:
            if len(data) == 2 and data[0] == KEY_PREFIX:
                kid = data[1]
                self.keys.pop(kid, None)
                if self.root_key_id == kid:
                    self.root_key_id = None
                    self._private = None
                return b'\x90\x00'
            return b'\x6A\x82'

        # SELECT / VERIFY etc. — acknowledge
        return b'\x90\x00'

    def list_key_ids(self) -> List[int]:
        return sorted(self.keys.keys())

    def wipe_root(self) -> bool:
        if self.root_key_id is None and self._private is None:
            return True
        if self.root_key_id is None:
            self._private = None
            return True
        kid = self.root_key_id
        rapdu = self.transmit(apdu_delete_key_file(kid))
        _, sw1, sw2 = parse_sw(rapdu)
        if not sw_ok(sw1, sw2):
            return False
        return kid not in self.keys and self._private is None

    def ensure_key(self):
        """RSA key that exists only inside this fake chip after unwrap."""
        if self._private is None:
            self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._private

    def public_pem(self) -> str:
        public = self.ensure_key().public_key()
        return public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')

    def sign_pkcs1(self, data: bytes, hash_algorithm: str) -> bytes:
        if self._private is None or self.root_key_id is None:
            raise RuntimeError('assembly token has no root key')
        digest = {
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512(),
        }.get(hash_algorithm, hashes.SHA256())
        return self._private.sign(data, padding.PKCS1v15(), digest)

    def rotate_signing_key(self) -> Tuple[str, bytes]:
        """Replace the on-chip key. Returns (public PEM, wrapped blob)."""
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_key_id = self.root_key_id or 1
        self.keys[self.root_key_id] = 'root'
        blob = os.urandom(48)
        self.wrapped_blob = blob
        return self.public_pem(), blob
