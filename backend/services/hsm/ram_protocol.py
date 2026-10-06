"""RAMOverHTTP TLV codec.

Matches CardContact/sc-hsm-embedded ``src/ramoverhttp`` (ramoverhttp.h / .c).
Fixtures are derived from that encoder — CI has no live ram-client exchange.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

# TLV tags (ramoverhttp.h)
RAM_INT = 0x02
RAM_UTF8 = 0x0C
RAM_NUM_APDU = 0x80
RAM_REQ_TEMPL = 0xAA
RAM_RES_TEMPL = 0xAB
RAM_INIT_TEMPL = 0xE8
RAM_CAPDU = 0x22
RAM_RAPDU = 0x23
RAM_RESET = 0xC0
RAM_NOTIFY = 0xE0
RAM_CLOSE = 0xE1

# Content-Type used by ram-client (ramConnect)
CONTENT_TYPE = 'application/org.openscdp-content-mgt-response;version=1.0'
ACCEPT = '*/*'
ADMIN_PROTOCOL = 'openscdp-remote-admin/1.0'


class RamProtocolError(ValueError):
    """Malformed or unexpected RAMOverHTTP TLV."""


def encode_length(length: int) -> bytes:
    """Encode a BER-style length the way ``tlvEncodeLength`` does."""
    if length < 0:
        raise RamProtocolError(f'negative length: {length}')
    if length >= 256:
        return bytes((0x82, (length >> 8) & 0xFF, length & 0xFF))
    if length >= 128:
        return bytes((0x81, length & 0xFF))
    return bytes((length,))


def decode_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Return ``(length, new_offset)`` matching ``tlvLength``."""
    if offset >= len(data):
        raise RamProtocolError('truncated length')
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 2:
            raise RamProtocolError('invalid length form')
        if offset + count > len(data):
            raise RamProtocolError('truncated length')
        value = 0
        for _ in range(count):
            value = (value << 8) | data[offset]
            offset += 1
        return value, offset
    return first, offset


def encode_tlv(tag: int, value: bytes = b'') -> bytes:
    if not (0 <= tag <= 0xFF):
        raise RamProtocolError(f'tag out of range: {tag}')
    return bytes((tag,)) + encode_length(len(value)) + value


def encode_integer(value: int) -> bytes:
    """Minimal big-endian two's-complement (``encodeInteger``)."""
    if -0x80 <= value <= 0x7F:
        width = 1
    elif -0x8000 <= value <= 0x7FFF:
        width = 2
    elif -0x800000 <= value <= 0x7FFFFF:
        width = 3
    else:
        width = 4
    out = bytearray(width)
    v = value & ((1 << (8 * width)) - 1)
    for i in range(width - 1, -1, -1):
        out[i] = v & 0xFF
        v >>= 8
    return bytes(out)


def decode_integer(raw: bytes) -> int:
    if not raw or len(raw) > 4:
        raise RamProtocolError('invalid INTEGER')
    bits = 8 * len(raw)
    unsigned = int.from_bytes(raw, 'big')
    if raw[0] & 0x80:
        return unsigned - (1 << bits)
    return unsigned


@dataclass
class Tlv:
    tag: int
    value: bytes = b''

    def encode(self) -> bytes:
        return encode_tlv(self.tag, self.value)


def iter_tlvs(data: bytes) -> List[Tlv]:
    """Decode a sequence of top-level TLVs (``tlvNext`` loop)."""
    items: List[Tlv] = []
    offset = 0
    remaining = len(data)
    while remaining > 0:
        base = offset
        if offset >= len(data):
            break
        tag = data[offset]
        offset += 1
        length, offset = decode_length(data, offset)
        if offset + length > len(data):
            raise RamProtocolError('TLV value truncated')
        value = data[offset:offset + length]
        offset += length
        remaining -= (offset - base)
        items.append(Tlv(tag=tag, value=value))
    return items


def unwrap_template(data: bytes, expected_tag: int) -> bytes:
    """Return the value of a single outer template TLV."""
    items = iter_tlvs(data)
    if len(items) != 1 or items[0].tag != expected_tag:
        raise RamProtocolError(
            f'expected single template tag 0x{expected_tag:02X}, got '
            f'{[hex(i.tag) for i in items]}'
        )
    return items[0].value


@dataclass
class InitiationRequest:
    """First POST body from ram-client: ``E8`` wrapping a ``C0`` ATR."""
    atr: bytes

    def encode(self) -> bytes:
        inner = encode_tlv(RAM_RESET, self.atr)
        return encode_tlv(RAM_INIT_TEMPL, inner)

    @classmethod
    def decode(cls, data: bytes) -> 'InitiationRequest':
        body = unwrap_template(data, RAM_INIT_TEMPL)
        items = iter_tlvs(body)
        atr = b''
        for item in items:
            if item.tag == RAM_RESET:
                atr = item.value
        if not atr:
            raise RamProtocolError('initiation template missing ATR (C0)')
        return cls(atr=atr)


@dataclass
class NotifyCommand:
    message_id: int = 0
    message: str = ''

    def encode_inner(self) -> bytes:
        parts = [
            encode_tlv(RAM_INT, encode_integer(self.message_id)),
            encode_tlv(RAM_UTF8, self.message.encode('utf-8')),
        ]
        return b''.join(parts)


@dataclass
class CloseNotification:
    message: str = ''

    def encode(self) -> bytes:
        utf8 = encode_tlv(RAM_UTF8, self.message.encode('utf-8'))
        return encode_tlv(RAM_CLOSE, utf8)

    @classmethod
    def decode_from_response_items(cls, items: List[Tlv]) -> Optional['CloseNotification']:
        for item in items:
            if item.tag == RAM_CLOSE:
                nested = iter_tlvs(item.value)
                msg = ''
                for n in nested:
                    if n.tag == RAM_UTF8:
                        msg = n.value.decode('utf-8', errors='replace')
                return cls(message=msg)
        return None


@dataclass
class RequestTemplate:
    """Server → client command template (``AA``).

    An empty template (no CAPDU/RESET/NOTIFY) is the keepalive.
    """
    commands: List[Tlv] = field(default_factory=list)

    @classmethod
    def keepalive(cls) -> 'RequestTemplate':
        return cls(commands=[])

    def add_capdu(self, apdu: bytes) -> None:
        self.commands.append(Tlv(RAM_CAPDU, apdu))

    def add_reset(self) -> None:
        self.commands.append(Tlv(RAM_RESET, b''))

    def add_notify(self, message_id: int = 0, message: str = '') -> None:
        self.commands.append(Tlv(RAM_NOTIFY, NotifyCommand(message_id, message).encode_inner()))

    def encode(self) -> bytes:
        body = b''.join(c.encode() for c in self.commands)
        return encode_tlv(RAM_REQ_TEMPL, body)

    @classmethod
    def decode(cls, data: bytes) -> 'RequestTemplate':
        if not data:
            return cls.keepalive()
        body = unwrap_template(data, RAM_REQ_TEMPL)
        return cls(commands=iter_tlvs(body) if body else [])


@dataclass
class ResponseTemplate:
    """Client → server response template (``AB``)."""
    items: List[Tlv] = field(default_factory=list)
    apdu_count: int = 0

    def rapdus(self) -> List[bytes]:
        return [i.value for i in self.items if i.tag == RAM_RAPDU]

    def atr(self) -> Optional[bytes]:
        for item in self.items:
            if item.tag == RAM_RESET and item.value:
                return item.value
        return None

    def close(self) -> Optional[CloseNotification]:
        return CloseNotification.decode_from_response_items(self.items)

    def encode(self) -> bytes:
        # Client always appends NUM_APDU then wraps in RES_TEMPL (processRequests).
        parts = list(self.items)
        has_num = any(i.tag == RAM_NUM_APDU for i in parts)
        if not has_num:
            parts.append(Tlv(RAM_NUM_APDU, encode_integer(self.apdu_count)))
        body = b''.join(p.encode() for p in parts)
        return encode_tlv(RAM_RES_TEMPL, body)

    @classmethod
    def decode(cls, data: bytes) -> 'ResponseTemplate':
        body = unwrap_template(data, RAM_RES_TEMPL)
        items = iter_tlvs(body) if body else []
        count = 0
        for item in items:
            if item.tag == RAM_NUM_APDU:
                count = decode_integer(item.value)
        return cls(items=items, apdu_count=count)

    @classmethod
    def from_rapdus(cls, rapdus: List[bytes], *, atr: Optional[bytes] = None) -> 'ResponseTemplate':
        items: List[Tlv] = []
        if atr is not None:
            items.append(Tlv(RAM_RESET, atr))
        for rapdu in rapdus:
            items.append(Tlv(RAM_RAPDU, rapdu))
        return cls(items=items, apdu_count=len(rapdus))


def is_empty_keepalive(request: Union[RequestTemplate, bytes]) -> bool:
    if isinstance(request, (bytes, bytearray)):
        if not request:
            return True
        try:
            request = RequestTemplate.decode(bytes(request))
        except RamProtocolError:
            return False
    return not request.commands
