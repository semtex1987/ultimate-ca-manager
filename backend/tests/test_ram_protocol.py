"""RAMOverHTTP TLV fixtures derived from CardContact/sc-hsm-embedded src/ramoverhttp.

No live ram-client exchange was available in CI; encodings match ramoverhttp.c
(tlvEncodeLength / makeInitiationRequest / processRequests / ramForceClose).
"""
from __future__ import annotations

import pytest

from services.hsm.ram_protocol import (
    CONTENT_TYPE,
    RAM_CAPDU,
    RAM_CLOSE,
    RAM_INIT_TEMPL,
    RAM_NUM_APDU,
    RAM_RAPDU,
    RAM_REQ_TEMPL,
    RAM_RES_TEMPL,
    RAM_RESET,
    InitiationRequest,
    CloseNotification,
    RequestTemplate,
    ResponseTemplate,
    encode_integer,
    encode_length,
    encode_tlv,
    is_empty_keepalive,
    iter_tlvs,
)


def test_content_type_matches_ram_client():
    assert CONTENT_TYPE == 'application/org.openscdp-content-mgt-response;version=1.0'


def test_encode_length_short_long_form():
    assert encode_length(5) == b'\x05'
    assert encode_length(128) == b'\x81\x80'
    assert encode_length(256) == b'\x82\x01\x00'


def test_initiation_request_roundtrip():
    atr = bytes.fromhex('3BFE1800008031FE4580318065')
    raw = InitiationRequest(atr=atr).encode()
    assert raw[0] == RAM_INIT_TEMPL
    decoded = InitiationRequest.decode(raw)
    assert decoded.atr == atr
    # Inner C0 ATR present
    body = iter_tlvs(raw)[0].value
    assert iter_tlvs(body)[0].tag == RAM_RESET


def test_keepalive_is_empty_request_template():
    tmpl = RequestTemplate.keepalive()
    assert is_empty_keepalive(tmpl)
    encoded = tmpl.encode()
    assert encoded[0] == RAM_REQ_TEMPL
    assert is_empty_keepalive(encoded)
    assert RequestTemplate.decode(encoded).commands == []


def test_request_with_capdu():
    tmpl = RequestTemplate()
    tmpl.add_capdu(b'\x00\xA4\x04\x00\x00')
    raw = tmpl.encode()
    decoded = RequestTemplate.decode(raw)
    assert len(decoded.commands) == 1
    assert decoded.commands[0].tag == RAM_CAPDU


def test_response_template_from_rapdus():
    rapdu = b'\x90\x00'
    resp = ResponseTemplate.from_rapdus([rapdu])
    raw = resp.encode()
    assert raw[0] == RAM_RES_TEMPL
    decoded = ResponseTemplate.decode(raw)
    assert decoded.rapdus() == [rapdu]
    assert decoded.apdu_count == 1
    assert any(i.tag == RAM_NUM_APDU for i in decoded.items)


def test_close_notification_shape():
    # Matches ramForceClose: E1 wrapping 0C UTF8 message
    close = CloseNotification(message='card removed')
    raw = close.encode()
    assert raw[0] == RAM_CLOSE
    items = iter_tlvs(raw)
    nested = iter_tlvs(items[0].value)
    assert nested[0].value == b'card removed'


def test_encode_integer_minimal():
    assert encode_integer(0) == b'\x00'
    assert encode_integer(1) == b'\x01'
    assert encode_integer(127) == b'\x7F'
    assert encode_integer(128) == b'\x00\x80'
