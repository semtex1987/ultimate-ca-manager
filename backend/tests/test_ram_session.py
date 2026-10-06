"""RAM session rendezvous and vpcd framing unit tests (no pcscd)."""
from __future__ import annotations

import struct
import threading

import pytest

from services.hsm.ram_protocol import InitiationRequest, ResponseTemplate
from services.hsm.ram_session import (
    RamSessionManager,
    SessionBusyError,
    SessionDropError,
)
from services.hsm.vpcd_card import (
    VPCD_CTRL_ATR,
    VPCD_CTRL_ON,
    VpcdVirtualCard,
    encode_frame,
)


ATR = bytes.fromhex('3BFE1800008031FE4580318065')


def test_four_custodians_accepted_second_refused():
    mgr = RamSessionManager()
    tokens = {}
    for i in range(4):
        tok = f'token-{i}'
        tokens[tok] = f'cust-{i}'
        mgr.register_slot(f'cust-{i}', tok)

    sessions = []
    for tok, cid in tokens.items():
        s = mgr.accept_client(tok, InitiationRequest(atr=ATR))
        assert s.connected
        assert s.custodian_id == cid
        sessions.append(s)

    assert len(mgr.connected_custodians()) == 4

    with pytest.raises(SessionBusyError):
        mgr.accept_client('token-0', InitiationRequest(atr=ATR))


def test_keepalive_reply_is_not_paired_with_a_later_capdu():
    """A response already in flight for an empty template must not complete a new command."""
    mgr = RamSessionManager()
    mgr.register_slot('c1', 'tok')
    session = mgr.accept_client('tok', InitiationRequest(atr=ATR))

    def client():
        assert session.wait_for_work(2.0)
        session.apply_response(ResponseTemplate.from_rapdus([]))
        req = session.build_request()
        assert req.commands
        session.apply_response(ResponseTemplate.from_rapdus([b'\x90\x00']))

    t = threading.Thread(target=client)
    t.start()
    rapdu = session.queue_transmit(b'\x00\xA4\x00\x00\x02', timeout=5.0)
    t.join(timeout=5)
    assert rapdu == b'\x90\x00'


def test_share_select_uses_p2_that_smartcard_hsm_accepts():
    from services.hsm.sc_hsm_apdu import SHARE_EF_FID, apdu_read_share, apdu_select_share_ef, apdu_update_share
    select = apdu_select_share_ef()
    assert select[1] == 0xA4
    assert select[2] == 0x00
    assert select[3] == 0x00  # P2=0C is SW 6A86 on this card
    assert select.endswith(SHARE_EF_FID + b'\x00')
    assert SHARE_EF_FID != b'\x2F\x02'
    read = apdu_read_share(0)
    assert read[1] == 0xB1
    share = b'\x11' * 32
    update = apdu_update_share(share)
    assert update[1] == 0xD7
    assert update[2:4] == SHARE_EF_FID
    assert share in update


def test_apdu_roundtrip_via_session():
    mgr = RamSessionManager()
    mgr.register_slot('c1', 'tok')
    session = mgr.accept_client('tok', InitiationRequest(atr=ATR))

    result = {}

    def client():
        # Wait for CAPDU in request template
        assert session.wait_for_work(2.0)
        req = session.build_request()
        assert req.commands
        # Reply with RAPDU
        session.apply_response(ResponseTemplate.from_rapdus([b'\x90\x00']))

    t = threading.Thread(target=client)
    t.start()
    rapdu = session.queue_transmit(b'\x00\xA4\x00\x00\x00', timeout=5.0)
    t.join(timeout=5)
    assert rapdu == b'\x90\x00'


def test_drop_mid_ceremony_invokes_callback():
    mgr = RamSessionManager()
    mgr.register_slot('c1', 'tok')
    dropped = []
    mgr.set_ceremony_active(True)
    mgr.on_mid_ceremony_drop(lambda s: dropped.append(s.custodian_id))
    session = mgr.accept_client('tok', InitiationRequest(atr=ATR))
    session.close('gone')
    assert dropped == ['c1']
    with pytest.raises(SessionDropError):
        session.queue_transmit(b'\x00\x00')


def test_vpcd_atr_and_transmit():
    seen = []

    def transmit(apdu: bytes) -> bytes:
        seen.append(apdu)
        return b'\x90\x00'

    card = VpcdVirtualCard(atr=ATR, transmit=transmit)
    assert card.handle_payload(bytes([VPCD_CTRL_ON])) is None
    assert card.handle_payload(bytes([VPCD_CTRL_ATR])) == ATR
    assert card.handle_payload(b'\x00\xA4\x04\x00') == b'\x90\x00'
    assert seen == [b'\x00\xA4\x04\x00']


def test_vpcd_frame_length_prefix():
    payload = b'\x01'
    frame = encode_frame(payload)
    assert struct.unpack('!H', frame[:2])[0] == 1
    assert frame[2:] == payload


def test_ram_bridge_defaults_and_mark_crl_signed():
    from services.hsm.ram_bridge import DEFAULT_RAM_PORT, DEFAULT_SOCK_PATH, RamBridge
    from services.hsm.vpcd_card import DEFAULT_VPCD_HOST, DEFAULT_VPCD_PORT

    assert DEFAULT_RAM_PORT == 8444
    assert DEFAULT_SOCK_PATH == '/opt/ucm/data/ram-bridge.sock'
    assert DEFAULT_VPCD_HOST == '127.0.0.1'
    assert DEFAULT_VPCD_PORT == 35963

    bridge = RamBridge.__new__(RamBridge)
    from services.hsm.ram_bridge import CeremonyState
    bridge.ceremony = CeremonyState()
    bridge.ceremony.key_assembled = True
    bridge.ceremony.last_change_seq = 3
    out = bridge.cmd_mark_crl_signed({})
    assert out['ok'] is True
    assert out['ceremony']['crl_ready_for_wipe'] is True
