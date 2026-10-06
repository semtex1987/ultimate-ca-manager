"""sc-hsm-cloud provider + ceremony API (fakes; no pcscd / no live token)."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time

import pytest

from models import db
from models.hsm import HsmCustodian, HsmProvider
from models.user import User
from services.hsm.ram_bridge import RamBridge
from services.hsm.sc_hsm_cloud_provider import ScHsmCloudProvider, call_bridge
from services.hsm import HsmService


@pytest.fixture
def bridge_sock():
    # AF_UNIX paths on macOS are capped (~104 bytes); keep the socket short.
    sock = f'/tmp/ucm-ram-test-{os.getpid()}.sock'
    if os.path.exists(sock):
        os.unlink(sock)
    bridge = RamBridge(
        ram_port=0,
        sock_path=sock,
        bind_host='127.0.0.1',
        vpcd_host='127.0.0.1',
        vpcd_port=1,  # nothing listening — client reconnects quietly
    )
    os.environ['RAM_BRIDGE_FAKE'] = '1'
    bridge.ceremony.use_fake = True
    bridge.start()
    assert bridge._http is not None
    bridge.ram_port = bridge._http.server_address[1]
    yield bridge
    bridge.stop()
    os.environ.pop('RAM_BRIDGE_FAKE', None)
    if os.path.exists(sock):
        try:
            os.unlink(sock)
        except OSError:
            pass


def test_provider_registered():
    assert 'sc-hsm-cloud' in HsmService.get_available_providers()
    assert 'sc-hsm-cloud' in HsmProvider.VALID_TYPES


def test_bridge_control_status(bridge_sock):
    status = call_bridge('status', sock_path=bridge_sock.sock_path)
    assert status['ok'] is True
    assert 'ceremony' in status
    assert status['ceremony']['active'] is False


def test_bridge_ceremony_assemble_and_wipe(bridge_sock):
    sock = bridge_sock.sock_path
    begin = call_bridge('begin_ceremony', {
        'provider_id': 1,
        'threshold_n': 2,
        'total_m': 2,
        'use_fake': True,
        'assembly_custodian_id': '1',
        'custodians': [
            {'custodian_id': '1', 'connect_token': 'tok-a', 'share_index': 1},
            {'custodian_id': '2', 'connect_token': 'tok-b', 'share_index': 2},
        ],
    }, sock_path=sock)
    assert begin['ok']

    import base64
    share = base64.b64encode(b'\x11' * 32).decode()
    assert call_bridge('import_share', {'share_b64': share}, sock_path=sock)['ok']
    assert call_bridge('import_share', {'share_b64': share}, sock_path=sock)['ok']

    wrapped = base64.b64encode(b'\xAA' * 64).decode()
    unwrap = call_bridge('unwrap_root', {'wrapped_root_b64': wrapped}, sock_path=sock)
    assert unwrap['ok']
    assert unwrap['ceremony']['key_assembled'] is True

    # Sign marks CRL fresh
    data_b64 = base64.b64encode(b'tbs-crl').decode()
    signed = call_bridge('sign_crl', {'data_b64': data_b64, 'is_crl': True}, sock_path=sock)
    assert signed['ok']
    assert signed['ceremony']['crl_ready_for_wipe'] is True

    wipe = call_bridge('wipe_assembly', sock_path=sock)
    assert wipe['ok']
    assert wipe.get('wipe_verified') or wipe['ceremony']['wipe_verified']

    end = call_bridge('end_ceremony', sock_path=sock)
    assert end['ok']


def test_provider_sign_refused_outside_window(bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    p = ScHsmCloudProvider({
        'token_label': 'test',
        'threshold_n': 2,
        'total_m': 2,
        'socket_path': bridge_sock.sock_path,
    })
    with pytest.raises(Exception):
        p.sign('1', b'data')


def test_create_sc_hsm_provider_with_custodians(auth_client, app):
    with app.app_context():
        # Need a second user for custodian roster
        u2 = User(username='custodian1', email='c1@example.com', role='operator')
        u2.set_password('TestPass123!')
        db.session.add(u2)
        db.session.commit()
        uid = u2.id

    r = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Offline Root HSM',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'root-domain',
            'threshold_n': 2,
            'total_m': 2,
            'custodians': [
                {'user_id': uid, 'share_index': 1},
                {'user_id': uid, 'share_index': 2},
            ],
        },
    })
    assert r.status_code in (200, 201), r.get_json()
    body = r.get_json()
    data = body.get('data') or body
    assert data['type'] == 'sc-hsm-cloud'

    pid = data['id']
    # List omits ram_client_url
    listed = auth_client.get('/api/v2/hsm/providers').get_json()
    items = listed.get('data') or listed
    row = next(p for p in items if p['id'] == pid)
    for c in row.get('custodians') or []:
        assert 'ram_client_url' not in c

    detail = auth_client.get(f'/api/v2/hsm/providers/{pid}').get_json()
    d = detail.get('data') or detail
    assert d['token_label'] == 'root-domain'
    assert d['threshold_n'] == 2
    assert d['total_m'] == 2
    assert d['ceremony_status'] == 'offline'
    assert d['wipe_confirmed'] is False
    assert d['crl_stale'] is False
    assert 'assembly_slot' in d
    assert 'ocsp_responder_warning' in d
    assert isinstance(d['custodians'], list)
    assert len(d['custodians']) == 2
    # write:hsm sees URLs
    c0 = d['custodians'][0]
    assert c0.get('ram_client_url')
    assert 'hsm/ram/' in c0['ram_client_url']
    assert d['ram_public']['origin']
    assert d['ram_public']['mode'] in ('dedicated', 'direct_port')
    assert c0['ram_client_url'].startswith(d['ram_public']['origin'])
    assert c0['user_id'] == uid
    assert c0['share_index'] in (1, 2)
    assert c0['status'] in ('waiting', 'connected', 'contributed')
    assert 'username' in c0 or 'name' in c0
    assert 'is_me' in c0

    with app.app_context():
        rows = HsmCustodian.query.filter_by(provider_id=pid).all()
        assert len(rows) == 2
        # Tokens encrypted at rest — not plaintext share material
        for row in rows:
            assert row.connect_token_enc
            assert row.get_connect_token()
            assert b'DKEK' not in (row.connect_token_enc.encode() if isinstance(row.connect_token_enc, str) else row.connect_token_enc)


def test_ceremony_http_flow(auth_client, app, bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    with app.app_context():
        u2 = User(username='keyholder', email='kh@example.com', role='operator')
        u2.set_password('TestPass123!')
        db.session.add(u2)
        db.session.commit()
        uid = u2.id

    create = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Ceremony Root',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'cer',
            'threshold_n': 1,
            'total_m': 1,
            'socket_path': bridge_sock.sock_path,
            'custodians': [{'user_id': uid, 'share_index': 1}],
        },
    })
    assert create.status_code in (200, 201), create.get_json()
    pid = (create.get_json().get('data') or create.get_json())['id']

    begin = auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/begin')
    assert begin.status_code == 200, begin.get_json()
    d = begin.get_json().get('data') or begin.get_json()
    assert d['ceremony_status'] != 'offline'
    custodian_id = str(d['custodians'][0]['id'])
    connected = call_bridge(
        'connect_fake',
        {'custodian_id': custodian_id},
        sock_path=bridge_sock.sock_path,
    )
    assert connected['ok'] is True

    slot = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/assembly-slot',
        json={'share_index': 1},
    )
    assert slot.status_code == 200, slot.get_json()
    assert (slot.get_json().get('data') or slot.get_json())['assembly_slot'] == 1

    # Wipe without assembled key / without stale CRL
    wipe = auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/wipe')
    assert wipe.status_code == 200, wipe.get_json()
    assert (wipe.get_json().get('data') or wipe.get_json())['wipe_confirmed'] is True

    end = auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/end')
    assert end.status_code == 200, end.get_json()
    d = end.get_json().get('data') or end.get_json()
    assert d['ceremony_status'] == 'offline'


def test_wipe_refuses_when_crl_stale(auth_client, app, bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    with app.app_context():
        u2 = User(username='kh2', email='kh2@example.com', role='operator')
        u2.set_password('TestPass123!')
        db.session.add(u2)
        db.session.commit()
        uid = u2.id

    create = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Stale CRL Root',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'stale',
            'threshold_n': 1,
            'total_m': 1,
            'socket_path': bridge_sock.sock_path,
            'custodians': [{'user_id': uid, 'share_index': 1}],
        },
    })
    pid = (create.get_json().get('data') or create.get_json())['id']
    auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/begin')

    with app.app_context():
        p = db.session.get(HsmProvider, pid)
        cfg = p.get_config()
        cfg['crl_stale'] = True
        p.set_config(cfg)
        db.session.commit()

    wipe = auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/wipe')
    assert wipe.status_code == 400
    body = wipe.get_json() or {}
    msg = str(body.get('detail') or body.get('error') or body.get('message') or body)
    assert 'CRL' in msg or 'crl' in msg.lower()


def test_provider_types_include_schsm(auth_client):
    r = auth_client.get('/api/v2/hsm/provider-types')
    data = r.get_json().get('data') or r.get_json()
    types = [t['type'] for t in data]
    assert 'sc-hsm-cloud' in types
    schsm = next(t for t in data if t['type'] == 'sc-hsm-cloud')
    assert schsm['label'] == 'SmartCard-HSM (remote)'
    assert 'threshold_n' in schsm['config_schema']
    assert 'custodians' in schsm['config_schema']


def test_begin_ceremony_does_not_force_fake(app, monkeypatch):
    captured = {}

    def _fake_call(method, params=None, sock_path=None):
        captured['method'] = method
        captured['params'] = params or {}
        return {'ok': True}

    monkeypatch.delenv('RAM_BRIDGE_FAKE', raising=False)
    monkeypatch.setattr('services.hsm.ceremony_service.call_bridge', _fake_call)

    with app.app_context():
        u = User(username='fake-check', email='fake-check@example.com', role='operator')
        u.set_password('TestPass123!')
        db.session.add(u)
        db.session.commit()
        uid = u.id
        p = HsmProvider(name='No Forced Fake', type='sc-hsm-cloud', config='{}', status='offline')
        p.set_config({'token_label': 'x', 'threshold_n': 1, 'total_m': 1})
        db.session.add(p)
        db.session.flush()
        from services.hsm.hsm_service import HsmService
        HsmService.sync_custodians(p, [{'user_id': uid, 'share_index': 1}])
        db.session.commit()
        from services.hsm.ceremony_service import begin_ceremony
        begin_ceremony(p)

    assert captured['method'] == 'begin_ceremony'
    assert captured['params'].get('use_fake') is False


def test_contribute_hsm_lists_own_provider(auth_client, app):
    from models.group import Group, GroupMember

    with app.app_context():
        holder = User(username='schsm-holder', email='schsm-holder@example.com', role='viewer')
        holder.set_password('TestPass123!')
        db.session.add(holder)
        other = User(username='schsm-other', email='schsm-other@example.com', role='operator')
        other.set_password('TestPass123!')
        db.session.add(other)
        grp = Group(name='schsm-holders', permissions=['contribute:hsm'])
        db.session.add(grp)
        db.session.flush()
        db.session.add(GroupMember(group_id=grp.id, user_id=holder.id))
        db.session.commit()
        holder_id = holder.id
        other_id = other.id

    create = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Contribute Root',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'contrib',
            'threshold_n': 1,
            'total_m': 2,
            'custodians': [
                {'user_id': holder_id, 'share_index': 1},
                {'user_id': other_id, 'share_index': 2},
            ],
        },
    })
    assert create.status_code in (200, 201), create.get_json()
    pid = (create.get_json().get('data') or create.get_json())['id']

    client = app.test_client()
    login = client.post('/api/v2/auth/login', json={
        'username': 'schsm-holder', 'password': 'TestPass123!',
    })
    assert login.status_code == 200, login.get_json()

    listed = client.get('/api/v2/hsm/providers')
    assert listed.status_code == 200, listed.get_json()
    items = listed.get_json().get('data') or listed.get_json()
    ids = [p['id'] for p in items]
    assert pid in ids
    for row in items:
        for c in row.get('custodians') or []:
            assert 'ram_client_url' not in c

    detail = client.get(f'/api/v2/hsm/providers/{pid}')
    assert detail.status_code == 200, detail.get_json()
    d = detail.get_json().get('data') or detail.get_json()
    mine = next(c for c in d['custodians'] if c['user_id'] == holder_id)
    theirs = next(c for c in d['custodians'] if c['user_id'] == other_id)
    assert mine.get('is_me') is True
    assert mine.get('ram_client_url')
    assert 'hsm/ram/' in mine['ram_client_url']
    assert theirs.get('is_me') is False
    assert 'ram_client_url' not in theirs


def test_contribute_custodian_may_inspect_only_own_token(auth_client, app, monkeypatch):
    """Ownership uses the authenticated user, not a missing g.user_id attribute."""
    from models.group import Group, GroupMember

    monkeypatch.setattr(
        'services.hsm.ceremony_service.inspect_token',
        lambda provider, custodian_id: {'ok': True, 'card': {'state': 'ready'}},
    )

    with app.app_context():
        holder = User(username='inspect-holder', email='inspect-holder@example.com', role='viewer')
        holder.set_password('TestPass123!')
        db.session.add(holder)
        other = User(username='inspect-other', email='inspect-other@example.com', role='operator')
        other.set_password('TestPass123!')
        db.session.add(other)
        grp = Group(name='inspect-holders', permissions=['contribute:hsm'])
        db.session.add(grp)
        db.session.flush()
        db.session.add(GroupMember(group_id=grp.id, user_id=holder.id))
        db.session.commit()
        holder_id = holder.id
        other_id = other.id

    create = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Inspect Own Token',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'inspect',
            'threshold_n': 1,
            'total_m': 2,
            'custodians': [
                {'user_id': holder_id, 'share_index': 1},
                {'user_id': other_id, 'share_index': 2},
            ],
        },
    })
    assert create.status_code in (200, 201), create.get_json()
    pid = (create.get_json().get('data') or create.get_json())['id']
    with app.app_context():
        rows = HsmCustodian.query.filter_by(provider_id=pid).all()
        mine = next(row.id for row in rows if row.user_id == holder_id)
        theirs = next(row.id for row in rows if row.user_id == other_id)

    client = app.test_client()
    login = client.post('/api/v2/auth/login', json={
        'username': 'inspect-holder', 'password': 'TestPass123!',
    })
    assert login.status_code == 200, login.get_json()

    own = client.post(f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{mine}/inspect')
    assert own.status_code == 200, own.get_json()
    foreign = client.post(f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{theirs}/inspect')
    assert foreign.status_code == 403, foreign.get_json()
    assert 'only your own token' in (foreign.get_json().get('message') or '')


def test_fake_custodian_select_hides_an_empty_share():
    from services.hsm.sc_hsm_apdu import FakeCustodianToken, apdu_select_share_ef

    card = FakeCustodianToken(b'\x11' * 32)
    assert card.transmit(apdu_select_share_ef())[-2:] == b'\x90\x00'
    card.zeroize()
    assert card.transmit(apdu_select_share_ef())[-2:] == b'\x6A\x82'
    card.replace_share(b'\x22' * 32)
    assert card.transmit(apdu_select_share_ef())[-2:] == b'\x90\x00'


def test_missing_share_file_is_not_a_probe_error():
    from services.hsm.sc_hsm_apdu import interpret_share_probe

    missing = interpret_share_probe(0x6A, 0x82)
    assert missing['readable'] is False
    assert missing['probe_error'] is None
    assert missing['probe_sw'] == '6A82'
    assert 'absent' in missing['log']

    present = interpret_share_probe(0x90, 0x00)
    assert present['readable'] is True
    assert present['probe_error'] is None

    other = interpret_share_probe(0x6A, 0x86)
    assert other['probe_error'] == 'SW=6A86'
    assert other['readable'] is False


def test_custodian_access_is_logged_once_per_change(caplog):
    from services.hsm.ceremony_service import _log_custodian_access, _logged_access

    _logged_access.clear()
    entry = {
        'id': 7,
        'access': 'card',
        'probe_error': None,
        'probe_sw': '6A82',
        'card_state': None,
        'card_ready': False,
    }
    with caplog.at_level('INFO', logger='services.hsm.ceremony_service'):
        _log_custodian_access(3, entry)
        _log_custodian_access(3, entry)
    lines = [r.getMessage() for r in caplog.records if 'sc-hsm provider 3' in r.getMessage()]
    assert len(lines) == 1
    assert 'probe_sw=6A82' in lines[0]
    assert 'access=card' in lines[0]


def test_classify_token_state_for_a_new_scheme():
    from services.hsm.sc_hsm_apdu import classify_token_state

    empty = classify_token_state(0x6A, 0x88, b'', 0x6A, 0x82)
    assert empty['state'] == 'ready' and empty['ready'] is True

    waiting = classify_token_state(0x90, 0x00, bytes((3, 3)), 0x6A, 0x82)
    assert waiting['state'] == 'awaiting_shares' and waiting['ready'] is True

    complete = classify_token_state(0x90, 0x00, bytes((3, 0)), 0x6A, 0x82)
    assert complete['state'] == 'has_dkek' and complete['ready'] is False

    partial = classify_token_state(0x90, 0x00, bytes((3, 1)), 0x6A, 0x82)
    assert partial['state'] == 'dkek_pending' and partial['destructive'] is True

    blank = classify_token_state(0x6A, 0x86, b'', 0x6A, 0x82)
    assert blank['state'] == 'uninitialized'

    leftover = classify_token_state(0x6A, 0x88, b'', 0x90, 0x00)
    assert leftover['state'] == 'has_share' and leftover['ready'] is False

    waiting_with_file = classify_token_state(0x90, 0x00, bytes((3, 3)), 0x90, 0x00)
    assert waiting_with_file['state'] == 'has_share' and waiting_with_file['ready'] is False


def _initialize_tags(apdu: bytes) -> list:
    assert apdu[:4] == bytes((0x80, 0x50, 0x00, 0x00))
    body = apdu[5:5 + apdu[4]]
    tags = []
    index = 0
    while index + 1 < len(body):
        tag = body[index]
        length = body[index + 1]
        tags.append(tag)
        index += 2 + length
    assert index == len(body)
    return tags


def test_card_import_is_one_32_byte_share_for_one_of_two():
    from services.hsm.sc_hsm_apdu import (
        apdu_import_dkek_share,
        generate_dkek_shares,
        reconstruct_dkek,
        shares_to_import,
    )

    shares = generate_dkek_shares(1, 2)
    assert all(len(part) == 33 for part in shares)
    secret = reconstruct_dkek(shares[:1])
    again = reconstruct_dkek(shares[1:])
    assert secret == again
    assert len(secret) == 32
    pieces = shares_to_import(shares, 1)
    assert pieces == [secret]
    apdu = apdu_import_dkek_share(pieces[0])
    assert apdu[4] == 32
    with pytest.raises(ValueError):
        apdu_import_dkek_share(shares[0])


def test_any_two_of_three_shamir_shares_rebuild_the_same_dkek():
    from services.hsm.sc_hsm_apdu import generate_dkek_shares, reconstruct_dkek, shares_to_import

    shares = generate_dkek_shares(2, 3)
    first = reconstruct_dkek(shares[:2])
    second = reconstruct_dkek([shares[0], shares[2]])
    third = reconstruct_dkek(shares[1:])
    assert first == second == third
    left = shares_to_import(shares[:2], 2)
    right = shares_to_import([shares[0], shares[2]], 2)
    assert len(left) == 2 and all(len(part) == 32 for part in left)
    folded = bytes(a ^ b for a, b in zip(left[0], left[1]))
    other = bytes(a ^ b for a, b in zip(right[0], right[1]))
    assert folded == other == first


def test_token_init_uses_the_provider_threshold():
    from services.hsm.ceremony_service import token_init_params

    assert token_init_params({'threshold_n': 1, 'total_m': 2}) == {
        'scheme': 'shares',
        'dkek_shares': 1,
        'key_domains': 1,
    }
    assert token_init_params({'device_scheme': 'none'})['scheme'] == 'none'
    domains = token_init_params({'device_scheme': 'domains', 'key_domains': 4})
    assert domains == {'scheme': 'domains', 'dkek_shares': 1, 'key_domains': 4}


def test_initialize_apdu_rejects_bad_pins_and_keeps_them_out_of_errors():
    from services.hsm.sc_hsm_apdu import apdu_create_dkek_domain, apdu_initialize

    secret_so = '0011223344556677'
    secret_pin = '654321'
    with pytest.raises(ValueError) as bad_so:
        apdu_initialize('57621880', secret_pin, 2)
    assert secret_pin not in str(bad_so.value)
    with pytest.raises(ValueError) as bad_pin:
        apdu_initialize(secret_so, 'short', 2)
    assert secret_so not in str(bad_pin.value)
    with pytest.raises(ValueError) as bad_scheme:
        apdu_initialize(secret_so, secret_pin, scheme='both')
    assert secret_so not in str(bad_scheme.value)
    assert secret_pin not in str(bad_scheme.value)

    shares = apdu_initialize(secret_so, secret_pin, 2, scheme='shares')
    assert _initialize_tags(shares) == [0x80, 0x81, 0x82, 0x91, 0x92]
    assert shares[-1] == 2
    assert 0x97 not in _initialize_tags(shares)

    random_dkek = apdu_initialize(secret_so, secret_pin, scheme='random')
    assert _initialize_tags(random_dkek) == [0x80, 0x81, 0x82, 0x91, 0x92]
    assert random_dkek[-1] == 0

    none = apdu_initialize(secret_so, secret_pin, scheme='none')
    assert _initialize_tags(none) == [0x80, 0x81, 0x82, 0x91]

    domains = apdu_initialize(secret_so, secret_pin, scheme='domains', key_domains=3)
    assert _initialize_tags(domains) == [0x80, 0x81, 0x82, 0x91, 0x97]
    assert domains[-1] == 3
    assert apdu_create_dkek_domain(2) == bytes((0x80, 0x52, 0x01, 0x00, 0x01, 0x02, 0x00))


def _ceremony_provider(auth_client, app, name, uid):
    create = auth_client.post('/api/v2/hsm/providers', json={
        'name': name,
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'prep',
            'threshold_n': 1,
            'total_m': 1,
            'custodians': [{'user_id': uid, 'share_index': 1}],
        },
    })
    assert create.status_code in (200, 201), create.get_json()
    pid = (create.get_json().get('data') or create.get_json())['id']
    begin = auth_client.post(f'/api/v2/hsm/providers/{pid}/ceremony/begin')
    assert begin.status_code == 200, begin.get_json()
    d = begin.get_json().get('data') or begin.get_json()
    return pid, str(d['custodians'][0]['id'])


def test_prepare_token_requires_delete_and_clears_share(auth_client, app, bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    with app.app_context():
        user = User(username='prep-holder', email='prep@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        uid = user.id
    pid, custodian_id = _ceremony_provider(auth_client, app, 'Prep Root', uid)
    connected = call_bridge(
        'connect_fake',
        {'custodian_id': custodian_id},
        sock_path=bridge_sock.sock_path,
    )
    assert connected['ok'] is True

    inspected = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{custodian_id}/inspect',
    )
    assert inspected.status_code == 200, inspected.get_json()
    card = (inspected.get_json().get('data') or inspected.get_json())['card']
    assert card['state'] == 'has_share'
    assert card['ready'] is False
    before = bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()
    assert len(before) == 32

    refused = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{custodian_id}/prepare',
        json={'confirm': 'delete'},
    )
    assert refused.status_code == 400, refused.get_json()
    assert 'DELETE' in (refused.get_json().get('message') or '')
    still = bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()
    assert bytes(still) == bytes(before)

    prepared = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{custodian_id}/prepare',
        json={'confirm': 'DELETE', 'so_pin': 'not-logged', 'user_pin': 'not-logged'},
    )
    assert prepared.status_code == 200, prepared.get_json()
    body = prepared.get_json()
    assert 'not-logged' not in json.dumps(body)
    ready = (body.get('data') or body)['card']
    assert ready['ready'] is True
    assert ready['has_share'] is False
    assert len(bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()) == 0

    again = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{custodian_id}/prepare',
        json={},
    )
    assert again.status_code == 200, again.get_json()
    assert (again.get_json().get('data') or again.get_json())['already_ready'] is True


def test_prepare_refuses_while_root_key_is_assembled(auth_client, app, bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    with app.app_context():
        user = User(username='prep-assembled', email='prepa@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        uid = user.id
    pid, custodian_id = _ceremony_provider(auth_client, app, 'Assembled Prep', uid)
    assert call_bridge(
        'connect_fake',
        {'custodian_id': custodian_id},
        sock_path=bridge_sock.sock_path,
    )['ok']
    slot = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/assembly-slot',
        json={'share_index': 1},
    )
    assert slot.status_code == 200, slot.get_json()
    refused = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/tokens/{custodian_id}/prepare',
        json={'confirm': 'DELETE'},
    )
    assert refused.status_code == 400
    assert 'assembled' in (refused.get_json().get('message') or '').lower()
    assert len(bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()) == 32


def test_roll_root_key_follows_share_index_not_token_map(bridge_sock):
    """Connect tokens are inserted out of share_index order. Roll still writes 1 then 2."""
    sock = bridge_sock.sock_path
    begin = call_bridge('begin_ceremony', {
        'provider_id': 1,
        'threshold_n': 1,
        'total_m': 2,
        'use_fake': True,
        'custodians': [
            {'custodian_id': '20', 'connect_token': 'zzz-share-2', 'share_index': 2},
            {'custodian_id': '10', 'connect_token': 'aaa-share-1', 'share_index': 1},
        ],
    }, sock_path=sock)
    assert begin['ok'] is True, begin
    for cid in ('10', '20'):
        assert call_bridge('connect_fake', {'custodian_id': cid}, sock_path=sock)['ok']

    created = call_bridge('create_root_key', {
        'confirm': 'DELETE',
        'assembly_custodian_id': '10',
    }, sock_path=sock)
    assert created['ok'] is True, created

    order = []
    original = bridge_sock._write_share

    def _spy(cid, share):
        order.append(str(cid))
        return original(cid, share)

    bridge_sock._write_share = _spy
    rolled = call_bridge('roll_root_key', {}, sock_path=sock)
    assert rolled['ok'] is True, rolled
    assert order == ['10', '20']


def test_create_root_key_writes_the_first_share(auth_client, app, bridge_sock, monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_SOCK', bridge_sock.sock_path)
    with app.app_context():
        user = User(username='create-holder', email='create@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        uid = user.id
    pid, custodian_id = _ceremony_provider(auth_client, app, 'Create Root', uid)
    assert call_bridge(
        'connect_fake',
        {'custodian_id': custodian_id},
        sock_path=bridge_sock.sock_path,
    )['ok']
    before = bytes(bridge_sock.ceremony.custodian_cards[custodian_id].copy_share())
    assert len(before) == 32

    refused = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/create-key',
        json={'share_index': 1, 'confirm': 'no'},
    )
    assert refused.status_code == 400
    assert 'DELETE' in (refused.get_json().get('message') or '')
    assert bytes(bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()) == before
    assert bridge_sock.ceremony.key_assembled is False

    created = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/create-key',
        json={'share_index': 1, 'confirm': 'DELETE'},
    )
    assert created.status_code == 200, created.get_json()
    data = created.get_json().get('data') or created.get_json()
    assert data['key_assembled'] is True
    assert data['assembly_slot'] == 1
    share = bridge_sock.ceremony.custodian_cards[custodian_id].copy_share()
    assert len(share) == 32
    assert bytes(share) != before
    with app.app_context():
        provider = db.session.get(HsmProvider, pid)
        assert provider.get_config().get('wrapped_root')
        assert provider.get_config().get('public_key_pem')
        signing = [key for key in provider.keys if key.purpose == 'signing']
        assert len(signing) == 1
        assert signing[0].public_key_pem == provider.get_config().get('public_key_pem')

    again = auth_client.post(
        f'/api/v2/hsm/providers/{pid}/ceremony/create-key',
        json={'share_index': 1, 'confirm': 'DELETE'},
    )
    assert again.status_code == 400
    assert 'already assembled' in (again.get_json().get('message') or '').lower()


def test_missing_assembly_card_uses_present_custodian_pin(bridge_sock, monkeypatch, caplog):
    """The last assembly card can be absent when the threshold is still met.

    The user PIN is the one entered for a card that is present. A PIN sitting
    in the server environment is ignored, and the ceremony PIN is not written
    into status, the snapshot, or the log.
    """
    import base64

    decoy = 'host-only-pin-9f3c'
    card_pin = 'card-three-pin-4a'
    monkeypatch.setenv('SC_HSM_USER_PIN', decoy)
    sock = bridge_sock.sock_path
    begin = call_bridge('begin_ceremony', {
        'provider_id': 2,
        'threshold_n': 2,
        'total_m': 4,
        'use_fake': True,
        'assembly_custodian_id': '1',
        'wrapped_root_b64': base64.b64encode(b'\xAA' * 64).decode(),
        'custodians': [
            {'custodian_id': '1', 'connect_token': 'tok-1', 'share_index': 1},
            {'custodian_id': '2', 'connect_token': 'tok-2', 'share_index': 2},
            {'custodian_id': '3', 'connect_token': 'tok-3', 'share_index': 3},
            {'custodian_id': '4', 'connect_token': 'tok-4', 'share_index': 4},
        ],
    }, sock_path=sock)
    assert begin['ok'] is True
    for cid in ('2', '3', '4'):
        assert call_bridge('connect_fake', {'custodian_id': cid}, sock_path=sock)['ok']

    with pytest.raises(RuntimeError, match='assembly device'):
        bridge_sock._pkcs11_login_pin()

    caplog.set_level('INFO')
    assembled = call_bridge('set_assembly', {
        'assembly_custodian_id': '3',
        'user_pin': card_pin,
    }, sock_path=sock)
    assert assembled['ok'] is True, assembled
    ceremony = assembled['ceremony']
    assert ceremony['assembly_custodian_id'] == '3'
    assert ceremony['key_assembled'] is True
    assert bridge_sock._pkcs11_login_pin() == card_pin
    assert bridge_sock._pkcs11_login_pin() != decoy

    visible = json.dumps(ceremony) + json.dumps(call_bridge('status', sock_path=sock))
    assert card_pin not in visible
    assert decoy not in visible
    assert card_pin not in caplog.text
    assert decoy not in caplog.text

    ended = call_bridge('end_ceremony', {'force': True}, sock_path=sock)
    assert ended['ok'] is True
    assert bridge_sock.ceremony.user_pin() == ''
    assert card_pin not in json.dumps(ended)


def test_root_key_generate_and_wrap_use_separate_logins(bridge_sock, monkeypatch):
    """Key generation logs out before a second login wraps the key.

    The wrap command is sent only while the second login is open. A status
    probe does not touch the assembly card during either login.
    """
    import sys
    import types

    from cryptography.hazmat.primitives.asymmetric import rsa

    card_pin = 'assembly-pin-17'
    events = []
    sessions = []
    private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    numbers = private.public_key().public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')

    sock = bridge_sock.sock_path
    begin = call_bridge('begin_ceremony', {
        'provider_id': 2,
        'threshold_n': 1,
        'total_m': 1,
        'use_fake': True,
        'assembly_custodian_id': '9',
        'custodians': [
            {'custodian_id': '9', 'connect_token': 'tok-9', 'share_index': 1},
        ],
    }, sock_path=sock)
    assert begin['ok'] is True
    assert call_bridge('connect_fake', {'custodian_id': '9'}, sock_path=sock)['ok']
    probed_at = bridge_sock.sessions.get_by_custodian('9').last_probe_at
    bridge_sock.ceremony.remember_user_pin(card_pin)

    class Attribute:
        MODULUS = object()
        PUBLIC_EXPONENT = object()
        VERIFY = object()
        SIGN = object()
        ID = object()

    class KeyType:
        RSA = 'rsa'

    class _Pub:
        def __getitem__(self, key):
            if key is Attribute.MODULUS:
                return modulus
            if key is Attribute.PUBLIC_EXPONENT:
                return exponent
            raise KeyError(key)

    class _Session:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            events.append('open')
            sessions.append(self)
            return self

        def __exit__(self, exc_type, exc, tb):
            self.closed = True
            events.append('close')
            return False

        def generate_keypair(self, *args, **kwargs):
            events.append('generate')
            assert kwargs['private_template'][Attribute.ID] == bytes((1,))
            bridge_sock._probe_custodian('9', force=True)
            assert bridge_sock.sessions.get_by_custodian('9').last_probe_at == probed_at
            return _Pub(), object()

    class _Token:
        def open(self, *, rw=False, user_pin=None, **kwargs):
            assert rw is True
            assert user_pin == card_pin
            return _Session()

    class _Slot:
        def get_token(self):
            return _Token()

    class _Lib:
        def get_slots(self):
            return [_Slot()]

    module = types.ModuleType('pkcs11')
    module.Attribute = Attribute
    module.KeyType = KeyType
    module.lib = lambda path: _Lib()
    previous = sys.modules.get('pkcs11')
    sys.modules['pkcs11'] = module

    def transmit(apdu):
        events.append('wrap')
        assert sessions[0].closed is True
        assert sessions[1].closed is False
        assert apdu == bytes((0x80, 0x72, 0x01, 0x92, 0x00, 0x00, 0x00))
        return b'\x22' * 16 + b'\x90\x00'

    monkeypatch.setattr(bridge_sock, 'transmit_assembly', transmit)
    try:
        public_pem, wrapped = bridge_sock._pkcs11_roll_key()
    finally:
        if previous is None:
            sys.modules.pop('pkcs11', None)
        else:
            sys.modules['pkcs11'] = previous

    assert events == ['open', 'generate', 'close', 'open', 'wrap', 'close']
    assert public_pem.startswith('-----BEGIN PUBLIC KEY-----')
    assert wrapped == b'\x22' * 16
    assert bridge_sock._assembly_busy is False


def test_share_write_verifies_assembly_pin_after_logout(bridge_sock):
    """A roll after key generation finds the assembly card logged out."""

    class Session:
        def __init__(self):
            self.connected = True
            self.hsm_selected = True
            self.apdus = []

        def queue_transmit(self, apdu, timeout=30.0):
            self.apdus.append(bytes(apdu))
            writes = [item for item in self.apdus if item[1] == 0xD7]
            if apdu[1] == 0xD7 and len(writes) == 1:
                return bytes((0x69, 0x82))
            return bytes((0x90, 0x00))

    session = Session()
    bridge_sock.ceremony.use_fake = False
    bridge_sock.ceremony.assembly_custodian_id = '9'
    bridge_sock.ceremony.remember_user_pin('654321')
    bridge_sock.sessions.get_by_custodian = lambda cid: session if str(cid) == '9' else None
    bridge_sock._write_share('9', b'\x11' * 32)
    assert [apdu[1] for apdu in session.apdus] == [0xD7, 0x20, 0xD7]


def test_reset_removes_existing_key_before_clearing_dkek(bridge_sock):
    """A completed device key makes CLEAR KEK and IMPORT return SW=6985.

    The root key file is deleted, then the domain is cleared, and only then
    can a new share be imported.
    """
    seen = []

    def transmit(apdu):
        seen.append(bytes(apdu))
        if apdu[0] == 0x80 and apdu[1] == 0x52 and apdu[2] == 0x04:
            if sum(1 for item in seen if item[1] == 0x52 and item[2] == 0x04) == 1:
                return bytes((0x69, 0x85))
            return bytes((0x90, 0x00))
        if apdu[0] == 0x80 and apdu[1] == 0x52 and apdu[2] == 0x00 and len(apdu) == 5:
            # Configured 1, outstanding 0: the DKEK is already complete.
            return bytes((0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00))
        if apdu[0] == 0x00 and apdu[1] == 0xE4:
            return bytes((0x90, 0x00))
        return bytes((0x6A, 0x86))

    bridge_sock.transmit_assembly = transmit
    bridge_sock._reset_assembly_domain(1)
    assert [apdu[1] for apdu in seen] == [0x52, 0x52, 0xE4, 0x52]
    assert seen[2][5:7] == b'\xCC\x01'


def test_reset_keeps_an_empty_domain_when_clear_returns_6985(bridge_sock):
    """CLEAR KEK on a domain that is still waiting for shares can return 6985."""
    seen = []

    def transmit(apdu):
        seen.append(bytes(apdu))
        if apdu[0] == 0x80 and apdu[1] == 0x52 and apdu[2] == 0x04:
            return bytes((0x69, 0x85))
        if apdu[0] == 0x80 and apdu[1] == 0x52 and apdu[2] == 0x00 and len(apdu) == 5:
            return bytes((0x01, 0x01, 0x00, 0x00, 0x00, 0x90, 0x00))
        return bytes((0x6A, 0x86))

    bridge_sock.transmit_assembly = transmit
    bridge_sock._reset_assembly_domain(1)
    assert [apdu[1] for apdu in seen] == [0x52, 0x52]
