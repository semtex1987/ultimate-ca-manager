"""End-to-end public key authentication ceremony through the HSM API.

The bridge runs in fake mode with a software root HSM that checks keyholder
signatures. Keyholders use their own logins and their own EC keys; no secret
passes through UCM.
"""
from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from models import db
from models.audit_log import AuditLog
from models.hsm import HsmProvider
from models.user import User
from services.hsm import HsmService
from services.hsm import sc_hsm_pka as pka
from services.hsm.ram_bridge import RamBridge
from services.hsm.sc_hsm_cloud_provider import call_bridge


@pytest.fixture
def pka_bridge(monkeypatch):
    monkeypatch.setenv('RAM_BRIDGE_FAKE', '1')
    monkeypatch.setenv('RAM_BRIDGE_ALLOW_PLAINTEXT', '1')
    monkeypatch.delenv('UCM_ALLOW_LEGACY_SHARE_CEREMONY', raising=False)
    sock = f'/tmp/ucm-ram-pka-{os.getpid()}.sock'
    if os.path.exists(sock):
        os.unlink(sock)
    bridge = RamBridge(ram_port=0, sock_path=sock, bind_host='127.0.0.1', vpcd_host='127.0.0.1', vpcd_port=1)
    bridge.start()
    yield bridge
    bridge.stop()
    if os.path.exists(sock):
        os.unlink(sock)


def _data(response):
    body = response.get_json()
    return body.get('data') if isinstance(body, dict) and 'data' in body else body


class Keyholder:
    def __init__(self, app, username, index):
        self.username = username
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.chr = f'UTKH{index:07d}'
        self.export = pka.build_fake_pka_export(self.private, self.chr, device_chr=f'DECC{index:010d}')
        self.client = app.test_client()
        login = self.client.post('/api/v2/auth/login', json={'username': username, 'password': 'TestPass123!'})
        assert login.status_code == 200, login.get_json()

    def sign(self, message):
        return base64.b64encode(pka.sign_plain(self.private, message)).decode()


def _setup(auth_client, app, bridge, *, n=2, m=3, name='pka-root'):
    with app.app_context():
        ids = []
        for index in range(m):
            user = User(username=f'{name}-kh{index}', email=f'{name}-kh{index}@example.com', role='operator')
            user.set_password('TestPass123!')
            db.session.add(user)
            db.session.flush()
            ids.append(user.id)
        db.session.commit()
    created = auth_client.post('/api/v2/hsm/providers', json={
        'name': name,
        'type': 'sc-hsm-cloud',
        'config': {
            'device_scheme': 'pka',
            'threshold_n': n,
            'total_m': m,
            'socket_path': bridge.sock_path,
            # Server-managed: an operator cannot pre-seed these.
            'pinned_device_chr': 'DEATTACKER0001',
            'transcripts': [{'ceremony_id': 'forged'}],
            'custodians': [{'user_id': ids[i], 'share_index': i + 1} for i in range(m)],
        },
    })
    assert created.status_code in (200, 201), created.get_json()
    provider_id = _data(created)['id']
    holders = [Keyholder(app, f'{name}-kh{i}', i + 1) for i in range(m)]
    return provider_id, holders


def _enroll_all(provider_id, holders):
    for holder in holders:
        r = holder.client.post(
            f'/api/v2/hsm/providers/{provider_id}/ceremony/keyholder/enroll',
            json={'export_b64': base64.b64encode(holder.export).decode()},
        )
        assert r.status_code == 200, r.get_json()
        assert _data(r)['fingerprint'] == pka.parse_pka_export(holder.export).fingerprint


def _begin(auth_client, provider_id, operations, budget=5):
    return auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/begin', json={
        'operations': operations, 'max_signatures': budget, 'ttl_hours': 2,
    })


def _approve_and_authenticate(provider_id, holder):
    base = f'/api/v2/hsm/providers/{provider_id}/ceremony/keyholder'
    context = _data(holder.client.get(base))
    digest = bytes.fromhex(context['manifest_sha256'])
    # The agent recomputes everything it shows from what it received.
    assert pka.manifest_hash(context['manifest']) == digest
    assert context['sas'] == pka.compute_sas(
        context['manifest']['ceremony_id'], digest, context['device_chr'], context['tls_spki_sha256'],
    )
    r = holder.client.post(f'{base}/approve', json={'signature_b64': holder.sign(pka.approval_message(digest))})
    assert r.status_code == 200, r.get_json()
    r = holder.client.post(f'{base}/challenge')
    assert r.status_code == 200, r.get_json()
    issued = _data(r)
    message = pka.auth_message(
        base64.b64decode(issued['device_id_b64']), base64.b64decode(issued['challenge_b64']),
    )
    r = holder.client.post(f'{base}/authenticate', json={'signature_b64': holder.sign(message)})
    assert r.status_code == 200, r.get_json()
    return _data(r)


def test_full_remote_ceremony_needs_quorum_and_leaves_a_verifiable_transcript(auth_client, app, pka_bridge):
    provider_id, holders = _setup(auth_client, app, pka_bridge)
    with app.app_context():
        cfg = db.session.get(HsmProvider, provider_id).get_config()
        assert 'pinned_device_chr' not in cfg
        assert 'transcripts' not in cfg

    # A window cannot open before every keyholder has enrolled.
    early = _begin(auth_client, provider_id, [{'type': 'generate_root_key', 'label': 'Generate root'}])
    assert early.status_code == 400
    _enroll_all(provider_id, holders)
    # The same key cannot be enrolled twice.
    dup = holders[1].client.post(
        f'/api/v2/hsm/providers/{provider_id}/ceremony/keyholder/enroll',
        json={'export_b64': base64.b64encode(holders[0].export).decode()},
    )
    assert dup.status_code == 400

    assert _begin(auth_client, provider_id, []).status_code == 400
    begun = _begin(auth_client, provider_id, [
        {'type': 'generate_root_key', 'label': 'Generate root key'},
        {'type': 'publish_crl', 'label': 'First CRL'},
    ], budget=3)
    assert begun.status_code == 200, begun.get_json()

    # The root HSM attaches at the site.
    attached = call_bridge('connect_fake', {'custodian_id': 'root'}, sock_path=pka_bridge.sock_path)
    assert attached['ok'] is True, attached
    detail = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))
    device_chr = detail['pka']['live']['device_chr']
    assert device_chr and detail['pka']['root_ram_client_url']
    assert all('ram_client_url' not in c for c in detail['custodians'])

    base = f'/api/v2/hsm/providers/{provider_id}/ceremony'
    # Keyholders cannot authenticate against an unpinned device.
    holder = holders[0]
    digest = bytes.fromhex(_data(holder.client.get(f'{base}/keyholder'))['manifest_sha256'])
    holder.client.post(f'{base}/keyholder/approve', json={'signature_b64': holder.sign(pka.approval_message(digest))})
    refused = holder.client.post(f'{base}/keyholder/challenge')
    assert refused.status_code == 400 and 'pin' in refused.get_json().get('message', refused.get_json().get('error', '')).lower()

    assert auth_client.post(f'{base}/pin-device', json={'device_chr': 'DEWRONG000001'}).status_code == 400
    pinned = auth_client.post(f'{base}/pin-device', json={'device_chr': device_chr})
    assert pinned.status_code == 200, pinned.get_json()

    # Approval must be signed by the keyholder's own key.
    forged = holders[1].client.post(
        f'{base}/keyholder/approve',
        json={'signature_b64': holders[0].sign(pka.approval_message(digest))},
    )
    assert forged.status_code == 400
    # A challenge needs an approval first.
    assert holders[2].client.post(f'{base}/keyholder/challenge').status_code == 400

    first = _approve_and_authenticate(provider_id, holders[0])
    assert first == {'authenticated': 1, 'required': 2, 'unlocked': False}
    generate = auth_client.post(f'{base}/generate-root-key', json={'confirm': 'GENERATE'})
    assert generate.status_code == 400

    second = _approve_and_authenticate(provider_id, holders[2])
    assert second['unlocked'] is True
    assert auth_client.post(f'{base}/generate-root-key', json={'confirm': 'yes'}).status_code == 400
    generate = auth_client.post(f'{base}/generate-root-key', json={'confirm': 'GENERATE'})
    assert generate.status_code == 200, generate.get_json()
    public_pem = _data(generate)['public_key_pem']
    assert 'PRIVATE' not in public_pem
    assert auth_client.post(f'{base}/generate-root-key', json={'confirm': 'GENERATE'}).status_code == 400

    # Sign through the provider, as CRL and certificate code does.
    public_key = serialization.load_pem_public_key(public_pem.encode())
    with app.app_context():
        provider = db.session.get(HsmProvider, provider_id)
        instance = HsmService._get_provider_instance(provider)
        assert instance.signing_window_open() is True
        for index in range(3):
            data = f'tbs-{index}'.encode()
            signature = instance.sign('1', data, hash_algorithm='sha256')
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        with pytest.raises(Exception, match='budget'):
            instance.sign('1', b'one too many', hash_algorithm='sha256')

    # Pinned device and threshold cannot be edited away while bound.
    edit = auth_client.put(f'/api/v2/hsm/providers/{provider_id}', json={
        'config': {'device_scheme': 'pka', 'threshold_n': 1, 'total_m': 3},
    })
    assert edit.status_code == 400

    # Lock (reset, read back zero) and close.
    locked = auth_client.post(f'{base}/wipe')
    assert locked.status_code == 200, locked.get_json()
    with app.app_context():
        instance = HsmService._get_provider_instance(db.session.get(HsmProvider, provider_id))
        assert instance.signing_window_open() is False
    ended = auth_client.post(f'{base}/end')
    assert ended.status_code == 200, ended.get_json()

    transcript = _data(holders[0].client.get(f'{base}/transcript'))
    assert transcript['sealed'] is True
    assert pka.verify_transcript(transcript['entries']) == transcript['final_hash']
    events = [entry['event'] for entry in transcript['entries']]
    for expected in ('opened', 'device', 'device_pinned', 'manifest_approved', 'authenticated',
                     'unlocked', 'key_generated', 'signed', 'locked', 'sealed'):
        assert expected in events, events
    assert events.count('signed') == 3
    assert 'authentication_rejected' not in events

    final = bytes.fromhex(transcript['final_hash'])
    bad = holders[1].client.post(f'{base}/transcript/countersign', json={
        'ceremony_id': transcript['ceremony_id'],
        'signature_b64': holders[0].sign(pka.transcript_message(final)),
    })
    assert bad.status_code == 400
    good = holders[1].client.post(f'{base}/transcript/countersign', json={
        'ceremony_id': transcript['ceremony_id'],
        'signature_b64': holders[1].sign(pka.transcript_message(final)),
    })
    assert good.status_code == 200, good.get_json()

    # With the window closed, the registered threshold and roster stay fixed,
    # and server-managed fields ignore an operator's values.
    rebind = auth_client.put(f'/api/v2/hsm/providers/{provider_id}', json={
        'config': {'device_scheme': 'pka', 'threshold_n': 1, 'total_m': 3, 'socket_path': pka_bridge.sock_path},
    })
    assert rebind.status_code == 400
    assert 'fixed' in str(rebind.get_json())
    same = auth_client.put(f'/api/v2/hsm/providers/{provider_id}', json={
        'config': {
            'device_scheme': 'pka', 'threshold_n': 2, 'total_m': 3,
            'socket_path': pka_bridge.sock_path,
            'pinned_device_chr': 'DEATTACKER0001', 'transcripts': [],
        },
    })
    assert same.status_code == 200, same.get_json()

    with app.app_context():
        provider = db.session.get(HsmProvider, provider_id)
        cfg = provider.get_config()
        assert cfg['pinned_device_chr'] == device_chr
        assert cfg['keyholders_locked'] is True
        assert cfg['public_key_pem'] == public_pem
        assert cfg['transcripts'][-1]['final_hash'] == transcript['final_hash']
        assert 'ceremony_manifest' not in cfg
        actions = {row.action for row in AuditLog.query.filter(AuditLog.resource_id == str(provider_id))}
        assert {'hsm_keyholder_enroll', 'hsm_keyholder_approve', 'hsm_keyholder_authenticate',
                'hsm_root_device_pinned', 'hsm_ceremony_create_key', 'hsm_ceremony_transcript'} <= actions


def test_wrong_device_and_replayed_signature_are_refused(auth_client, app, pka_bridge):
    provider_id, holders = _setup(auth_client, app, pka_bridge, n=1, m=2, name='pka-replay')
    _enroll_all(provider_id, holders)
    base = f'/api/v2/hsm/providers/{provider_id}/ceremony'
    assert _begin(auth_client, provider_id, [{'type': 'publish_crl', 'label': 'CRL'}]).status_code == 200
    call_bridge('connect_fake', {'custodian_id': 'root'}, sock_path=pka_bridge.sock_path)
    device_chr = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))['pka']['live']['device_chr']
    assert auth_client.post(f'{base}/pin-device', json={'device_chr': device_chr}).status_code == 200

    holder = holders[0]
    context = _data(holder.client.get(f'{base}/keyholder'))
    digest = bytes.fromhex(context['manifest_sha256'])
    holder.client.post(f'{base}/keyholder/approve', json={'signature_b64': holder.sign(pka.approval_message(digest))})
    issued = _data(holder.client.post(f'{base}/keyholder/challenge'))
    # Signing the wrong device id is caught before the card sees it.
    wrong = pka.auth_message(b'DECC9999999999', base64.b64decode(issued['challenge_b64']))
    r = holder.client.post(f'{base}/keyholder/authenticate', json={'signature_b64': holder.sign(wrong)})
    assert r.status_code == 400
    # The challenge was consumed; replaying a valid signature for it fails too.
    message = pka.auth_message(base64.b64decode(issued['device_id_b64']), base64.b64decode(issued['challenge_b64']))
    r = holder.client.post(f'{base}/keyholder/authenticate', json={'signature_b64': holder.sign(message)})
    assert r.status_code == 400

    # A different device attached later is refused even though it is pinned-format.
    pka_bridge.pka.device_chr = 'DECC0000000777'
    r = holder.client.post(f'{base}/keyholder/challenge')
    assert r.status_code == 400 and 'not the pinned' in str(r.get_json())

    # Nobody reached the quorum, so the window closes without a lock round trip.
    pka_bridge._pka_fake_connected = False
    assert auth_client.post(f'{base}/wipe').status_code == 200
    assert auth_client.post(f'{base}/end').status_code == 200


def test_signing_window_belongs_to_one_provider(auth_client, app, pka_bridge):
    provider_id, holders = _setup(auth_client, app, pka_bridge, n=1, m=1, name='pka-owner')
    _enroll_all(provider_id, holders)
    other = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'pka-other', 'type': 'sc-hsm-cloud',
        'config': {'device_scheme': 'pka', 'threshold_n': 1, 'total_m': 1, 'socket_path': pka_bridge.sock_path},
    })
    other_id = _data(other)['id']
    base = f'/api/v2/hsm/providers/{provider_id}/ceremony'
    _begin(auth_client, provider_id, [{'type': 'generate_root_key', 'label': 'gen'}])
    call_bridge('connect_fake', {'custodian_id': 'root'}, sock_path=pka_bridge.sock_path)
    device_chr = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))['pka']['live']['device_chr']
    auth_client.post(f'{base}/pin-device', json={'device_chr': device_chr})
    assert _approve_and_authenticate(provider_id, holders[0])['unlocked'] is True
    assert auth_client.post(f'{base}/generate-root-key', json={'confirm': 'GENERATE'}).status_code == 200
    with app.app_context():
        mine = HsmService._get_provider_instance(db.session.get(HsmProvider, provider_id))
        theirs = HsmService._get_provider_instance(db.session.get(HsmProvider, other_id))
        assert mine.signing_window_open() is True
        assert theirs.signing_window_open() is False
    refused = call_bridge('sign', {
        'data_b64': base64.b64encode(b'x').decode(), 'provider_id': other_id,
    }, sock_path=pka_bridge.sock_path)
    assert refused['ok'] is False and 'different provider' in refused['error']


def test_legacy_share_ceremony_is_refused_without_opt_in(auth_client, app, pka_bridge):
    with app.app_context():
        user = User(username='legacy-kh', email='legacy-kh@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        uid = user.id
    created = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'legacy-shares', 'type': 'sc-hsm-cloud',
        'config': {'device_scheme': 'shares', 'threshold_n': 1, 'total_m': 1,
                   'socket_path': pka_bridge.sock_path,
                   'custodians': [{'user_id': uid, 'share_index': 1}]},
    })
    provider_id = _data(created)['id']
    r = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/begin')
    assert r.status_code == 400
    assert 'UCM_ALLOW_LEGACY_SHARE_CEREMONY' in str(r.get_json())
    direct = call_bridge('begin_ceremony', {
        'device_scheme': 'shares', 'threshold_n': 1, 'total_m': 1,
        'custodians': [{'custodian_id': '1', 'connect_token': 't', 'share_index': 1}],
    }, sock_path=pka_bridge.sock_path)
    assert direct['ok'] is False


def test_bridge_refuses_plaintext_without_opt_in(monkeypatch):
    monkeypatch.delenv('RAM_BRIDGE_ALLOW_PLAINTEXT', raising=False)
    monkeypatch.setenv('HTTPS_CERT_PATH', '/nonexistent/cert.pem')
    monkeypatch.setenv('HTTPS_KEY_PATH', '/nonexistent/key.pem')
    bridge = RamBridge(ram_port=0, sock_path=f'/tmp/ucm-ram-tls-{os.getpid()}.sock',
                       bind_host='127.0.0.1', vpcd_host='127.0.0.1', vpcd_port=1)
    with pytest.raises(RuntimeError, match='TLS'):
        bridge._start_http()


def test_fake_mode_cannot_be_requested_over_the_control_socket(monkeypatch):
    monkeypatch.delenv('RAM_BRIDGE_FAKE', raising=False)
    monkeypatch.setenv('UCM_ALLOW_LEGACY_SHARE_CEREMONY', '1')
    bridge = RamBridge(ram_port=0, sock_path=f'/tmp/ucm-ram-fake-{os.getpid()}.sock',
                       bind_host='127.0.0.1', vpcd_host='127.0.0.1', vpcd_port=1, allow_plaintext=True)
    result = bridge.handle_control({'method': 'begin_ceremony', 'params': {
        'use_fake': True, 'threshold_n': 1, 'total_m': 1,
        'custodians': [{'custodian_id': '1', 'connect_token': 'tok', 'share_index': 1}],
    }})
    assert result['ok'] is True
    assert bridge.ceremony.use_fake is False
    assert bridge.ceremony.fake is None
