"""End-to-end SmartCard-HSM signing window.

The bridge runs in fake mode (no pcscd, no token). Share bytes are created
inside the bridge and must never land in the database, an API response, or
an audit row. Operator actions use the assembled key. Protocol paths keep
seeing an offline CA.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from models import db
from models.audit_log import AuditLog
from models.ca import CA
from models.hsm import HsmCustodian, HsmKey, HsmProvider
from models.user import User
from services.hsm.base_provider import HsmOperationError
from services.hsm.ram_bridge import RamBridge
from services.hsm.sc_hsm_apdu import generate_dkek_shares
from services.hsm.sc_hsm_cloud_provider import ScHsmCloudProvider, call_bridge


@pytest.fixture
def bridge_sock():
    sock = f'/tmp/ucm-ram-e2e-{os.getpid()}.sock'
    if os.path.exists(sock):
        os.unlink(sock)
    bridge = RamBridge(
        ram_port=0,
        sock_path=sock,
        bind_host='127.0.0.1',
        vpcd_host='127.0.0.1',
        vpcd_port=1,
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


def _xor_combine(shares):
    acc = bytearray(shares[0])
    for share in shares[1:]:
        for i, byte in enumerate(share):
            acc[i] ^= byte
    return bytes(acc)


def test_n_of_n_shares_are_an_xor_split():
    shares = generate_dkek_shares(4, 4)
    assert len(shares) == 4
    assert all(len(share) == 32 for share in shares)
    # Any three shares do not reveal the secret: dropping one changes the XOR.
    full = _xor_combine(shares)
    partial = _xor_combine(shares[:3])
    assert partial != full


def test_three_of_four_does_not_assemble_until_the_fourth_connects(bridge_sock):
    sock = bridge_sock.sock_path
    begin = call_bridge('begin_ceremony', {
        'provider_id': 1,
        'threshold_n': 4,
        'total_m': 4,
        'use_fake': True,
        'wrapped_root_b64': base64.b64encode(b'\x22' * 32).decode(),
        'custodians': [
            {'custodian_id': str(i), 'connect_token': f'tok-{i}', 'share_index': i}
            for i in range(1, 5)
        ],
    }, sock_path=sock)
    assert begin['ok'] is True

    for i in range(1, 4):
        assert call_bridge('connect_fake', {'custodian_id': str(i)}, sock_path=sock)['ok']

    early = call_bridge('set_assembly', {'assembly_custodian_id': '1'}, sock_path=sock)
    assert early['ok'] is False
    assert 'need 4' in early['error']
    assert bridge_sock.ceremony.fake.shares == []
    assert bridge_sock.ceremony.key_assembled is False

    assert call_bridge('connect_fake', {'custodian_id': '4'}, sock_path=sock)['ok']
    built = call_bridge('set_assembly', {'assembly_custodian_id': '1'}, sock_path=sock)
    assert built['ok'] is True, built
    assert built['ceremony']['key_assembled'] is True
    assert 'share' not in built
    assert bridge_sock.ceremony.fake.list_key_ids() == [1]
    # Response must not echo share material.
    blob = str(built)
    for card in bridge_sock.ceremony.custodian_cards.values():
        raw = bytes(card.copy_share())
        assert raw.hex() not in blob
        assert base64.b64encode(raw).decode() not in blob


def test_begin_and_wipe_fail_closed_when_bridge_is_down(app):
    from services.hsm.ceremony_service import begin_ceremony, wipe_assembly

    with app.app_context():
        user = User(username='bridge-down', email='bridge-down@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        provider = HsmProvider(name='Bridge Down', type='sc-hsm-cloud', config='{}', status='offline')
        provider.set_config({
            'token_label': 'down',
            'threshold_n': 1,
            'total_m': 1,
            'socket_path': '/tmp/ucm-ram-missing-bridge.sock',
        })
        db.session.add(provider)
        db.session.flush()
        from services.hsm.hsm_service import HsmService
        HsmService.sync_custodians(provider, [{'user_id': user.id, 'share_index': 1}])
        db.session.commit()
        with pytest.raises(Exception):
            begin_ceremony(provider)
        db.session.refresh(provider)
        assert provider.get_config().get('ceremony_active') is not True
        with pytest.raises(HsmOperationError, match='unavailable'):
            wipe_assembly(provider)
        db.session.refresh(provider)
        assert provider.get_config().get('wipe_confirmed') is not True


def _provider(auth_client, app, bridge, *, n, m, name):
    with app.app_context():
        users = []
        for index in range(m):
            user = User(
                username=f'{name}-u{index}',
                email=f'{name}-u{index}@example.com',
                role='operator',
            )
            user.set_password('TestPass123!')
            db.session.add(user)
            users.append(user)
        db.session.commit()
        user_ids = [user.id for user in users]
    created = auth_client.post('/api/v2/hsm/providers', json={
        'name': name,
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': name,
            'threshold_n': n,
            'total_m': m,
            'socket_path': bridge.sock_path,
            'wrapped_root': base64.b64encode(os.urandom(32)).decode(),
            'custodians': [
                {'user_id': user_ids[index], 'share_index': index + 1}
                for index in range(m)
            ],
        },
    })
    assert created.status_code in (200, 201), created.get_json()
    return (created.get_json().get('data') or created.get_json())['id']


def _begin_and_assemble(auth_client, app, bridge, provider_id, assembly_share=1):
    begun = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/begin')
    assert begun.status_code == 200, begun.get_json()
    with app.app_context():
        rows = HsmCustodian.query.filter_by(provider_id=provider_id).all()
        ids = [str(row.id) for row in rows]
    for custodian_id in ids:
        connected = call_bridge(
            'connect_fake',
            {'custodian_id': custodian_id},
            sock_path=bridge.sock_path,
        )
        assert connected['ok'] is True, connected
    slotted = auth_client.post(
        f'/api/v2/hsm/providers/{provider_id}/ceremony/assembly-slot',
        json={'share_index': assembly_share},
    )
    assert slotted.status_code == 200, slotted.get_json()
    body = slotted.get_json().get('data') or slotted.get_json()
    assert body['key_assembled'] is True
    return body


def _bind_root(app, bridge, provider_id, common_name):
    status = call_bridge('status', sock_path=bridge.sock_path)
    public_pem = status['ceremony']['public_key_pem']
    assert 'PRIVATE' not in public_pem
    public_key = serialization.load_pem_public_key(public_pem.encode())
    now = datetime.now(timezone.utc)
    # The certificate is signed by the assembled key once the HsmKey row exists.
    with app.app_context():
        hsm_key = HsmKey(
            provider_id=provider_id,
            key_identifier='1',
            label='root',
            algorithm='RSA-2048',
            key_type='asymmetric',
            purpose='signing',
            public_key_pem=public_pem,
            is_extractable=False,
        )
        db.session.add(hsm_key)
        db.session.flush()
        # Temporary self-signed cert using a stand-in is replaced below.
        ca = CA(
            refid=str(uuid.uuid4()),
            descr=common_name,
            crt=base64.b64encode(b'pending').decode(),
            subject=f'CN={common_name}',
            issuer=f'CN={common_name}',
            offline=True,
            offline_mode='sc-hsm-cloud',
            hsm_key_id=hsm_key.id,
            cdp_enabled=True,
            serial=1,
        )
        db.session.add(ca)
        db.session.commit()
        ca_id = ca.id
        from services.hsm.ca_key_loader import get_ca_signing_key
        signing_key = get_ca_signing_key(ca)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .sign(signing_key, hashes.SHA256())
        )
        ca.crt = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
        ca.subject = cert.subject.rfc4514_string()
        ca.issuer = cert.issuer.rfc4514_string()
        ca.serial_number = str(cert.serial_number)
        db.session.commit()
        assert ca.offline is True
    return ca_id, cert


def _assert_shares_absent(app, provider_id, share_blobs):
    with app.app_context():
        provider = db.session.get(HsmProvider, provider_id)
        stored = provider.config or ''
        for row in HsmCustodian.query.filter_by(provider_id=provider_id):
            stored += row.connect_token_enc or ''
        audits = AuditLog.query.filter(AuditLog.resource_id == str(provider_id)).all()
        stored += '\n'.join((row.details or '') for row in audits)
    for blob in share_blobs:
        encoded = base64.b64encode(blob).decode()
        assert blob.hex() not in stored
        assert encoded not in stored


def test_signing_window_operator_actions_and_protocol_refusal(auth_client, app, bridge_sock):
    provider_id = _provider(auth_client, app, bridge_sock, n=2, m=2, name='e2e-root')
    _begin_and_assemble(auth_client, app, bridge_sock, provider_id)
    ca_id, root_cert = _bind_root(app, bridge_sock, provider_id, 'E2E Offline Root')
    share_blobs = [bytes(card.copy_share()) for card in bridge_sock.ceremony.custodian_cards.values()]

    with app.app_context():
        ca = db.session.get(CA, ca_id)
        assert ca.offline is True
        from utils.signing_ca import signing_ca_problem
        assert signing_ca_problem(ca) == 'CA is offline'

        from services.ocsp_service import OCSPService, OCSPSigningUnavailable
        with pytest.raises(OCSPSigningUnavailable, match='offline'):
            OCSPService()._resolve_signing(ca, root_cert)

        from services.crl_scheduler_task import CRLSchedulerTask
        from unittest.mock import patch
        with patch.object(CRLSchedulerTask, 'regenerate_crl') as regen:
            CRLSchedulerTask.execute()
        assert ca_id not in [call.args[0] for call in regen.call_args_list]

        from services.hsm.ca_key_loader import get_ca_signing_key
        signing_key = get_ca_signing_key(ca)
        now = datetime.now(timezone.utc)
        child_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        child_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'E2E Sub CA')])
        child_cert = (
            x509.CertificateBuilder()
            .subject_name(child_name)
            .issuer_name(root_cert.subject)
            .public_key(child_key.public_key())
            .serial_number(0xA11CE)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(signing_key, hashes.SHA256())
        )
        child_cert.verify_directly_issued_by(root_cert)

        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'E2E OCSP')]))
            .issuer_name(root_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(0x0C59)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=False,
            )
            .sign(signing_key, hashes.SHA256())
        )
        responder_cert.verify_directly_issued_by(root_cert)
        # A response the responder signs still verifies after the window.
        ocsp_tbs = b'ocsp-response-tbs'
        ocsp_sig = responder_key.sign(ocsp_tbs, padding.PKCS1v15(), hashes.SHA256())

        child = CA(
            refid=str(uuid.uuid4()),
            descr='E2E Sub CA',
            crt=base64.b64encode(child_cert.public_bytes(serialization.Encoding.PEM)).decode(),
            subject=child_cert.subject.rfc4514_string(),
            issuer=child_cert.issuer.rfc4514_string(),
            caref=ca.refid,
            serial=1,
        )
        db.session.add(child)
        db.session.commit()
        child_id = child.id

        from services.ca_service import CAService
        revoked, warnings = CAService.revoke_ca(child_id, reason='cessationOfOperation', username='operator')
        assert revoked.revoked is True
        assert not any('could not be regenerated' in warning for warning in warnings)

        from services.crl_service import CRLService
        from models.crl import CRLMetadata
        meta = CRLMetadata.query.filter_by(ca_id=ca_id).order_by(CRLMetadata.id.desc()).first()
        assert meta is not None and meta.crl_der
        published = x509.load_der_x509_crl(meta.crl_der)
        assert published.get_revoked_certificate_by_serial_number(0xA11CE) is not None
        root_cert.public_key().verify(
            published.signature,
            published.tbs_certlist_bytes,
            padding.PKCS1v15(),
            published.signature_hash_algorithm,
        )

        # A second operator CRL publish still works, and the CA is still offline.
        again = CRLService.generate_crl(ca_id, username='operator')
        assert again.crl_der
        db.session.refresh(ca)
        assert ca.offline is True

    wipe = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/wipe')
    assert wipe.status_code == 200, wipe.get_json()
    end = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/end')
    assert end.status_code == 200, end.get_json()
    closed = end.get_json().get('data') or end.get_json()
    assert closed['ceremony_status'] == 'offline'

    with app.app_context():
        ca = db.session.get(CA, ca_id)
        assert ca.offline is True
        from services.hsm.ca_key_loader import get_ca_signing_key
        with pytest.raises(ValueError, match='offline'):
            get_ca_signing_key(ca)
        responder_cert.public_key().verify(ocsp_sig, ocsp_tbs, padding.PKCS1v15(), hashes.SHA256())

    _assert_shares_absent(app, provider_id, share_blobs)

    refused = ScHsmCloudProvider({
        'token_label': 'e2e-root',
        'threshold_n': 2,
        'total_m': 2,
        'socket_path': bridge_sock.sock_path,
    })
    with pytest.raises(HsmOperationError, match='signing window'):
        refused.sign('1', b'after-wipe')


def test_key_roll_replaces_blob_and_signs_with_the_new_key(auth_client, app, bridge_sock):
    provider_id = _provider(auth_client, app, bridge_sock, n=2, m=2, name='e2e-roll')
    _begin_and_assemble(auth_client, app, bridge_sock, provider_id)
    ca_id, old_cert = _bind_root(app, bridge_sock, provider_id, 'E2E Roll Root')
    old_shares = [bytes(card.copy_share()) for card in bridge_sock.ceremony.custodian_cards.values()]

    with app.app_context():
        before = db.session.get(HsmProvider, provider_id).get_config().get('wrapped_root')

    rolled = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/roll-key')
    assert rolled.status_code == 200, rolled.get_json()
    body = rolled.get_json().get('data') or rolled.get_json()
    assert 'wrapped_root' not in body
    assert 'PRIVATE' not in (body.get('public_key_pem') or '')
    new_shares = [bytes(card.copy_share()) for card in bridge_sock.ceremony.custodian_cards.values()]
    assert new_shares != old_shares

    with app.app_context():
        provider = db.session.get(HsmProvider, provider_id)
        after = provider.get_config().get('wrapped_root')
        assert after and after != before
        ca = db.session.get(CA, ca_id)
        new_cert = x509.load_pem_x509_certificate(base64.b64decode(ca.crt))
        assert new_cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != old_cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        from services.hsm.ca_key_loader import get_ca_signing_key
        key = get_ca_signing_key(ca)
        signature = key.sign(b'rolled', padding.PKCS1v15(), hashes.SHA256())
        new_cert.public_key().verify(signature, b'rolled', padding.PKCS1v15(), hashes.SHA256())
        with pytest.raises(Exception):
            old_cert.public_key().verify(signature, b'rolled', padding.PKCS1v15(), hashes.SHA256())
        assert ca.offline is True

    _assert_shares_absent(app, provider_id, old_shares + new_shares)


def test_detail_shows_bridge_down(auth_client, app):
    with app.app_context():
        user = User(username='access-down', email='access-down@example.com', role='operator')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        uid = user.id
    created = auth_client.post('/api/v2/hsm/providers', json={
        'name': 'Access Down',
        'type': 'sc-hsm-cloud',
        'config': {
            'token_label': 'down',
            'threshold_n': 1,
            'total_m': 1,
            'socket_path': '/tmp/ucm-ram-absent.sock',
            'custodians': [{'user_id': uid, 'share_index': 1}],
        },
    })
    assert created.status_code in (200, 201), created.get_json()
    pid = (created.get_json().get('data') or created.get_json())['id']
    detail = auth_client.get(f'/api/v2/hsm/providers/{pid}')
    assert detail.status_code == 200, detail.get_json()
    data = detail.get_json().get('data') or detail.get_json()
    assert data['bridge']['reachable'] is False
    assert data['bridge']['error']
    assert data['ceremony_status'] == 'offline'
    assert data['key_fingerprint'] is None
    for custodian in data['custodians']:
        assert custodian['access'] == 'waiting'
        assert 'connect_token' not in custodian


def test_connect_fake_marks_token_readable_without_share_bytes(auth_client, app, bridge_sock):
    provider_id = _provider(auth_client, app, bridge_sock, n=1, m=1, name='access-read')
    begun = auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/begin')
    assert begun.status_code == 200, begun.get_json()
    with app.app_context():
        row = HsmCustodian.query.filter_by(provider_id=provider_id).one()
        cid = str(row.id)
    connected = call_bridge(
        'connect_fake',
        {'custodian_id': cid},
        sock_path=bridge_sock.sock_path,
    )
    assert connected['ok'] is True
    info = connected['custodians'][cid]
    assert info['connected'] is True
    assert info['has_atr'] is True
    assert info['readable'] is True
    blob = json.dumps(connected)
    share = bytes(bridge_sock.ceremony.custodian_cards[cid].copy_share())
    assert share.hex() not in blob
    assert base64.b64encode(share).decode() not in blob

    detail = auth_client.get(f'/api/v2/hsm/providers/{provider_id}')
    data = detail.get_json().get('data') or detail.get_json()
    assert data['bridge']['reachable'] is True
    mine = data['custodians'][0]
    assert mine['access'] == 'readable'
    assert mine['status'] == 'connected'
    payload = json.dumps(data)
    assert share.hex() not in payload
    assert base64.b64encode(share).decode() not in payload
    assert 'BEGIN PRIVATE' not in payload
    assert 'public_key_pem' not in data or data.get('public_key_pem') is None
