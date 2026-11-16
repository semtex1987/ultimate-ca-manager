"""SmartCard-HSM public key authentication: parsing, messages, software root HSM."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from services.hsm import sc_hsm_pka as pka


def _keyholder(chr_value='UTKH0000001', curve=ec.SECP256R1()):
    private = ec.generate_private_key(curve)
    return private, pka.build_fake_pka_export(private, chr_value)


def _authenticate(hsm, private, chr_value):
    _, sw1, sw2 = _sw(hsm.transmit(pka.apdu_select_auth_key(chr_value)))
    assert (sw1, sw2) == (0x90, 0x00)
    challenge, sw1, sw2 = _sw(hsm.transmit(pka.apdu_get_challenge()))
    assert (sw1, sw2) == (0x90, 0x00) and len(challenge) == 8
    message = pka.auth_message(pka.device_id_bytes(hsm.device_chr), challenge)
    signature = pka.sign_plain(private, message)
    return challenge, signature, hsm.transmit(pka.apdu_external_authenticate(signature))


def _sw(rapdu):
    return rapdu[:-2], rapdu[-2], rapdu[-1]


# -- export parsing ----------------------------------------------------------

def test_export_round_trip_exposes_holder_device_and_fingerprint():
    private, export = _keyholder()
    key = pka.parse_pka_export(export)
    assert key.chr == 'UTKH0000001'
    assert key.device_chr == 'DECC0000000001'
    assert key.dica_chr == 'DEDICA00001'
    assert key.curve == 'secp256r1'
    assert key.hash_name == 'sha256'
    assert key.fingerprint == hashlib.sha256(key.point).hexdigest()
    assert key.summary()['fingerprint'] == key.fingerprint


@pytest.mark.parametrize('curve', [ec.SECP384R1(), ec.BrainpoolP256R1()])
def test_curve_is_detected_from_the_point(curve):
    _, export = _keyholder(curve=curve)
    assert pka.parse_pka_export(export).curve == curve.name


def test_export_rejects_rsa_keys_and_broken_chains():
    private, export = _keyholder()
    tampered = export.replace(
        pka.encode_oid(pka.OID_ECDSA_SHA256), pka.encode_oid(pka.OID_RSA_V15_SHA256), 1,
    )
    with pytest.raises(pka.PkaError, match='ECC'):
        pka.parse_pka_export(tampered)
    # Outer CAR no longer names the included device certificate.
    broken = export.replace(b'DECC0000000001', b'DECC0000000002', 1)
    with pytest.raises(pka.PkaError):
        pka.parse_pka_export(broken)
    with pytest.raises(pka.PkaError):
        pka.parse_pka_export(b'')
    with pytest.raises(pka.PkaError):
        pka.parse_pka_export(b'\x30\x05\x01\x02')


def test_signature_check_accepts_plain_and_der_and_rejects_other_keys():
    private, export = _keyholder()
    key = pka.parse_pka_export(export)
    message = b'device' + b'\x01' * 8
    plain = pka.sign_plain(private, message)
    pka.verify_keyholder_signature(key, message, plain)
    der = private.sign(message, ec.ECDSA(hashes.SHA256()))
    pka.verify_keyholder_signature(key, message, der)
    other, _ = _keyholder('UTKH0000002')
    with pytest.raises(pka.PkaError):
        pka.verify_keyholder_signature(key, message, pka.sign_plain(other, message))
    with pytest.raises(pka.PkaError):
        pka.verify_keyholder_signature(key, message + b'x', plain)


def test_card_signature_format_follows_environment(monkeypatch):
    private, export = _keyholder()
    key = pka.parse_pka_export(export)
    plain = pka.sign_plain(private, b'm')
    assert pka.card_signature(key, plain) == plain
    monkeypatch.setenv('UCM_PKA_SIGNATURE_FORMAT', 'der')
    der = pka.card_signature(key, plain)
    assert der[0] == 0x30
    pka.verify_keyholder_signature(key, b'm', der)


# -- APDUs ---------------------------------------------------------------------

def test_apdu_encoding_short_and_extended():
    assert pka.apdu_pka_status() == bytes.fromhex('8054000004')
    assert pka.apdu_get_challenge() == bytes.fromhex('0084000008')
    assert pka.apdu_select_auth_key('AB') == bytes.fromhex('00228 1A4 04 8302 4142'.replace(' ', ''))
    long_data = b'\x11' * 300
    apdu = pka.build_apdu(0x80, 0x68, 0x01, 0x30, long_data, le=65536)
    assert apdu[:7] == bytes((0x80, 0x68, 0x01, 0x30, 0x00, 0x01, 0x2C))
    assert apdu[-2:] == b'\x00\x00'
    assert pka.split_apdu(apdu) == (0x80, 0x68, 0x01, 0x30, long_data, 65536)


def test_gakp_body_matches_opensc_field_order():
    body = pka.gakp_rsa_body(2048, 'UCMROOT00001')
    tags = [item.tag for item in pka.parse_tlvs(body)]
    assert tags == [0x5F29, 0x42, 0x7F49, 0x5F20]
    pubkey = pka.find(pka.parse_tlvs(body), 0x7F49).children()
    assert [item.tag for item in pubkey] == [0x06, 0x82, 0x02]
    assert pka.decode_oid(pubkey[0].value) == pka.OID_RSA_V15_SHA256
    assert pubkey[2].value == b'\x08\x00'
    with pytest.raises(pka.PkaError):
        pka.gakp_rsa_body(1024, 'X')


def test_digest_info_prefix_is_der_sha256():
    info = pka.digest_info('sha256', b'abc')
    assert info.startswith(bytes.fromhex('3031300d0609608648016503040201'))
    assert info.endswith(hashlib.sha256(b'abc').digest())


# -- software root HSM ----------------------------------------------------------

def _root(n=2, m=3):
    hsm = pka.FakePkaRootHsm(threshold_n=n, total_m=m)
    holders = []
    for index in range(m):
        private, export = _keyholder(f'UTKH000000{index}')
        hsm.register(export)
        holders.append((private, f'UTKH000000{index}'))
    return hsm, holders


def test_quorum_is_required_before_generation_or_signing():
    hsm, holders = _root(n=2, m=3)
    status, _, _ = _sw(hsm.transmit(pka.apdu_pka_status()))
    assert pka.parse_pka_status(status) == {'total': 3, 'missing': 0, 'required': 2, 'authenticated': 0}

    _, _, rapdu = _authenticate(hsm, *holders[0])
    assert rapdu == b'\x90\x00'
    assert hsm.transmit(pka.apdu_generate_rsa(1, 2048, 'UCMROOT00001'))[-2:] == b'\x69\x82'

    _, _, rapdu = _authenticate(hsm, *holders[2])
    assert rapdu == b'\x90\x00'
    response = hsm.transmit(pka.apdu_generate_rsa(1, 2048, 'UCMROOT00001'))
    assert response[-2:] == b'\x90\x00'
    public = pka.parse_generated_rsa(response[:-2])

    info = pka.digest_info('sha256', b'tbs')
    signature = hsm.transmit(pka.apdu_sign_pkcs1(1, info))
    assert signature[-2:] == b'\x90\x00'
    pka.verify_rsa_pkcs1(public, b'tbs', signature[:-2], 'sha256')

    objects, _, _ = _sw(hsm.transmit(pka.apdu_enumerate_objects()))
    assert b'\xCC\x01' in pka.parse_object_list(objects)
    assert hsm.transmit(pka.apdu_generate_rsa(1, 2048, 'UCMROOT00001'))[-2:] == b'\x6A\x89'

    hsm.reset()
    status, _, _ = _sw(hsm.transmit(pka.apdu_pka_status()))
    assert pka.parse_pka_status(status)['authenticated'] == 0
    assert hsm.transmit(pka.apdu_sign_pkcs1(1, info))[-2:] == b'\x69\x82'


def test_replayed_or_foreign_signatures_are_rejected():
    hsm, holders = _root(n=1, m=2)
    _, signature, rapdu = _authenticate(hsm, *holders[0])
    assert rapdu == b'\x90\x00'
    hsm.reset()
    hsm.transmit(pka.apdu_select_auth_key(holders[0][1]))
    hsm.transmit(pka.apdu_get_challenge())
    assert hsm.transmit(pka.apdu_external_authenticate(signature)) == b'\x63\x00'
    # A key that was never registered cannot even be selected.
    stranger, _ = _keyholder('UTKH9999999')
    assert hsm.transmit(pka.apdu_select_auth_key('UTKH9999999')) == b'\x6A\x88'
    # A registered CHR signed by the wrong private key fails.
    hsm.transmit(pka.apdu_select_auth_key(holders[1][1]))
    challenge, _, _ = _sw(hsm.transmit(pka.apdu_get_challenge()))
    forged = pka.sign_plain(stranger, pka.auth_message(pka.device_id_bytes(hsm.device_chr), challenge))
    assert hsm.transmit(pka.apdu_external_authenticate(forged)) == b'\x63\x00'


def test_device_certificate_is_readable_from_ef_2f02():
    hsm, _ = _root(n=1, m=1)
    assert hsm.transmit(pka.apdu_select_ef(pka.DEVICE_CERT_FID))[-2:] == b'\x90\x00'
    data = b''
    while True:
        chunk = hsm.transmit(pka.apdu_read_binary(len(data)))
        body = chunk[:-2]
        data += body
        if len(body) < 0xE0:
            break
    device, dica = pka.parse_device_certificate(data + b'\x00' * 16)
    assert device.chr == hsm.device_chr
    assert dica is not None and device.car == dica.chr


# -- ceremony messages -----------------------------------------------------------

def test_manifest_validation_and_hash_are_canonical():
    ops, budget = pka.validate_manifest_request(
        [{'type': 'publish_crl', 'label': 'CRL for Root A', 'ca_id': '3'}], '4',
    )
    assert ops == [{'type': 'publish_crl', 'label': 'CRL for Root A', 'ca_id': 3}]
    assert budget == 4
    a = pka.manifest_hash({'b': 1, 'a': [1, 2]})
    b = pka.manifest_hash({'a': [1, 2], 'b': 1})
    assert a == b
    for bad in ([], [{'type': 'nope', 'label': 'x'}], [{'type': 'publish_crl', 'label': ''}]):
        with pytest.raises(pka.PkaError):
            pka.validate_manifest_request(bad, 1)
    with pytest.raises(pka.PkaError):
        pka.validate_manifest_request([{'type': 'publish_crl', 'label': 'x'}], 0)


def test_signed_messages_are_domain_separated():
    digest = b'\x01' * 32
    approval = pka.approval_message(digest)
    countersign = pka.transcript_message(digest)
    auth = pka.auth_message(b'DECC0000000099', b'\x02' * 8)
    assert len({approval, countersign, auth}) == 3
    assert approval.startswith(b'UCM-PKA-MANIFEST-APPROVAL-v1\x00')
    assert len(auth) != len(approval)
    with pytest.raises(pka.PkaError):
        pka.auth_message(b'x', b'short')


def test_sas_depends_on_every_input():
    digest = b'\x05' * 32
    base = pka.compute_sas('c1', digest, 'DECC1', 'aa')
    assert len(base) == 7 and base[3] == '-'
    assert base == pka.compute_sas('c1', digest, 'DECC1', 'AA')
    variants = {
        pka.compute_sas('c2', digest, 'DECC1', 'aa'),
        pka.compute_sas('c1', b'\x06' * 32, 'DECC1', 'aa'),
        pka.compute_sas('c1', digest, 'DECC2', 'aa'),
        pka.compute_sas('c1', digest, 'DECC1', 'bb'),
    }
    assert base not in variants


def test_transcript_chain_detects_tampering():
    transcript = pka.Transcript()
    transcript.append('opened', {'ceremony_id': 'c1'})
    transcript.append('signed', {'tbs_sha256': 'ab'})
    final = transcript.seal()
    entries = transcript.to_list()
    assert pka.verify_transcript(entries) == final
    with pytest.raises(pka.PkaError):
        transcript.append('late')
    entries[1]['data']['tbs_sha256'] = 'cd'
    with pytest.raises(pka.PkaError):
        pka.verify_transcript(entries)
    entries = transcript.to_list()
    del entries[1]
    with pytest.raises(pka.PkaError):
        pka.verify_transcript(entries)
