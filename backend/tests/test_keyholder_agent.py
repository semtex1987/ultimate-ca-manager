"""Keyholder agent (tools/keyholder/ucm_keyholder.py).

The agent is standalone, so its message formats are checked against the
backend here, and its approve/countersign commands run against the API with a
software card in place of PKCS#11.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import os
import pathlib
import types

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from services.hsm import sc_hsm_pka as pka
from services.hsm.sc_hsm_cloud_provider import call_bridge

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('ucm_keyholder', ROOT / 'tools' / 'keyholder' / 'ucm_keyholder.py')
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)

from tests.test_sc_hsm_pka_ceremony import (  # noqa: E402
    _begin,
    _data,
    _enroll_all,
    _setup,
    pka_bridge,  # noqa: F401 — fixture
)


def test_agent_message_formats_match_the_backend():
    manifest = {'ceremony_id': 'c-1', 'operations': [{'type': 'publish_crl', 'label': 'é'}], 'max_signatures': 2}
    digest = agent.manifest_hash(manifest)
    assert digest == pka.manifest_hash(manifest)
    assert agent.approval_message(digest) == pka.approval_message(digest)
    assert agent.transcript_message(digest) == pka.transcript_message(digest)
    assert agent.compute_sas('c-1', digest, 'DECC1', 'AB') == pka.compute_sas('c-1', digest, 'DECC1', 'ab')
    transcript = pka.Transcript()
    transcript.append('opened', {'x': 1})
    final = transcript.seal()
    assert agent.verify_transcript(transcript.to_list()) == final
    tampered = transcript.to_list()
    tampered[0]['data']['x'] = 2
    with pytest.raises(agent.AgentError):
        agent.verify_transcript(tampered)


def test_agent_checks_device_id_and_unwraps_ec_points():
    assert agent.device_id_matches(b'DECC01', 'DECC01')
    assert agent.device_id_matches(pka.encode_tlv(0x5F20, b'DECC01'), 'DECC01')
    assert not agent.device_id_matches(b'DECC02', 'DECC01')
    point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    assert agent.unwrap_ec_point(b'\x04' + bytes((len(point),)) + point) == point
    assert agent.unwrap_ec_point(point) == point


class _SoftCard:
    """Stands in for the keyholder's SmartCard-HSM."""

    def __init__(self, private):
        self.private = private
        self.logins = 0

    def public_point(self):
        return self.private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
        )

    @contextlib.contextmanager
    def signer(self, *, pinpad):
        self.logins += 1
        yield lambda message: pka.sign_plain(self.private, message)

    def sign(self, messages, *, pinpad):
        with self.signer(pinpad=pinpad) as sign:
            return [sign(m) for m in messages]


class _ClientApi:
    """The agent's Api, backed by the Flask test client."""

    def __init__(self, client):
        self.client = client
        from services.hsm.ceremony_service import server_tls_spki_sha256
        self.observed_spki = server_tls_spki_sha256()

    def request(self, method, path, body=None):
        response = self.client.open(path, method=method, json=body)
        if response.status_code >= 400:
            raise agent.AgentError(f'{method} {path}: HTTP {response.status_code}: {response.get_json()}')
        return _data(response)


def test_agent_approves_authenticates_and_countersigns(auth_client, app, pka_bridge, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setattr(agent, 'PIN_FILE', str(tmp_path / 'pins.json'))
    provider_id, holders = _setup(auth_client, app, pka_bridge, n=2, m=2, name='agent-root')
    _enroll_all(provider_id, holders)
    assert _begin(auth_client, provider_id, [{'type': 'generate_root_key', 'label': 'Generate'}]).status_code == 200
    call_bridge('connect_fake', {'custodian_id': 'root'}, sock_path=pka_bridge.sock_path)
    device_chr = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))['pka']['live']['device_chr']
    assert auth_client.post(
        f'/api/v2/hsm/providers/{provider_id}/ceremony/pin-device', json={'device_chr': device_chr},
    ).status_code == 200

    args = types.SimpleNamespace(provider=provider_id, url='https://ucm.test', pinpad=False,
                                 ceremony_id=None, countersign=True)
    for index, holder in enumerate(holders):
        # Each keyholder has their own machine and their own pin file.
        monkeypatch.setattr(agent, 'PIN_FILE', str(tmp_path / f'pins-{index}.json'))
        card = _SoftCard(holder.private)
        answers = iter([device_chr, 'APPROVE'])
        monkeypatch.setattr('builtins.input', lambda _prompt='': next(answers))
        assert agent.cmd_approve(args, card, _ClientApi(holder.client)) == 0
        assert card.logins == 1  # one PIN entry for approval and authentication

    detail = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))
    assert detail['pka']['live']['unlocked'] is True

    base = f'/api/v2/hsm/providers/{provider_id}/ceremony'
    assert auth_client.post(f'{base}/generate-root-key', json={'confirm': 'GENERATE'}).status_code == 200
    assert auth_client.post(f'{base}/wipe').status_code == 200
    assert auth_client.post(f'{base}/end').status_code == 200

    # A pinned device that changes is refused locally.
    with pytest.raises(agent.AgentError, match='pinned'):
        agent.check_device_pin('https://ucm.test', provider_id, 'DECC0000000777')

    monkeypatch.setattr('builtins.input', lambda _prompt='': 'CONFIRM')
    card = _SoftCard(holders[0].private)
    assert agent.cmd_transcript(args, card, _ClientApi(holders[0].client)) == 0
    transcript = _data(holders[0].client.get(f'{base}/transcript'))
    assert list(transcript['countersignatures']) != []


def test_agent_refuses_a_card_that_is_not_the_enrolled_key(auth_client, app, pka_bridge, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setattr(agent, 'PIN_FILE', str(tmp_path / 'pins.json'))
    provider_id, holders = _setup(auth_client, app, pka_bridge, n=1, m=1, name='agent-wrong-card')
    _enroll_all(provider_id, holders)
    assert _begin(auth_client, provider_id, [{'type': 'publish_crl', 'label': 'CRL'}]).status_code == 200
    call_bridge('connect_fake', {'custodian_id': 'root'}, sock_path=pka_bridge.sock_path)
    device_chr = _data(auth_client.get(f'/api/v2/hsm/providers/{provider_id}'))['pka']['live']['device_chr']
    auth_client.post(f'/api/v2/hsm/providers/{provider_id}/ceremony/pin-device', json={'device_chr': device_chr})
    stranger = _SoftCard(ec.generate_private_key(ec.SECP256R1()))
    answers = iter([device_chr, 'APPROVE'])
    monkeypatch.setattr('builtins.input', lambda _prompt='': next(answers))
    args = types.SimpleNamespace(provider=provider_id, url='https://ucm.test', pinpad=False)
    with pytest.raises(agent.AgentError, match='not the key enrolled'):
        agent.cmd_approve(args, stranger, _ClientApi(holders[0].client))
    assert stranger.logins == 0


def test_version_prints_the_agents_own_hash_without_touching_a_card(capsys):
    """The keyholder compares this on the call with the published value."""
    path = pathlib.Path(__file__).resolve().parents[2] / 'tools' / 'keyholder' / 'ucm_keyholder.py'
    spec = importlib.util.spec_from_file_location('ucm_keyholder_version', path)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    with pytest.raises(SystemExit) as exited:
        agent.main(['--version'])
    assert exited.value.code == 0
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert capsys.readouterr().out.strip() == f'ucm_keyholder.py sha256 {expected}'
