"""The keyholder roster of a quorum-controlled HSM survives a backup.

A provider restored without its custodians has a quorum nobody can satisfy:
the public key each keyholder enrolled is what the root HSM was registered
with. The roster travels; the per-window connect token, a bearer credential,
does not, and a restore issues a fresh one.
"""
import pytest

from models import db
from services.backup import manifest
from services.backup.restore import RestorePlan

PASSWORD = 'Correct-Horse-Battery-9'
PROVIDER = 'zzcust-backup-provider'
PUBLIC_KEY = 'zzcust-public-key-export'
TOKEN = 'zzcust-connect-token-never-archived'


def _service():
    from services.backup_service import BackupService
    return BackupService()


def _only(*names):
    return {name: name in names for name in manifest.SECTIONS}


def _payload(blob):
    _key, data = _service()._decrypt_framed(blob, PASSWORD)
    return data


@pytest.fixture
def roster(app):
    from models.hsm import HsmCustodian, HsmProvider

    with app.app_context():
        provider = HsmProvider(name=PROVIDER, type='sc-hsm-cloud', config='{}')
        db.session.add(provider)
        db.session.flush()
        for index in (1, 2):
            row = HsmCustodian(provider_id=provider.id, share_index=index,
                               display_name=f'zzcust-holder-{index}',
                               auth_public_key=f'{PUBLIC_KEY}-{index}')
            row.set_connect_token(f'{TOKEN}-{index}')
            db.session.add(row)
        db.session.commit()
        provider_id = provider.id

    yield provider_id

    with app.app_context():
        HsmCustodian.query.filter_by(provider_id=provider_id).delete(
            synchronize_session=False)
        HsmProvider.query.filter_by(name=PROVIDER).delete(
            synchronize_session=False)
        db.session.commit()


def _archived(app):
    with app.app_context():
        blob = _service().create_backup(
            PASSWORD, include=_only('hsm_providers', 'hsm_custodians'))
    payload = _payload(blob)
    rows = [row for row in payload['hsm_custodians']
            if str(row.get('display_name', '')).startswith('zzcust-')]
    return payload, rows


def test_the_roster_travels_with_its_public_keys(app, roster):
    _payload_, rows = _archived(app)
    assert sorted(row['share_index'] for row in rows) == [1, 2]
    assert {row['auth_public_key'] for row in rows} == {
        f'{PUBLIC_KEY}-1', f'{PUBLIC_KEY}-2'}
    for row in rows:
        assert row.get('provider_id_ref', {}).get('name') == PROVIDER


def test_the_connect_token_never_leaves(app, roster):
    payload, rows = _archived(app)
    for row in rows:
        assert 'connect_token_enc' not in row
    assert TOKEN not in str(payload)


def test_a_restore_puts_the_roster_back_with_fresh_tokens(app, roster):
    from models.hsm import HsmCustodian

    payload, rows = _archived(app)
    payload = {**payload, 'hsm_custodians': rows}

    with app.app_context():
        HsmCustodian.query.filter_by(provider_id=roster).delete(
            synchronize_session=False)
        db.session.commit()

        results = {}
        _service()._restore_hsm_custodians(
            payload, results, RestorePlan.build(payload))
        db.session.commit()

        restored = (HsmCustodian.query.filter_by(provider_id=roster)
                    .order_by(HsmCustodian.share_index).all())
        assert results['hsm_custodians'] == 2
        assert [row.auth_public_key for row in restored] == [
            f'{PUBLIC_KEY}-1', f'{PUBLIC_KEY}-2']
        tokens = [row.get_connect_token() for row in restored]
        assert all(tokens) and len(set(tokens)) == 2
        assert not any(token.startswith(TOKEN) for token in tokens)


def test_a_restore_onto_an_existing_roster_keeps_its_tokens(app, roster):
    from models.hsm import HsmCustodian

    payload, rows = _archived(app)
    payload = {**payload, 'hsm_custodians': rows}

    with app.app_context():
        results = {}
        _service()._restore_hsm_custodians(
            payload, results, RestorePlan.build(payload))
        db.session.commit()
        restored = HsmCustodian.query.filter_by(provider_id=roster).all()
        assert len(restored) == 2
        assert sorted(row.get_connect_token() for row in restored) == [
            f'{TOKEN}-1', f'{TOKEN}-2']
