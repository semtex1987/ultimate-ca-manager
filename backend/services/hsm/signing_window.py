"""Offline-root signing window helpers.

A SmartCard-HSM ceremony does **not** clear ``ca.offline``. Protocol routes
keep reading ``ca.offline`` directly and stay blocked. Operator root actions
gate with::

    if ca.offline and not signing_window_open(ca):
        refuse

``get_ca_signing_key`` returns the assembly key only while the window is open.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def signing_window_open(ca) -> bool:
    """True when this CA's SmartCard-HSM ceremony has the root key assembled."""
    if ca is None:
        return False
    if not getattr(ca, 'offline', False):
        return False
    hsm_key_id = getattr(ca, 'hsm_key_id', None)
    if not hsm_key_id:
        return False
    try:
        from models import db
        from models.hsm import HsmKey
        hsm_key = db.session.get(HsmKey, hsm_key_id)
        if hsm_key is None or hsm_key.provider is None:
            return False
        if hsm_key.provider.type != 'sc-hsm-cloud':
            return False
        from services.hsm import HsmService
        provider = HsmService._get_provider_instance(hsm_key.provider)
        if not hasattr(provider, 'signing_window_open'):
            return False
        return bool(provider.signing_window_open())
    except Exception as exc:  # noqa: BLE001 — never break operator paths with bridge errors
        logger.warning('signing_window_open check failed for CA %s: %s', getattr(ca, 'id', '?'), exc)
        return False


def operator_offline_blocks(ca) -> bool:
    """True when an offline CA must refuse an operator root-key action."""
    return bool(getattr(ca, 'offline', False)) and not signing_window_open(ca)


def offline_block_message(ca, *, action: str = 'this operation') -> str:
    reason = getattr(ca, 'offline_reason', None) or 'no reason provided'
    return (
        f"Cannot perform {action}: CA '{getattr(ca, 'descr', ca)}' is offline ({reason})"
    )
