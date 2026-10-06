"""
CA Signing Key Loader.

Returns a usable signing key for a CA — either a real cryptography
``PrivateKey`` (loaded and decrypted from ``ca.prv``) or an HSM-backed
wrapper (when ``ca.hsm_key_id`` is set) that delegates to the HSM provider.

Use this everywhere you previously did::

    pem = load_pem_bytes(ca.prv, context=f"CA {ca.id}")
    private_key = serialization.load_pem_private_key(pem, password=None,
                                                     backend=default_backend())

so HSM-backed CAs work transparently.
"""

from __future__ import annotations

import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from services.hsm.hsm_private_key import (
    HsmECPrivateKey,
    HsmRSAPrivateKey,
    load_hsm_private_key,
    is_hsm_private_key,
)
from utils.key_codec import load_pem_bytes

logger = logging.getLogger(__name__)


def get_ca_signing_key(ca, *, allow_revoked: bool = False):
    """Return a signing key usable with ``cryptography``'s builders.

    For HSM-backed CAs returns an :class:`HsmRSAPrivateKey` /
    :class:`HsmECPrivateKey` wrapper.  Otherwise returns a real
    ``RSAPrivateKey`` / ``EllipticCurvePrivateKey`` decoded from
    ``ca.prv``.

    For an offline ``sc-hsm-cloud`` root the assembly key is returned only
    while :func:`services.hsm.signing_window.signing_window_open` is true.

    Raises :class:`ValueError` if neither key source is available, or when
    the CA (or an ancestor) is revoked (#343): every issuance path loads the
    key here, so a revoked CA signs nothing new. Serving its existing CRL
    stays possible with ``allow_revoked=True``.
    """
    if ca is None:
        raise ValueError("CA is required")

    if not allow_revoked and getattr(ca, 'revoked_in_chain', False):
        raise ValueError(
            f"CA '{getattr(ca, 'descr', ca)}' is revoked and can no longer sign"
        )

    if getattr(ca, 'hsm_key_id', None):
        # Offline SmartCard-HSM roots only sign inside an open ceremony window.
        if getattr(ca, 'offline', False):
            from services.hsm.signing_window import signing_window_open
            if not signing_window_open(ca):
                raise ValueError(
                    f"CA '{getattr(ca, 'descr', ca)}' is offline and no "
                    "SmartCard-HSM signing window is open"
                )
        return load_hsm_private_key(ca.hsm_key_id)

    if not ca.prv:
        raise ValueError(
            f"CA {getattr(ca, 'refid', ca)} has no signing key "
            "(neither local nor HSM)"
        )

    pem = load_pem_bytes(ca.prv, context=f"CA {getattr(ca, 'refid', ca.id)}")
    return serialization.load_pem_private_key(
        pem, password=None, backend=default_backend()
    )


__all__ = [
    'get_ca_signing_key',
    'is_hsm_private_key',
    'load_hsm_private_key',
    'HsmRSAPrivateKey',
    'HsmECPrivateKey',
]
