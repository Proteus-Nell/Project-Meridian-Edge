"""ML-DSA-65 signature verification (FIPS 204) via pyca/cryptography.

The server verifies login-challenge signatures against stored public keys.
It never holds private keys (CLAUDE.md section 0); the keypair generated at
import time below exists solely so failure paths can burn comparable
verification time (uniform timing, CLAUDE.md section 5).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)


def verify_mldsa65(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return False


_TIMING_PAD_PUBKEY: bytes = (
    MLDSA65PrivateKey.generate().public_key().public_bytes_raw()
)


def burn_verification_time(signature: bytes, message: bytes) -> None:
    """Equalize the not-found path with the wrong-signature path."""
    verify_mldsa65(_TIMING_PAD_PUBKEY, signature, message)
