# COUNTERSIGN Crypto Types
# Internal type definitions for the crypto package.

from __future__ import annotations

import os
from typing import Tuple

from nacl.signing import SigningKey, VerifyKey


# ---------------------------------------------------------------------------
# Ed25519 key types wrapped from PyNaCl
# ---------------------------------------------------------------------------

class Ed25519PrivateKey:
    """Wrapper for a NaCl Ed25519 private key.

    This is a type-level wrapper to make the crypto package's
    public API self-documenting. The actual NaCl key object
    is stored as ._nacl_key.
    """

    def __init__(self, nacl_key: SigningKey) -> None:
        self._nacl_key = nacl_key

    # Property to access the raw 32-byte private key
    @property
    def seed(self) -> bytes:
        return self._nacl_key._seed

    # Property to access the raw 32-byte private key material
    @property
    def private_bytes(self) -> bytes:
        return self._nacl_key.encode()


class Ed25519PublicKey:
    """Wrapper for a NaCl Ed25519 public key."""

    def __init__(self, bytes_: bytes) -> None:
        if len(bytes_) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self.bytes = bytes_


def generate_demo_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair for demo/test use.

    Returns:
        (private_key, public_key) tuple of wrapper types.
    """
    signing_key = SigningKey(os.urandom(32))
    private_key = Ed25519PrivateKey(signing_key)

    # Extract the public key from the signing key
    verify_key = signing_key.verify_key
    pub_bytes = verify_key.encode()
    public_key = Ed25519PublicKey(pub_bytes)
    return private_key, public_key