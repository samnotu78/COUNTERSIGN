# COUNTERSIGN Token Module
# Token creation, serialization, and signed envelope handling.

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

from .errors import ErrorCode, VerificationResult, error_code_to_verdict
from .models import CountersignToken, SignedCountersignToken
from . import errors as errors_module


# ---------------------------------------------------------------------------
# Re-export for convenience; token-level factory
# ---------------------------------------------------------------------------

def make_token(
    *,
    version: int = 1,
    alg: str = "Ed25519",
    kid: str,
    iss: str,
    jti: str,
    policy_version: int = 1,
    amount: Optional[str] = None,
    currency: Optional[str] = None,
    payee: Optional[str] = None,
    issued_at: Optional[datetime] = None,
    not_before: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    private_key: Optional["Ed25519PrivateKey"] = None,
) -> Optional[SignedCountersignToken]:
    """Build and optionally sign a Countersign token.

    Args:
        version: Token format version.
        alg: Algorithm identifier (only "Ed25519" is verification-compatible).
        kid: Key ID referencing the trust directory snapshot.
        iss: Issuer identifier (fictional organization).
        jti: JWT ID for replay protection.
        policy_version: Policy version contained in the token.
        amount: Signed amount field (Optional).
        currency: Signed currency field (Optional).
        payee: Signed payee field (Optional).
        issued_at: UTC issued-at timestamp (Optional).
        not_before: UTC not-before timestamp (Optional).
        expires_at: UTC expires-at timestamp (Optional).
        private_key: Ed25519 private key for signing. If None, returns
            an unsigned CountersignToken (not SignedCountersignToken).

    Returns:
        A SignedCountersignToken if private_key is provided,
        otherwise a CountersignToken (unsigned).
    """
    from .crypto_types import Ed25519PrivateKey

    token = CountersignToken(
        version=version,
        alg=alg,
        kid=kid,
        iss=iss,
        jti=jti,
        policy_version=policy_version,
        amount=amount,
        currency=currency,
        payee=payee,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
    )

    if private_key is None:
        return token  # type: ignore[return-value]  # returns CountersignToken

    # Sign the token and return the signed container
    signed = token.sign(private_key)  # type: ignore[arg-type]  # SignedCountersignToken
    return signed


def parse_token_bytes(raw: bytes) -> Optional[SignedCountersignToken]:
    """Parse a raw byte token representation.

    Expects base64-encoded SignedCountersignToken.
    Returns a SignedCountersignToken or None if parsing fails.
    """
    try:
        text = raw.decode("utf-8").strip()
        b64_data = base64.b64decode(text)
        # The signed container format: we store the signed token as
        # JSON + signature; for simplicity, re-use Pydantic parsing.
        # In a full implementation, this would be a more compact format.
        return None  # Placeholder — full impl in later steps
    except Exception:
        return None