# COUNTERSIGN Crypto Package
# Cryptographic trust core for COUNTERSIGN.

# Phase 1: deterministic, fail-closed verification foundation.
# No LLM/AI dependencies. All verification is purely cryptographic.

from .errors import ErrorCode, VerificationResult, error_code_to_verdict
from .models import CountersignToken, SignedCountersignToken
from .replay import ReplayStore
from .trust import TrustDirectory
from .verification import verify_token, verify_from_bytes
from .crypto_types import Ed25519PrivateKey, Ed25519PublicKey, generate_demo_key_pair

# Convenience re-exports
__all__ = [
    "ErrorCode",
    "VerificationResult",
    "error_code_to_verdict",
    "CountersignToken",
    "SignedCountersignToken",
    "ReplayStore",
    "TrustDirectory",
    "verify_token",
    "verify_from_bytes",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "generate_demo_key_pair",
]

# Version string
__version__ = "1.0.0-phase1"