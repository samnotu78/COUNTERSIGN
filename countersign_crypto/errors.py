# COUNTERSIGN Crypto Error Codes
# Closed reason codes — no free-form LLM text.

from enum import Enum, auto


class VerificationResult(Enum):
    """Top-level verdict."""
    VERIFIED = auto()
    CONTRADICTS_POLICY = auto()
    UNVERIFIABLE = auto()


class ErrorCode(Enum):
    """Closed error codes that appear under UNVERIFIABLE verdict."""

    # Cryptographic failures
    SIGNATURE_INVALID = auto()
    KEY_UNKNOWN = auto()
    KEY_REVOKED = auto()
    KEY_NOT_YET_VALID = auto()
    KEY_EXPIRED = auto()

    # Token failures
    TOKEN_EXPIRED = auto()
    TOKEN_NOT_YET_VALID = auto()
    TOKEN_TIMESTAMP_INVALID = auto()

    # Directory/Trust failures
    DIRECTORY_INVALID = auto()
    DIRECTORY_SIGNATURE_INVALID = auto()
    DIRECTORY_EXPIRED = auto()

    # Algorithm failures
    ALG_UNSUPPORTED = auto()
    ALG_NONE = auto()

    # Structural failures
    MALFORMED_TOKEN = auto()
    DUPLICATE_FIELD = auto()
    UNKNOWN_FIELD = auto()
    INVALID_FIELD_TYPE = auto()
    INVALID_CANONICAL_ENCODING = auto()

    # Policy failures
    POLICY_VERSION_TOO_OLD = auto()
    POLICY_CONTRADICTION = auto()
    POLICY_NOT_FOUND = auto()
    POLICY_AMBIGUOUS = auto()
    UNSUPPORTED_ACTION = auto()
    MALFORMED_POLICY = auto()
    POLICY_TAMPERED = auto()

    # Replay failures
    REPLAY_DETECTED = auto()

    # Directory trust failures
    DIRECTORY_NOT_TRUSTED = auto()
    DIRECTORY_NOT_YET_ACTIVE = auto()
    DIRECTORY_VERSION_DOWNGRADE = auto()


def error_code_to_verdict(code: ErrorCode) -> VerificationResult:
    """Map error codes to top-level verdicts.

    All ErrorCode values map to UNVERIFIABLE since no error
    may produce VERIFIED.
    """
    return VerificationResult.UNVERIFIABLE


# Map error code to human-readable string for UI display
ERROR_CODE_LABELS = {
    ErrorCode.SIGNATURE_INVALID: "SIGNATURE_INVALID",
    ErrorCode.KEY_UNKNOWN: "KEY_UNKNOWN",
    ErrorCode.KEY_REVOKED: "KEY_REVOKED",
    ErrorCode.KEY_NOT_YET_VALID: "KEY_NOT_YET_VALID",
    ErrorCode.KEY_EXPIRED: "KEY_EXPIRED",
    ErrorCode.TOKEN_EXPIRED: "TOKEN_EXPIRED",
    ErrorCode.TOKEN_NOT_YET_VALID: "TOKEN_NOT_YET_VALID",
    ErrorCode.TOKEN_TIMESTAMP_INVALID: "TOKEN_TIMESTAMP_INVALID",
    ErrorCode.DIRECTORY_INVALID: "DIRECTORY_INVALID",
    ErrorCode.DIRECTORY_SIGNATURE_INVALID: "DIRECTORY_SIGNATURE_INVALID",
    ErrorCode.DIRECTORY_EXPIRED: "DIRECTORY_EXPIRED",
    ErrorCode.ALG_UNSUPPORTED: "ALG_UNSUPPORTED",
    ErrorCode.ALG_NONE: "ALG_NONE",
    ErrorCode.MALFORMED_TOKEN: "MALFORMED_TOKEN",
    ErrorCode.DUPLICATE_FIELD: "DUPLICATE_FIELD",
    ErrorCode.UNKNOWN_FIELD: "UNKNOWN_FIELD",
    ErrorCode.INVALID_FIELD_TYPE: "INVALID_FIELD_TYPE",
    ErrorCode.INVALID_CANONICAL_ENCODING: "INVALID_CANONICAL_ENCODING",
    ErrorCode.POLICY_VERSION_TOO_OLD: "POLICY_VERSION_TOO_OLD",
    ErrorCode.POLICY_CONTRADICTION: "POLICY_CONTRADICTION",
    ErrorCode.POLICY_NOT_FOUND: "POLICY_NOT_FOUND",
    ErrorCode.POLICY_AMBIGUOUS: "POLICY_AMBIGUOUS",
    ErrorCode.UNSUPPORTED_ACTION: "UNSUPPORTED_ACTION",
    ErrorCode.MALFORMED_POLICY: "MALFORMED_POLICY",
    ErrorCode.POLICY_TAMPERED: "POLICY_TAMPERED",
    ErrorCode.REPLAY_DETECTED: "REPLAY_DETECTED",
    ErrorCode.DIRECTORY_NOT_TRUSTED: "DIRECTORY_NOT_TRUSTED",
    ErrorCode.DIRECTORY_NOT_YET_ACTIVE: "DIRECTORY_NOT_YET_ACTIVE",
    ErrorCode.DIRECTORY_VERSION_DOWNGRADE: "DIRECTORY_VERSION_DOWNGRADE",
}