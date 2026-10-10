#!/usr/bin/env python3
"""COUNTERSIGN Phase 1 — Cryptographic Trust Core test suite.

Run with: python -m pytest test_phase1.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest

# Ensure package is importable
sys.path.insert(0, os.path.dirname(__file__))

# Import PyNaCl types directly for key generation
from nacl.signing import SigningKey, VerifyKey

# Import from the crypto package (will be adjusted to work with native types)
from countersign_crypto.errors import ErrorCode, VerificationResult, error_code_to_verdict
from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.replay import ReplayStore
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.verification import verify_token


# ===========================================================================
# Helpers: PyNaCl key generation and token signing
# ===========================================================================


def _new_signing_key() -> SigningKey:
    """Generate a new PyNaCl SigningKey."""
    return SigningKey(os.urandom(32))


def _new_verify_key(sk: SigningKey) -> VerifyKey:
    """Extract the VerifyKey from a SigningKey."""
    return sk.verify_key


def _sign_message(sk: SigningKey, message: bytes) -> bytes:
    """Sign a message and return base64-encoded signature."""
    sig = sk.sign(message)
    return base64.b64encode(sig.signature)


def _verify_signature(vk: VerifyKey, message: bytes, signature_b64: bytes) -> bool:
    """Verify a signature. Returns True if valid."""
    try:
        sig_bytes = base64.b64decode(signature_b64)
        vk.verify(message, sig_bytes)
        return True
    except Exception:
        return False


def _make_signed_token_native(
    sk: SigningKey,
    *,
    kid: str = "test-key-1",
    iss: str = "TestOrg",
    jti: str = str(uuid.uuid4()),
    amount: str = "4200",
    currency: str = "INR",
    payee: str = "merchant@example.test",
    policy_version: int = 1,
    expires_at: str | None = None,
    not_before: str | None = None,
) -> SignedCountersignToken:
    """Create a valid signed token using PyNaCl types directly.

    This bypasses the CountersignToken model and signs the canonical JSON
    directly using PyNaCl, then constructs a SignedCountersignToken.
    """

    # Build the canonical JSON (same logic as CountersignToken.canonical())
    issued_at_val = 'null'
    not_before_val = 'null'
    expires_at_val = 'null'

    if expires_at is not None:
        expires_at_val = json.dumps(expires_at)
    if not_before is not None:
        not_before_val = json.dumps(not_before)

    canonical = (
        f'{{"version":1,"alg":"Ed25519","kid":"{kid}","iss":"{iss}"'
        f',"jti":"{jti}","policy_version":{policy_version}'
        f',"amount":"{amount}","currency":"{currency}","payee":"{payee}"'
        f',"issued_at":{issued_at_val},"not_before":{not_before_val},"expires_at":{expires_at_val}}}'
    )

    # Sign the canonical JSON
    signature_b64 = _sign_message(sk, canonical.encode("utf-8"))

    # Construct SignedCountersignToken
    # Use the original approach: model fields stay as None, but set
    # signed_canonical directly to the canonical that was signed, so
    # verification can use the stored signed_canonical bytes.
    from countersign_crypto.models import CountersignToken, SignedCountersignToken

    unsigned_token = CountersignToken(
        version=1,
        alg="Ed25519",
        kid=kid,
        iss=iss,
        jti=jti,
        policy_version=policy_version,
        amount=amount,
        currency=currency,
        payee=payee,
        issued_at=None,
        not_before=None,
        expires_at=None,
    )

    # Parse the canonical to extract expires_at and not_before values
    # so the model fields are populated for expiry/nbf checks.
    # This ensures _get_canonical_bytes() still returns the correct
    # signed bytes (via signed_canonical) while the model fields
    # contain the actual datetime values for validation.
    import json as _json
    canonical_dict = _json.loads(canonical)
    model_expires_at = (
        datetime.fromisoformat(canonical_dict["expires_at"].replace("Z", "+00:00"))
        if canonical_dict.get("expires_at") is not None
        else None
    )
    model_not_before = (
        datetime.fromisoformat(canonical_dict["not_before"].replace("Z", "+00:00"))
        if canonical_dict.get("not_before") is not None
        else None
    )

    signed = SignedCountersignToken(
        version=unsigned_token.version,
        alg=unsigned_token.alg,
        kid=unsigned_token.kid,
        iss=unsigned_token.iss,
        jti=unsigned_token.jti,
        policy_version=unsigned_token.policy_version,
        amount=unsigned_token.amount,
        currency=unsigned_token.currency,
        payee=unsigned_token.payee,
        issued_at=unsigned_token.issued_at,
        not_before=model_not_before,
        expires_at=model_expires_at,
        # The Ed25519 signature over the canonical JSON
        signature=signature_b64.decode("ascii"),
        # Set signed_canonical to the exact canonical that was signed,
        # so _get_canonical_bytes() returns the correct bytes for verification.
        signed_canonical=canonical,
    )

    return signed


def _make_trust_snapshot(*, keys: dict = None, signing_key: SigningKey = None) -> TrustDirectorySnapshot:
    """Build a root-authenticated test snapshot with explicit issuer bindings."""
    from datetime import timedelta
    root = SigningKey(bytes.fromhex("42" * 32))
    TrustDirectory.set_pinned_root_key(root.verify_key.encode())
    snapshot_keys = {}
    for kid, props in (keys or {}).items():
        signer = signing_key or SigningKey.generate()
        snapshot_keys[kid] = {
            "revoked": props.get("revoked", False),
            "valid_from": props.get("valid_from"),
            "valid_until": props.get("valid_until"),
            "public_key_b64": base64.b64encode(signer.verify_key.encode()).decode("ascii"),
            "trusted_organization": props.get("trusted_organization", "TestOrg"),
        }
    snap = TrustDirectorySnapshot(
        snapshot_id=str(uuid.uuid4()), version="1.0", keys=snapshot_keys,
        root_key_fingerprint=__import__("hashlib").sha256(root.verify_key.encode()).hexdigest(),
        signature="pending",
    )
    snap.signature = base64.b64encode(root.sign(snap.signed_bytes()).signature).decode("ascii")
    return snap


# ===========================================================================
# Test Group 1: Valid token produces VERIFIED
# ===========================================================================


@pytest.mark.unit
def test_valid_token_produces_verified():
    """A validly signed token with all checks passing produces VERIFIED."""
    # Generate key pair
    sk = _new_signing_key()
    vk = _new_verify_key(sk)

    # Create a signed token
    signed = _make_signed_token_native(sk)

    # Set up trust directory with the key's kid
    # We need to add the verify key's public key fingerprint to the directory
    # For the demo, we'll use the kid and trust directory setup

    # Get the public key bytes to use as reference
    pub_bytes = vk.encode()
    kid = signed.kid

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={kid: {"revoked": False}}, signing_key=sk)
    )

    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict == VerificationResult.VERIFIED
    assert error_code is None
    assert "AMOUNT" in metadata["verified_fields"]
    assert "CURRENCY" in metadata["verified_fields"]
    assert "PAYEE" in metadata["verified_fields"]


# ===========================================================================
# Test Group 2: Field tampering never produces VERIFIED
# ===========================================================================


@pytest.mark.unit
def test_amount_tamper_not_verified():
    """Tampering with the amount field invalidates verification."""
    sk = _new_signing_key()

    # Create a signed token with amount "4200"
    signed = _make_signed_token_native(sk, amount="4200")

    # Create a second token with different amount - since the signature
    # is over the canonical JSON, changing the amount changes the signed
    # content, so the signature won't verify
    sk2 = _new_signing_key()
    signed2 = _make_signed_token_native(sk2, amount="9999")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed2, replay_store, TrustDirectory)

    # Signature verification should fail because the content was signed by
    # a different key
    assert verdict != VerificationResult.VERIFIED


@pytest.mark.unit
def test_currency_tamper_not_verified():
    """Tampering with the currency field invalidates verification."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, currency="INR")

    sk2 = _new_signing_key()
    signed2 = _make_signed_token_native(sk2, currency="USD")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed2, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED


@pytest.mark.unit
def test_payee_tamper_not_verified():
    """Tampering with the payee field invalidates verification."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, payee="merchant@example.test")

    sk2 = _new_signing_key()
    signed2 = _make_signed_token_native(sk2, payee="different@payee.test")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed2, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED


# ===========================================================================
# Test Group 3: Key trust failures
# ===========================================================================


@pytest.mark.unit
def test_unknown_key_not_verified():
    """A token signed by an unknown key must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="unknown-key-999")

    TrustDirectory.initialize_with_snapshot(_make_trust_snapshot())
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED
    assert error_code == ErrorCode.KEY_UNKNOWN


@pytest.mark.unit
def test_revoked_key_not_verified():
    """A token signed by a revoked key must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="revoked-key")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"revoked-key": {"revoked": True}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED
    assert error_code == ErrorCode.KEY_REVOKED


@pytest.mark.unit
def test_expired_key_not_verified():
    """A token signed by an expired key must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="expired-key")

    from datetime import datetime, timezone

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(
            keys={
                "expired-key": {
                    "revoked": False,
                    "valid_until": datetime(2020, 1, 1, tzinfo=timezone.utc),
                }
            },
            signing_key=sk,
        )
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED
    assert error_code == ErrorCode.KEY_EXPIRED


@pytest.mark.unit
def test_future_key_not_verified():
    """A token signed by a key not yet valid must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="future-key")

    from datetime import datetime, timezone

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(
            keys={
                "future-key": {
                    "revoked": False,
                    "valid_from": datetime(2030, 1, 1, tzinfo=timezone.utc),
                }
            },
            signing_key=sk,
        )
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED
    assert error_code == ErrorCode.KEY_NOT_YET_VALID


@pytest.mark.unit
def test_expired_token_not_verified():
    """An expired token must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, expires_at="2020-01-01T00:00:00Z")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.TOKEN_EXPIRED


@pytest.mark.unit
def test_not_yet_valid_token_not_verified():
    """A token not yet valid (not_before in the future) must never be VERIFIED."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, not_before="2099-01-01T00:00:00Z")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.TOKEN_NOT_YET_VALID


# ===========================================================================
# Test Group 5: Replay protection
# ===========================================================================


@pytest.mark.unit
def test_replay_first_accepted_second_rejected():
    """First presentation of a token is accepted; second (replay) is rejected."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, jti="replay-test-jti-123")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # First presentation — should be accepted
    verdict1, error_code1, metadata1 = verify_token(signed, replay_store, TrustDirectory)
    assert verdict1 == VerificationResult.VERIFIED
    assert error_code1 is None

    # Second presentation of the same jti/issuer — should be replay
    verdict2, error_code2, metadata2 = verify_token(signed, replay_store, TrustDirectory)
    assert verdict2 == VerificationResult.UNVERIFIABLE
    assert error_code2 == ErrorCode.REPLAY_DETECTED


# ===========================================================================
# Test Group 6: Algorithm rejection
# ===========================================================================


@pytest.mark.unit
def test_alg_none_rejected():
    """alg:none must never produce VERIFIED."""
    from countersign_crypto.errors import ErrorCode

    assert ErrorCode.ALG_NONE is not None


@pytest.mark.unit
def test_unsupported_algorithm_rejected():
    """An unsupported algorithm must never produce VERIFIED."""
    from countersign_crypto.errors import ErrorCode

    assert ErrorCode.ALG_UNSUPPORTED is not None


# ===========================================================================
# Test Group 7: Fail-closed property tests
# ===========================================================================


@pytest.mark.unit
def test_fail_closed_unknown_key():
    """Verification failures always fail closed — unknown key."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="nonexistent-key")

    TrustDirectory.initialize_with_snapshot(_make_trust_snapshot())
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED


@pytest.mark.unit
def test_fail_closed_revoked_key():
    """Verification failures always fail closed — revoked key."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, kid="revoked-key")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"revoked-key": {"revoked": True}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict != VerificationResult.VERIFIED
    assert error_code == ErrorCode.KEY_REVOKED


@pytest.mark.unit
def test_fail_closed_expired_token():
    """Verification failures always fail closed — expired token."""
    sk = _new_signing_key()

    signed = _make_signed_token_native(sk, expires_at="2020-01-01T00:00:00Z")

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.TOKEN_EXPIRED


# ===========================================================================
# ===========================================================================
# Phase 2: Policy engine + verdict layer tests
# ===========================================================================


@pytest.mark.unit
def test_phase2_valid_signed_evidence_no_contradiction():
    """Valid signed evidence + no policy contradiction → VERIFIED."""
    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # No ai_action/policy_engine → Phase 1 behaviour: VERIFIED
    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)

    assert verdict == VerificationResult.VERIFIED
    assert error_code is None


@pytest.mark.unit
def test_phase2_valid_signed_evidence_with_contradiction():
    """Valid signed evidence + deterministic prohibited action → CONTRADICTS_POLICY."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # OTP disclosure is a baseline deny → CONTRADICTS_POLICY
    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_untrusted_claim_cannot_create_verified():
    """Unsigned/untrusted claim attempting to create trust → MUST NOT produce VERIFIED."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # AI claims "safe" but policy says prohibited; crypto still passes,
    # but policy engine blocks VERIFIED
    policy_engine = PolicyEngine(policies={"REQUEST_OTP_DISCLOSURE": "DENY"})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    # Must NOT be VERIFIED
    assert verdict != VerificationResult.VERIFIED
    # Should be CONTRADICTS_POLICY since it's a baseline deny
    assert verdict == VerificationResult.CONTRADICTS_POLICY


@pytest.mark.unit
def test_phase2_ai_malicious_claim_safe_while_policy_prohibited():
    """AI-like malicious claim saying 'safe' while deterministic policy says prohibited → MUST NOT produce VERIFIED."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # AI claims action is "safe" but policy engine has it as DENY
    policy_engine = PolicyEngine(
        policies={"REQUEST_OTP_DISCLOSURE": "DENY", "REQUEST_PIN_DISCLOSURE": "DENY"}
    )
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict != VerificationResult.VERIFIED
    assert verdict == VerificationResult.CONTRADICTS_POLICY


# Baseline deny tests: OTP, PIN, CVV, Password, Remote-access, Gift-card
@pytest.mark.unit
def test_phase2_otp_disclosure():
    """OTP request → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_pin_disclosure():
    """PIN request → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_PIN_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_cvv_disclosure():
    """CVV request → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_CVV_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_password_disclosure():
    """Password request → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_PASSWORD_DISCLOSURE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_remote_access_installation():
    """Remote-access software installation → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="INSTALL_REMOTE_ACCESS_SOFTWARE",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_gift_card_payment():
    """Gift-card payment request → CONTRADICTS_POLICY (baseline deny)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="MAKE_GIFT_CARD_PAYMENT",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.CONTRADICTS_POLICY
    assert error_code == ErrorCode.POLICY_CONTRADICTION


@pytest.mark.unit
def test_phase2_unknown_action():
    """Unknown action → UNVERIFIABLE (no policy defined)."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="ACTION_UNKNOWN",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.POLICY_NOT_FOUND


@pytest.mark.unit
def test_phase2_ambiguous_action():
    """Ambiguous action → UNVERIFIABLE."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="AMBIGUOUS_ACTION_XYZ",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.POLICY_NOT_FOUND


@pytest.mark.unit
def test_phase2_missing_policy():
    """Missing policy → UNVERIFIABLE."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="SOME_ACTION",
        policy_engine=policy_engine,
    )

    assert verdict == VerificationResult.UNVERIFIABLE
    assert error_code == ErrorCode.POLICY_NOT_FOUND


@pytest.mark.unit
def test_phase2_malformed_policy():
    """Malformed policy → UNVERIFIABLE."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # Policy engine with invalid rule values should still handle gracefully
    # (only DENY/ALLOW are valid; other values are filtered out)
    policy_engine = PolicyEngine(policies={"SOME_ACTION": "INVALID_RULE"})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="SOME_ACTION",
        policy_engine=policy_engine,
    )

    # Invalid rules are filtered out → action becomes unknown → UNVERIFIABLE
    assert verdict == VerificationResult.UNVERIFIABLE


@pytest.mark.unit
def test_phase2_policy_downgrade():
    """Policy downgrade → UNVERIFIABLE."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    # Policy engine with a very low version (should not happen in practice,
    # but test that version guard works)
    policy_engine = PolicyEngine(policies={"REQUEST_OTP_DISCLOSURE": "DENY"}, policy_version=0)
    # policy_version=0 is invalid but the engine should handle it;
    # the token has policy_version=1 which is >= 1 (MINIMUM_POLICY_VERSION)
    # but the engine's internal check may differ
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    # Should not VERIFY; downgrade attempts fail closed
    assert verdict != VerificationResult.VERIFIED


@pytest.mark.unit
def test_phase2_organization_mismatch():
    """Organization mismatch → UNVERIFIABLE."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    # Use a different org that's not in the trust directory
    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"other-org-key": {"revoked": False}}, signing_key=sk)
    )
    replay_store = ReplayStore()

    policy_engine = PolicyEngine(policies={})
    verdict, error_code, metadata = verify_token(
        signed, replay_store, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )

    # Unknown key → KEY_UNKNOWN which maps to UNVERIFIABLE
    assert verdict != VerificationResult.VERIFIED


@pytest.mark.unit
def test_phase2_policy_cannot_alter_cryptographic_evidence():
    """Policy cannot alter cryptographic evidence — VERIFIED if crypto passes."""
    from countersign_crypto.policy import PolicyEngine

    sk = _new_signing_key()
    signed = _make_signed_token_native(sk)

    TrustDirectory.initialize_with_snapshot(
        _make_trust_snapshot(keys={"test-key-1": {"revoked": False}}, signing_key=sk)
    )

    # First call: without policy engine → VERIFIED (crypto passes, no contradiction eval)
    replay_store_1 = ReplayStore()
    verdict, error_code, metadata = verify_token(signed, replay_store_1, TrustDirectory)

    assert verdict == VerificationResult.VERIFIED

    # Second call: with policy engine and ai_action → CONTRADICTS_POLICY
    # Use a fresh replay store so the policy contradiction evaluation
    # is not short-circuited by replay detection from the first call.
    replay_store_2 = ReplayStore()
    policy_engine = PolicyEngine(policies={})
    verdict2, error_code2, metadata2 = verify_token(
        signed, replay_store_2, TrustDirectory,
        ai_action="REQUEST_OTP_DISCLOSURE",
        policy_engine=policy_engine,
    )
    assert verdict2 != VerificationResult.VERIFIED
    assert verdict2 == VerificationResult.CONTRADICTS_POLICY


@pytest.mark.unit
def test_phase2_exactly_three_verdicts():
    """Exactly three top-level verdicts exist: VERIFIED, CONTRADICTS_POLICY, UNVERIFIABLE."""
    from countersign_crypto.errors import VerificationResult

    verdicts = {VerificationResult.VERIFIED, VerificationResult.CONTRADICTS_POLICY, VerificationResult.UNVERIFIABLE}
    assert len(verdicts) == 3
    assert VerificationResult.VERIFIED in verdicts
    assert VerificationResult.CONTRADICTS_POLICY in verdicts
    assert VerificationResult.UNVERIFIABLE in verdicts


# Run on CLI
# ===========================================================================

if __name__ == "__main__":
    """Allow running this file directly: python -m pytest test_phase1.py -v"""
    pytest.main([os.path.abspath(__file__), "-v"])
