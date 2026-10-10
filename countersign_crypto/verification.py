# COUNTERSIGN Verification Module
# Deterministic verification pipeline — the core trust boundary.

# This module implements the fail-closed verification pipeline that:
# - Has zero dependency on any LLM/AI output
# - Operates only on deterministic inputs
# - Produces exactly three verdicts: VERIFIED / CONTRADICTS_POLICY / UNVERIFIABLE
# - All cryptographic/trust failures → UNVERIFIABLE with closed reason code
# - Never produces VERIFIED when any error is present

from __future__ import annotations

import base64 as _b64mod
import json

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .ai_sensor import AIOutput, DeterministicAISensor, _abstain, has_supported_grounding
from .errors import ErrorCode, VerificationResult
from .models import CountersignToken, SignedCountersignToken, parse_canonical_json
from .policy import PolicyEngine
from .replay import ReplayStore
from .trust import TrustDirectory, TrustDirectorySnapshot
from .crypto_types import Ed25519PrivateKey, Ed25519PublicKey


# ---------------------------------------------------------------------------
# VerificationResult extended tuple: (verdict, error_code, metadata)
# ---------------------------------------------------------------------------

VerificationMeta = Dict[str, Any]


def verify_token(token: SignedCountersignToken, replay_store: ReplayStore,
                 trust_directory: TrustDirectory, current_time: Optional[datetime] = None,
                 ai_action: Optional[str] = None, policy_engine: Optional[PolicyEngine] = None,
                 ai_sensor: Optional[DeterministicAISensor] = None
                 ) -> Tuple[VerificationResult, Optional[ErrorCode], VerificationMeta]:
    """Verify signed evidence fail-closed; optional AI is policy-only input."""
    now = current_time or datetime.now(timezone.utc)
    meta: VerificationMeta = {"verified_fields": [], "signed_values": {}}
    try:
        if not isinstance(token, SignedCountersignToken):
            return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, meta
        raw = token._get_canonical_bytes()
        signed = parse_canonical_json(raw)
        expected = {"version": token.version, "alg": token.alg, "kid": token.kid,
                    "iss": token.iss, "jti": token.jti, "policy_version": token.policy_version,
                    "amount": token.amount, "currency": token.currency, "payee": token.payee}
        if any(signed[k] != v for k, v in expected.items()):
            return VerificationResult.UNVERIFIABLE, ErrorCode.INVALID_CANONICAL_ENCODING, meta
        for name in ("issued_at", "not_before", "expires_at"):
            dt = getattr(token, name)
            wire = None if dt is None else (dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat(timespec="microseconds" if dt.microsecond else "seconds").replace("+00:00", "Z")
            if signed[name] != wire:
                return VerificationResult.UNVERIFIABLE, ErrorCode.INVALID_CANONICAL_ENCODING, meta
        if token.alg.lower() == "none" or token.alg == "alg:none":
            return VerificationResult.UNVERIFIABLE, ErrorCode.ALG_NONE, meta
        if token.alg != "Ed25519":
            return VerificationResult.UNVERIFIABLE, ErrorCode.ALG_UNSUPPORTED, meta
        snapshot = trust_directory.current_snapshot()
        reason = trust_directory.directory_rejected_reason(snapshot, now)
        if reason:
            return VerificationResult.UNVERIFIABLE, reason, meta
        entry = snapshot.lookup_key(token.kid)
        if entry is None:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_UNKNOWN, meta
        if entry["trusted_organization"] != token.iss:
            return VerificationResult.UNVERIFIABLE, ErrorCode.DIRECTORY_NOT_TRUSTED, meta
        from nacl.signing import VerifyKey
        public = _b64mod.b64decode(entry["public_key_b64"], validate=True)
        signature = _b64mod.b64decode(token.signature.encode("ascii"), validate=True)
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("bad key or signature length")
        VerifyKey(public).verify(raw, signature)
        if entry["revoked"]:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_REVOKED, meta
        if entry["valid_from"] is not None and now < entry["valid_from"]:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_NOT_YET_VALID, meta
        if entry["valid_until"] is not None and now >= entry["valid_until"]:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_EXPIRED, meta
        if token.expires_at is not None and now >= token.expires_at:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_EXPIRED, meta
        if token.not_before is not None and now < token.not_before:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_NOT_YET_VALID, meta
        if token.issued_at is not None and token.issued_at > now:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_TIMESTAMP_INVALID, meta
        if token.policy_version < snapshot.get_min_policy_version():
            return VerificationResult.UNVERIFIABLE, ErrorCode.POLICY_VERSION_TOO_OLD, meta
        action = ai_action
        if action is None and ai_sensor is not None and token.raw_text:
            try:
                output = ai_sensor.interpret(token.raw_text)
                allowed = {"organization", "requested_action", "payment_claim", "suspicious_instruction", "grounding", "confidence"}
                if not isinstance(output, dict) or set(output) - allowed:
                    raise ValueError("malformed sensor output")
                if not has_supported_grounding(token.raw_text, output):
                    return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, meta
                action = output.get("requested_action")
            except Exception:
                return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, meta
        if action is not None and policy_engine is not None:
            policy_result, policy_error = policy_engine.evaluate(action=action, organization=token.iss)
            if policy_result != VerificationResult.VERIFIED:
                return policy_result, policy_error, meta
        # Reserve only after all cryptographic, identity, freshness and policy checks.
        if replay_store.check_and_record(token.jti, token.iss, now):
            return VerificationResult.UNVERIFIABLE, ErrorCode.REPLAY_DETECTED, meta
        labels = (("amount", "AMOUNT"), ("currency", "CURRENCY"), ("payee", "PAYEE"))
        fields, values = [], {}
        for name, label in labels:
            value = signed[name]
            if value is not None and value.strip():
                fields.append(label)
                values[label] = value
        meta = {"verified_fields": fields, "signed_values": values, "key_id": token.kid,
                "issuer": token.iss, "jti": token.jti, "policy_version": token.policy_version,
                "algorithm": token.alg, "directory_version": snapshot.version,
                "verification_time": now.isoformat()}
        return VerificationResult.VERIFIED, None, meta
    except Exception:
        return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, meta


# ---------------------------------------------------------------------------
# Helper: parse canonical JSON bytes into a dict
# ---------------------------------------------------------------------------

def parse_canonical_json(data: bytes) -> Dict[str, Any]:
    from .models import parse_canonical_json as strict_parse
    return strict_parse(data)


# ---------------------------------------------------------------------------
# High-level convenience: verify from raw bytes
# ---------------------------------------------------------------------------

def verify_from_bytes(raw_token: bytes, replay_store: ReplayStore,
                     trust_directory: TrustDirectory,
                     current_time: Optional[datetime] = None
                     ) -> Tuple[VerificationResult, Optional[ErrorCode], VerificationMeta]:
    """Decode a base64 encoded JSON envelope then use the same verifier."""
    empty = {"verified_fields": [], "signed_values": {}}
    try:
        decoded = _b64mod.b64decode(raw_token, validate=True)
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out:
                    raise ValueError("duplicate envelope member")
                out[key] = value
            return out
        data = json.loads(decoded.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        if not isinstance(data, dict):
            raise ValueError("envelope must be an object")
        allowed = set(SignedCountersignToken.model_fields)
        if set(data) - allowed or not {"signature", "kid", "iss", "jti"}.issubset(data):
            raise ValueError("envelope schema mismatch")
        token = SignedCountersignToken(**data)
        return verify_token(token, replay_store, trust_directory, current_time=current_time)
    except Exception:
        return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, empty


# ---------------------------------------------------------------------------
# Signature generation (for testing/demo key creation)
# ---------------------------------------------------------------------------

def sign_token(token: CountersignToken, private_key: Ed25519PrivateKey) -> SignedCountersignToken:
    """Sign a CountersignToken using the given Ed25519 private key.

    This is a convenience function for test setup.
    """
    signed = token.sign(private_key)
    return signed  # type: ignore[return-value]


def generate_demo_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair for demo/test use.

    Returns:
        (private_key, public_key) tuple.
    """
    from nacl.signing import SigningKey

    signing_key = SigningKey()
    private_key = Ed25519PrivateKey(signing_key)
    # Extract the public key bytes
    from nacl.public import PrivateKey as NaclPrivateKey
    nkl_priv = NaclPrivateKey(bytes(private_key))
    pub_bytes = nkl_priv.public_key
    from .crypto_types import Ed25519PublicKey as ETPublicKey
    public_key = ETPublicKey(pub_bytes)
    return private_key, public_key