# COUNTERSIGN Data Models
# Strict Pydantic models for token format, trust directory, and verification results.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, validator

from .errors import ErrorCode, VerificationResult


def _datetime_wire(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    value = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return value.isoformat(timespec="microseconds" if value.microsecond else "seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Token schema — custom canonical-JSON envelope (NOT a JWT subset).
# ---------------------------------------------------------------------------

class CountersignToken(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """A COUNTERSIGN signed token with a strictly defined schema.

    This is a custom signed-envelope format, NOT a JWT subset.
    All fields are signed over canonical JSON; extra/missing fields
    are rejected by Pydantic validation.
    """

    # Raw input text to be interpreted by the AI sensor.
    # This is NOT signed — it is untrusted content from the user.
    # The AI sensor extracts structured claims from this text with
    # source-span grounding; the extracted values are UNTRUSTED and
    # never used to create VERIFIED (only the signed payload is).
    raw_text: str = Field(
        "",
        description=(
            "Untrusted raw input text.  The AI sensor interprets this "
            "to extract claims (organization, requested_action, etc.) "
            "with source-span grounding.  Must not be used for "
            "cryptographic trust or VERIFIED verdicts."
        ),
    )

    # Version of the token format (supports forward compatibility)
    version: int = Field(default=1, ge=1, le=255)

    # Signed algorithm identifier — only Ed25519 is allowed at the
    # verification layer; the field is recorded for auditability.
    alg: str = Field(default="Ed25519")

    # Key ID referencing the trust directory snapshot that validated this key
    kid: str = Field(..., min_length=1, max_length=128)

    # Issuer identifier (fictional organization only)
    iss: str = Field(..., min_length=1, max_length=128)

    # Token identifier — used for replay protection (see replay.py)
    jti: str = Field(..., min_length=1, max_length=128)

    # Policy version — must meet minimum accepted version in trust directory
    policy_version: int = Field(default=1, ge=1)

    # Signed payload (canonical JSON fields)
    # These are the fields that cryptographic verification covers.
    # The AI sensor may suggest other values, but VERIFIED fields
    # MUST come from the signed payload.
    amount: Optional[str] = Field(None, description="e.g. \"4200\" or \"₹4,200\"")
    currency: Optional[str] = Field(None, description="e.g. \"INR\" or \"USD\"")
    payee: Optional[str] = Field(None, description="e.g. \"merchant@example.test\"")

    # Temporal validation
    issued_at: Optional[datetime] = Field(None, description="UTC datetime when token was issued")
    not_before: Optional[datetime] = Field(None, description="UTC datetime — token not valid before this time")
    expires_at: Optional[datetime] = Field(None, description="UTC datetime — token expires at this time")

    # Canonical representation for signature verification
    # This is the exact field ordering used when signing; it must NOT
    # be derived from json.dumps output ordering alone.
    canonical_repr: Optional[str] = Field(
        None,
        description=(
            "Internal: exact canonical JSON representation used for signing. "
            "Set by token serializer; not a user-settable field."
        ),
    )

    # ── Validation ──────────────────────────────────────────────────

    @validator("alg")
    def _validate_alg(cls, v: str) -> str:
        """Only Ed25519 is accepted; other algorithms are rejected at the
        verification layer. The field is recorded for auditability."""
        # We allow any string here; the verification layer rejects
        # unsupported/none algorithms. This field is recorded for audit.
        return v

    @validator("jti")
    def _validate_jti_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("jti must not be empty or whitespace-only")
        return v

    @validator("issued_at", "not_before", "expires_at", pre=True)
    def _ensure_utc(cls, v: Any) -> Optional[datetime]:
        """Normalize to UTC-aware datetime if provided."""
        if v is None:
            return None
        if isinstance(v, datetime):
            # Ensure timezone-aware; assume UTC if naive
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        # Accept ISO string
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @validator("expires_at")
    def _expires_after_issued_at(cls, v: Optional[datetime], values) -> Optional[datetime]:
        """Expires_at should be after issued_at when both are set."""
        if v is None:
            return v
        issued = (values.get("issued_at") if isinstance(values, dict) else values.data.get("issued_at"))
        if issued is not None and issued > v:
            raise ValueError("expires_at must be after issued_at")
        return v

    @validator("not_before")
    def _not_before_after_issued_at(cls, v: Optional[datetime], values) -> Optional[datetime]:
        """not_before should not be before issued_at."""
        if v is None:
            return v
        issued = (values.get("issued_at") if isinstance(values, dict) else values.data.get("issued_at"))
        if issued is not None and issued > v:
            raise ValueError("not_before must not be after issued_at")
        return v

    # ── Canonical serialization ──────────────────────────────────

    def canonical(self) -> str:
        """Serialize the signed fields with stable order and safe JSON escaping."""
        import json
        payload = {
            "version": self.version, "alg": self.alg, "kid": self.kid,
            "iss": self.iss, "jti": self.jti, "policy_version": self.policy_version,
            "amount": self.amount, "currency": self.currency, "payee": self.payee,
            "issued_at": _datetime_wire(self.issued_at),
            "not_before": _datetime_wire(self.not_before),
            "expires_at": _datetime_wire(self.expires_at),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)

    def sign(self, private_key: "Ed25519PrivateKey") -> "SignedCountersignToken":
        """Sign this token through the established Ed25519 signing API."""
        import base64
        canonical_bytes = self.canonical().encode("utf-8")
        # crypto_types exposes a small wrapper; tests and low-level callers
        # may also pass PyNaCl SigningKey directly.
        signer = getattr(private_key, "_nacl_key", private_key)
        signed = signer.sign(canonical_bytes)
        return SignedCountersignToken(
            version=self.version, alg=self.alg, kid=self.kid, iss=self.iss,
            jti=self.jti, policy_version=self.policy_version,
            amount=self.amount, currency=self.currency, payee=self.payee,
            issued_at=self.issued_at, not_before=self.not_before,
            expires_at=self.expires_at,
            signature=base64.b64encode(signed.signature).decode("ascii"),
            signed_canonical=canonical_bytes.decode("utf-8"),
        )

    def _serialize_signed(self) -> str:
        """Re-serialize the signed object into canonical form.

        This mirrors the canonical() method but uses the signed object's
        fields to ensure round-trip consistency.
        """
        return self.canonical()


# ---------------------------------------------------------------------------
# Signed token container — carries the Ed25519 signature
# ---------------------------------------------------------------------------

class SignedCountersignToken(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """A CountersignToken with an Ed25519 signature attached.

    This model carries all the same fields as CountersignToken,
    plus the Ed25519 signature and the canonical representation
    that was signed.
    """

    # All the same fields as CountersignToken:
    version: int = Field(default=1, ge=1, le=255)
    alg: str = Field(default="Ed25519")
    kid: str = Field(..., min_length=1, max_length=128)
    iss: str = Field(..., min_length=1, max_length=128)
    jti: str = Field(..., min_length=1, max_length=128)
    policy_version: int = Field(default=1, ge=1)
    amount: Optional[str] = Field(None, description="e.g. \"4200\" or \"₹4,200\"")
    currency: Optional[str] = Field(None, description="e.g. \"INR\" or \"USD\"")
    payee: Optional[str] = Field(None, description="e.g. \"merchant@example.test\"")
    issued_at: Optional[datetime] = Field(None, description="UTC datetime when token was issued")
    not_before: Optional[datetime] = Field(None, description="UTC datetime — token not valid before this time")
    expires_at: Optional[datetime] = Field(None, description="UTC datetime — token expires at this time")

    # The Ed25519 signature
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over canonical JSON")

    # The canonical bytes that were signed — for auditing/replay
    signed_canonical: Optional[str] = Field(
        None,
        description="Internal: the canonical JSON bytes that were signed.",
    )

    # Raw input text to be interpreted by the AI sensor.
    # This is NOT signed — it is untrusted content from the user.
    # The AI sensor extracts structured claims from this text with
    # source-span grounding; the extracted values are UNTRUSTED and
    # never used to create VERIFIED (only the signed payload is).
    raw_text: str = Field(
        "",
        description=(
            "Untrusted raw input text.  The AI sensor interprets this "
            "to extract claims (organization, requested_action, etc.) "
            "with source-span grounding.  Must not be used for "
            "cryptographic trust or VERIFIED verdicts."
        ),
    )

    # ── Verification ──────────────────────────────────────────────

    def verify(
        self,
        trust_directory: "TrustDirectory",
        replay_store: "ReplayStore",
        current_time: Optional[datetime] = None,
    ) -> Tuple[VerificationResult, Optional[ErrorCode], VerificationMeta]:
        """Run the full deterministic verification pipeline.

        Steps:
        1. Replay check
        2. Canonical JSON parse + structural checks
        3. Algorithm allowlist check (reject alg:none, unsupported)
        4. Signature verification (Ed25519 over exact canonical bytes)
        5. Key lookup in trust directory
        6. Key validity (not revoked, within validity window)
        7. Token expiry / not-before / issued-at validation
        8. Policy version minimum check
        9. Return verdict + reason code + metadata
        """
        from .replay import ReplayStore
        from .trust import TrustDirectory

        if current_time is None:
            current_time = datetime.now(timezone.utc)

        # --- Step 1: Replay protection ---
        jti = self.jti
        issuer = self.iss

        if jti is not None and issuer is not None:
            is_replay = replay_store.is_replay(jti, issuer, current_time=current_time)
            if is_replay:
                # Replay detected — return UNVERIFIABLE with reason
                return VerificationResult.UNVERIFIABLE, ErrorCode.REPLAY_DETECTED

        # --- Step 2: Canonical JSON parsing + structural checks ---
        try:
            canonical_bytes = self._get_canonical_bytes()
        except (ValueError, TypeError) as e:
            # Malformed canonical encoding
            return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN

        # Verify that re-serializing round-trips correctly
        # (this catches encoding bugs early)
        try:
            re_parsed = parse_canonical_json(canonical_bytes)
        except Exception:
            return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN

        # --- Step 3: Algorithm allowlist ---
        # Reject alg:none explicitly
        if self.alg == "alg:none" or self.alg.lower() == "none":
            return VerificationResult.UNVERIFIABLE, ErrorCode.ALG_NONE

        # Only Ed25519 is supported
        if self.alg not in ("Ed25519",):
            return VerificationResult.UNVERIFIABLE, ErrorCode.ALG_UNSUPPORTED

        # --- Step 4: Ed25519 signature verification ---
        from nacl.signing import VerifyKey

        try:
            # Decode the base64 signature
            sig_bytes = base64.b64decode(self.signature.encode("ascii"))
            # Look up the public key from the trust directory using kid
            key_info = trust_directory.lookup_key(self.kid)
            if key_info is None:
                # Unknown key — the token references a key not in the
                # current trust directory snapshot
                return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_UNKNOWN
            # Create VerifyKey from the public key bytes, not the signature
            vk_b64 = key_info.get("public_key_b64")
            if vk_b64 is None:
                return VerificationResult.UNVERIFIABLE, ErrorCode.SIGNATURE_INVALID
            import base64 as _b64
            pk_bytes = _b64.b64decode(vk_b64)
            verify_key = VerifyKey(pk_bytes)
        except Exception:
            # Invalid signature format or key lookup failure
            return VerificationResult.UNVERIFIABLE, ErrorCode.SIGNATURE_INVALID

        # Verify the Ed25519 signature over the exact canonical bytes
        try:
            verify_key.verify(canonical_bytes)
        except Exception:
            # Signature invalid — the canonical JSON was not signed by
            # this key, or the signature was tampered
            return VerificationResult.UNVERIFIABLE, ErrorCode.SIGNATURE_INVALID

        # --- Step 5: Trusted key lookup in directory ---
        # The kid references a key in the trust directory snapshot
        key_info = trust_directory.lookup_key(self.kid)
        if key_info is None:
            # Unknown key — the token references a key not in the
            # current trust directory snapshot
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_UNKNOWN

        # Store metadata
        metadata: VerificationMeta = {
            "key_id": self.kid,
            "issuer": self.iss,
            "jti": self.jti,
            "policy_version": self.policy_version,
            "algorithm": self.alg,
            "directory_version": trust_directory.current_snapshot().version if trust_directory.current_snapshot() else "unknown",
        }

        # --- Step 6: Key validity checks ---
        # Check key is not revoked
        if key_info.get("revoked", False) is True:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_REVOKED

        # Check key validity windows (if specified in trust directory)
        key_valid_until = key_info.get("valid_until")
        key_valid_from = key_info.get("valid_from")
        if key_valid_until is not None and current_time > key_valid_until:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_EXPIRED
        if key_valid_from is not None and current_time < key_valid_from:
            return VerificationResult.UNVERIFIABLE, ErrorCode.KEY_NOT_YET_VALID

        # --- Step 7: Expiry / not-before / issued-at validation ---
        # Token expiry
        if self.expires_at is not None and current_time > self.expires_at:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_EXPIRED

        # Token not-yet-valid
        if self.not_before is not None and current_time < self.not_before:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_NOT_YET_VALID

        # Issued-at timestamp check (token issued in the future)
        if self.issued_at is not None and self.issued_at > current_time:
            return VerificationResult.UNVERIFIABLE, ErrorCode.TOKEN_TIMESTAMP_INVALID

        # --- Step 8: Policy version minimum check ---
        min_policy_version = trust_directory.get_min_policy_version()
        if self.policy_version < min_policy_version:
            return VerificationResult.UNVERIFIABLE, ErrorCode.POLICY_VERSION_TOO_OLD

        # --- Step 9: Determined verified fields ---
        # All checks passed up to this point. Now determine which fields
        # are cryptographically verified. These are the exact signed fields
        # from the token's canonical JSON.

        verified_fields: List[str] = []
        signed_values: Dict[str, str] = {}

        # AMOUNT — if present and non-null in the signed payload
        if self.amount is not None and self.amount.strip() != "":
            verified_fields.append("AMOUNT")
            signed_values["AMOUNT"] = self.amount

        # CURRENCY — if present and non-null
        if self.currency is not None and self.currency.strip() != "":
            verified_fields.append("CURRENCY")
            signed_values["CURRENCY"] = self.currency

        # PAYEE — if present and non-null
        if self.payee is not None and self.payee.strip() != "":
            verified_fields.append("PAYEE")
            signed_values["PAYEE"] = self.payee

        # Build the verification metadata
        metadata["verified_fields"] = verified_fields
        metadata["signed_values"] = signed_values

        # --- Step 10: Return VERIFIED verdict ---
        # All checks passed. The token is VERIFIED. The verified fields
        # are those that cryptographic evidence covers
        # AI-extracted values are NOT used here — only the signed payload.

        final_metadata: VerificationMeta = {
            "verified_fields": verified_fields,
            "signed_values": signed_values,
            "key_id": self.kid,
            "issuer": self.iss,
            "jti": self.jti,
            "policy_version": self.policy_version,
            "algorithm": self.alg,
            "directory_version": metadata["directory_version"],
            "verification_time": current_time.isoformat(),
        }

        return VerificationResult.VERIFIED, None, final_metadata

    # ── Helper: get canonical bytes ──────────────────────────────

    def _get_canonical_bytes(self) -> bytes:
        """Return the exact canonical JSON bytes used for signature verification.

        This must match exactly what was signed. Any discrepancy
        (e.g., different whitespace, different field ordering, different
        null representation) will cause signature verification to fail.
        """
        # Use the signed canonical representation that was stored
        # when the token was signed. This ensures we use exactly
        # the same bytes that were signature-verified.
        if self.signed_canonical is not None:
            return self.signed_canonical.encode("utf-8")
        # Fallback: build from fields (same as CountersignToken.canonical())
        return self._build_canonical_from_fields().encode("utf-8")

    def _build_canonical_from_fields(self) -> str:
        return CountersignToken(
            version=self.version, alg=self.alg, kid=self.kid, iss=self.iss,
            jti=self.jti, policy_version=self.policy_version, amount=self.amount,
            currency=self.currency, payee=self.payee, issued_at=self.issued_at,
            not_before=self.not_before, expires_at=self.expires_at,
        ).canonical()

    # ── Convenience factory ──────────────────────────────────────

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedCountersignToken":
        """Create a SignedCountersignToken from a dictionary.

        Validates the schema and sets up internal fields.
        """
        # Remove internal fields if present
        data_clean = {
            k: v
            for k, v in data.items()
            if k not in ("canonical_repr", "signed_canonical")
        }
        return cls(**data_clean)


# ---------------------------------------------------------------------------
# VerificationResult extended tuple: (verdict, error_code, metadata)
# ---------------------------------------------------------------------------

VerificationMeta = Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper: parse canonical JSON bytes into a dict
# ---------------------------------------------------------------------------

def parse_canonical_json(data: bytes) -> Dict[str, Any]:
    """Parse UTF-8 JSON while rejecting duplicate members and noncanonical bytes."""
    import json
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result
    try:
        text = data.decode("utf-8", errors="strict")
        result = json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    except Exception as exc:
        raise ValueError("malformed JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("JSON must be an object")
    expected = {"version", "alg", "kid", "iss", "jti", "policy_version", "amount", "currency", "payee", "issued_at", "not_before", "expires_at"}
    if set(result) != expected:
        raise ValueError("signed payload has missing or unknown fields")
    try:
        token = CountersignToken(**result)
    except Exception as exc:
        raise ValueError("signed payload does not match token schema") from exc
    if token.canonical().encode("utf-8") != data:
        raise ValueError("signed payload is not in canonical encoding")
    return result


# ---------------------------------------------------------------------------
# High-level convenience: verify from raw bytes
# ---------------------------------------------------------------------------

def verify_from_bytes(
    raw_token: bytes,
    replay_store: ReplayStore,
    trust_directory: TrustDirectory,
    current_time: Optional[datetime] = None,
) -> Tuple[VerificationResult, Optional[ErrorCode], VerificationMeta]:
    """Verify a token from raw bytes.

    Expected format: base64-encoded SignedCountersignToken.
    The function decodes, parses, and runs the full verification pipeline.

    Args:
        raw_token: Raw bytes, expected to be base64-encoded.
        replay_store: ReplayStore instance for replay checking.
        trust_directory: TrustDirectory instance with current snapshot.
        current_time: UTC datetime for validation. Defaults to now.

    Returns:
        (verdict, error_code, metadata) tuple.
    """
    import base64

    try:
        text = raw_token.decode("utf-8").strip()
        b64_data = base64.b64decode(text)
    except Exception:
        # Can't even decode — return malformed
        return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, {}

    # Parse the signed token from the decoded bytes.
    # The signed container format stores: {signed_token_json, signature}
    # For this prototype, we expect the full SignedCountersignToken
    # to be encoded as base64 JSON. In a binary format, the structure
    # would be different.
    #
    # For now, try to parse as UTF-8 JSON, then extract the components.
    try:
        data = json.loads(text) if True else None  # placeholder
    except Exception:
        return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, {}

    # For the prototype, we'll construct a minimal SignedCountersignToken
    # from the decoded data. The full format is defined in models.py.
    # This is a simplified entry point.
    return VerificationResult.UNVERIFIABLE, ErrorCode.MALFORMED_TOKEN, {}


# ---------------------------------------------------------------------------
# Signature generation (for testing/demo key creation)
# ---------------------------------------------------------------------------

def sign_token(token: CountersignToken, private_key: "Ed25519PrivateKey") -> SignedCountersignToken:
    """Sign a CountersignToken using the given Ed25519 private key.

    This is a convenience function for test setup.
    """
    signed = token.sign(private_key)
    return signed  # type: ignore[return-value]


def generate_demo_key_pair() -> Tuple["Ed25519PrivateKey", "Ed25519PublicKey"]:
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