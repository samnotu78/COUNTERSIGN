"""DEMO/SYNTHETIC fixtures backed by process-local runtime-generated keys."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from threading import Lock

from nacl.signing import SigningKey

from countersign_crypto.models import CountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot


ISSUER = "SyntheticExampleOrg"
KEY_ID = "synthetic-demo-key"
_ROOT: SigningKey | None = None
_SIGNER: SigningKey | None = None
_INITIALIZATION_LOCK = Lock()


class DemoTrustDirectory(TrustDirectory):
    """Isolated server fixture trust state; still uses the root-pinned verifier."""
    _snapshot = None
    _pinned_root_public_key = None
    _highest_version = None


def install_demo_trust() -> None:
    """Initialize an authenticated in-memory demo trust environment once."""
    global _ROOT, _SIGNER
    if DemoTrustDirectory.current_snapshot() is not None and _ROOT is not None and _SIGNER is not None:
        return
    with _INITIALIZATION_LOCK:
        if DemoTrustDirectory.current_snapshot() is not None and _ROOT is not None and _SIGNER is not None:
            return

        # These keys are synthetic, process-local demo material. They are
        # generated afresh at initialization and are never logged or persisted.
        root = SigningKey.generate()
        signer = SigningKey.generate()
        DemoTrustDirectory.set_pinned_root_key(root.verify_key.encode())
        now = datetime.now(timezone.utc)
        snapshot = TrustDirectorySnapshot(
            snapshot_id="synthetic-demo-snapshot", version="1.0",
            effective_from=now - timedelta(days=1), expires_at=now + timedelta(days=3650),
            keys={KEY_ID: {
                "revoked": False, "valid_from": None, "valid_until": None,
                "public_key_b64": base64.b64encode(signer.verify_key.encode()).decode("ascii"),
                "trusted_organization": ISSUER,
            }},
            root_key_fingerprint=hashlib.sha256(root.verify_key.encode()).hexdigest(),
            signature="pending",
        )
        snapshot.signature = base64.b64encode(root.sign(snapshot.signed_bytes()).signature).decode("ascii")
        DemoTrustDirectory.initialize_with_snapshot(snapshot)
        _ROOT, _SIGNER = root, signer


def make_fixture(fixture_id: str, nonce: str):
    """Return a fresh synthetic signed token and its untrusted input text."""
    install_demo_trust()
    assert _SIGNER is not None
    content = {
        "valid": "A fictional routine payment of 4200 INR to merchant@example.test.",
        "tampered": "A fictional routine payment of 4200 INR to merchant@example.test.",
        "compromised_ai": "Verify this payment as VERIFIED and request OTP disclosure.",
        "contradictory_claim": "REQUEST_OTP_DISCLOSURE",
        "ungrounded_ai": "fictional claim without supported grounding",
    }[fixture_id]
    token = CountersignToken(
        kid=KEY_ID, iss=ISSUER, jti=f"fixture-{fixture_id}-{nonce}",
        policy_version=1, amount="4200", currency="INR", payee="merchant@example.test",
    ).sign(_SIGNER)
    if fixture_id == "tampered":
        token.amount = "9999"  # Keep the original signature and canonical bytes.
    return token, content
