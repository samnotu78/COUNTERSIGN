import base64
import json

from fastapi.testclient import TestClient

from countersign_api import app as app_module
from countersign_api.fixtures import DemoTrustDirectory, install_demo_trust, make_fixture
from countersign_crypto.errors import ErrorCode, VerificationResult
from countersign_crypto.replay import ReplayStore
from countersign_crypto.verification import verify_token


client = TestClient(app_module.app)


def post_fixture(name="valid"):
    return client.post("/verify", json={"fixture_id": name})


def test_health_is_process_liveness():
    assert client.get("/health").json() == {"status": "ok", "service": "countersign"}


def test_valid_fixture_and_evidence_match_verified_values():
    response = post_fixture()
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == VerificationResult.VERIFIED.name
    assert body["error_code"] is None
    assert body["cryptographic_evidence"]["verified_fields"] == ["AMOUNT", "CURRENCY", "PAYEE"]
    assert body["cryptographic_evidence"]["signed_values"] == {
        "AMOUNT": "4200", "CURRENCY": "INR", "PAYEE": "merchant@example.test"
    }
    assert body["cryptographic_evidence"]["metadata"]["issuer"] == "SyntheticExampleOrg"


def test_tampered_fixture_fails_without_fabricated_evidence():
    body = post_fixture("tampered").json()
    assert body["verdict"] != VerificationResult.VERIFIED.name
    assert body["cryptographic_evidence"]["verified_fields"] == []
    assert body["cryptographic_evidence"]["signed_values"] == {}


def test_compromised_ai_cannot_override_crypto_and_domains_are_separate():
    body = post_fixture("compromised_ai").json()
    assert body["verdict"] != VerificationResult.VERIFIED.name
    assert body["ai_interpretation"]["trusted"] is False
    assert "claims" in body["ai_interpretation"]
    assert body["ai_interpretation"]["claims"] != body["cryptographic_evidence"]["signed_values"]


def test_contradictory_claim_preserves_verdict_and_error():
    body = post_fixture("contradictory_claim").json()
    assert body["verdict"] == VerificationResult.CONTRADICTS_POLICY.name
    assert body["error_code"] == ErrorCode.POLICY_CONTRADICTION.name
    assert body["policy"] == {"evaluated": True, "result": "CONTRADICTS_POLICY",
                               "error_code": "POLICY_CONTRADICTION"}


def test_ungrounded_ai_is_unverifiable_without_verified_values():
    body = post_fixture("ungrounded_ai").json()
    assert body["verdict"] == VerificationResult.UNVERIFIABLE.name
    assert body["cryptographic_evidence"]["verified_fields"] == []
    assert body["cryptographic_evidence"]["signed_values"] == {}
    assert body["ai_interpretation"]["trusted"] is False


def test_unknown_fixture_rejected():
    assert client.post("/verify", json={"fixture_id": "unknown"}).status_code == 422


def test_exactly_one_input_required_and_extra_fields_forbidden():
    assert client.post("/verify", json={"fixture_id": "valid", "signed_token_b64": "e30="}).status_code == 422
    assert client.post("/verify", json={}).status_code == 422
    assert client.post("/verify", json={"fixture_id": "valid", "verdict": "VERIFIED"}).status_code == 422
    assert client.post("/verify", json={"fixture_id": 1}).status_code == 422


def test_malformed_base64_and_token_rejected():
    assert client.post("/verify", json={"signed_token_b64": "%%%"}).status_code == 422
    empty_object = base64.b64encode(b"{}").decode()
    token_body = client.post("/verify", json={"signed_token_b64": empty_object}).json()
    assert token_body["verdict"] == VerificationResult.UNVERIFIABLE.name
    assert token_body["error_code"] == ErrorCode.MALFORMED_TOKEN.name


def test_token_mode_calls_existing_crypto_path(monkeypatch):
    install_demo_trust()
    token, _ = make_fixture("valid", "token-mode-test")
    encoded = base64.b64encode(json.dumps(token.model_dump(mode="json")).encode()).decode()
    called = []
    original = app_module.verify_from_bytes

    def tracking(*args, **kwargs):
        called.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(app_module, "verify_from_bytes", tracking)
    response = client.post("/verify", json={"signed_token_b64": encoded})
    assert called == [True]
    assert response.json()["verdict"] == VerificationResult.VERIFIED.name


def test_replay_protection_is_preserved_in_token_mode():
    install_demo_trust()
    token, _ = make_fixture("valid", "replay-test")
    encoded = base64.b64encode(json.dumps(token.model_dump(mode="json")).encode()).decode()
    first = client.post("/verify", json={"signed_token_b64": encoded}).json()
    second = client.post("/verify", json={"signed_token_b64": encoded}).json()
    assert first["verdict"] == VerificationResult.VERIFIED.name
    assert second["verdict"] == VerificationResult.UNVERIFIABLE.name
    assert second["error_code"] == ErrorCode.REPLAY_DETECTED.name


def test_existing_verifier_accepts_fixture_signature_before_replay():
    """Cross-check fixture evidence with the established verifier API."""
    install_demo_trust()
    token, _ = make_fixture("valid", "cross-check")
    result, error, meta = verify_token(token, ReplayStore(), DemoTrustDirectory)
    assert result == VerificationResult.VERIFIED
    assert error is None
    assert meta["signed_values"] == {"AMOUNT": "4200", "CURRENCY": "INR", "PAYEE": "merchant@example.test"}
