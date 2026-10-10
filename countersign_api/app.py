"""Minimal HTTP adapter over the existing COUNTERSIGN verifier."""
from __future__ import annotations

import base64
import itertools
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictStr, model_validator

from countersign_crypto.ai_sensor import MaliciousAISensor
from countersign_crypto.errors import ErrorCode, VerificationResult
from countersign_crypto.policy import PolicyEngine
from countersign_crypto.replay import ReplayStore
from countersign_crypto.verification import verify_from_bytes, verify_token

from .fixtures import DemoTrustDirectory, install_demo_trust, make_fixture


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fixture_id: Optional[StrictStr] = None
    signed_token_b64: Optional[StrictStr] = None

    @model_validator(mode="after")
    def exactly_one_input(self):
        if (self.fixture_id is None) == (self.signed_token_b64 is None):
            raise ValueError("provide exactly one of fixture_id or signed_token_b64")
        return self


app = FastAPI(title="COUNTERSIGN API")
_replay_store = ReplayStore()
_fixture_sequence = itertools.count(1)
_fixture_ids = {"valid", "tampered", "compromised_ai", "contradictory_claim", "ungrounded_ai"}


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    return JSONResponse(status_code=422, content={"detail": "request validation failed"})


@app.get("/health")
def health():
    return {"status": "ok", "service": "countersign"}


def _evidence(meta: dict) -> dict:
    """Expose only verifier-authenticated fields and metadata."""
    if not meta.get("verified_fields") and not meta.get("signed_values"):
        return {"verified_fields": [], "signed_values": {}, "metadata": {}}
    return {
        "verified_fields": list(meta.get("verified_fields", [])),
        "signed_values": dict(meta.get("signed_values", {})),
        "metadata": {key: meta[key] for key in (
            "key_id", "issuer", "jti", "policy_version", "algorithm",
            "directory_version", "verification_time",
        ) if key in meta},
    }


def _response(verdict, error, meta, *, interpretation=None, policy=None):
    labels = {
        VerificationResult.VERIFIED: "The signed request passed the configured verification checks.",
        VerificationResult.CONTRADICTS_POLICY: "The signed request conflicts with deterministic policy.",
        VerificationResult.UNVERIFIABLE: "The request could not be verified.",
    }
    return {
        "request_id": str(uuid.uuid4()),
        "verdict": verdict.name,
        "error_code": error.name if error is not None else None,
        "explanation": labels[verdict],
        "cryptographic_evidence": _evidence(meta),
        "ai_interpretation": interpretation or {"trusted": False, "status": "not_used", "claims": {}},
        "policy": policy or {"evaluated": False, "result": None, "error_code": None},
    }


@app.post("/verify")
def verify(request: VerifyRequest):
    if request.fixture_id is not None:
        if request.fixture_id not in _fixture_ids:
            raise HTTPException(status_code=422, detail="unknown fixture_id")
        install_demo_trust()
        token, raw_text = make_fixture(request.fixture_id, str(next(_fixture_sequence)))
        token = token.model_copy(update={"raw_text": raw_text})
        if request.fixture_id == "compromised_ai":
            sensor = MaliciousAISensor()
        else:
            action = "REQUEST_OTP_DISCLOSURE" if request.fixture_id == "contradictory_claim" else None
            class FixtureSensor:
                def interpret(self, text):
                    if request.fixture_id == "ungrounded_ai":
                        return {"organization": "SyntheticExampleOrg", "requested_action": None,
                                "payment_claim": None, "suspicious_instruction": None,
                                "grounding": {"start": -1, "end": -1, "type": "extraction"},
                                "confidence": 1.0}
                    return {"organization": None, "requested_action": action,
                            "payment_claim": None, "suspicious_instruction": None,
                            "grounding": {"start": 0, "end": len(text), "type": "extraction"},
                            "confidence": 0.5}
            sensor = FixtureSensor()
        result, error, meta = verify_token(
            token, _replay_store, DemoTrustDirectory, ai_sensor=sensor,
            policy_engine=PolicyEngine(),
        )
        output = sensor.interpret(raw_text)
        grounded = False
        from countersign_crypto.ai_sensor import has_supported_grounding
        grounded = has_supported_grounding(raw_text, output)
        interpretation = {"trusted": False, "status": "grounded" if grounded else "ungrounded_or_invalid",
                          "claims": {key: output.get(key) for key in (
                              "organization", "requested_action", "payment_claim", "suspicious_instruction",
                              "confidence", "grounding")}}
        policy_info = {"evaluated": bool(grounded and output.get("requested_action")),
                       "result": None, "error_code": None}
        if grounded and output.get("requested_action"):
            policy_result, policy_error = PolicyEngine().evaluate(
                action=output["requested_action"], organization=token.iss)
            policy_info = {"evaluated": True, "result": policy_result.name,
                           "error_code": policy_error.name if policy_error else None}
        # Policy rejection occurs only after the verifier checks signature/trust.
        # Establish evidence through the existing crypto-only path because the
        # verifier intentionally returns no metadata on policy contradiction.
        if result == VerificationResult.CONTRADICTS_POLICY:
            crypto_result, _, crypto_meta = verify_token(token, ReplayStore(), DemoTrustDirectory)
            if crypto_result == VerificationResult.VERIFIED:
                meta = crypto_meta
        return _response(result, error, meta, interpretation=interpretation, policy=policy_info)

    install_demo_trust()
    try:
        encoded = request.signed_token_b64.encode("ascii")
        base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError):
        raise HTTPException(status_code=422, detail="signed_token_b64 must be valid Base64")
    result, error, meta = verify_from_bytes(encoded, _replay_store, DemoTrustDirectory)
    return _response(result, error, meta)
