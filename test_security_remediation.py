"""Regression tests for the backend security remediation pass."""
from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from nacl.signing import SigningKey

from countersign_crypto.errors import ErrorCode, VerificationResult
from countersign_crypto.models import CountersignToken, SignedCountersignToken, parse_canonical_json
from countersign_crypto.policy import PolicyEngine
from countersign_crypto.replay import ReplayStore
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.verification import verify_token, verify_from_bytes


ROOT = SigningKey(bytes.fromhex("9a" * 32))
NOW = datetime.now(timezone.utc)


def snapshot(*, key: SigningKey | None = None, issuer="TestOrg", version="2.0",
             effective=None, expires=None):
    key = key or SigningKey.generate()
    TrustDirectory._snapshot = None
    TrustDirectory._highest_version = None
    TrustDirectory.set_pinned_root_key(ROOT.verify_key.encode())
    obj = TrustDirectorySnapshot(
        snapshot_id="remediation-snapshot", version=version,
        effective_from=effective or NOW - timedelta(minutes=1),
        expires_at=expires or NOW + timedelta(days=5),
        keys={"key-1": {"revoked": False, "valid_from": None, "valid_until": None,
                        "public_key_b64": base64.b64encode(key.verify_key.encode()).decode(),
                        "trusted_organization": issuer}},
        root_key_fingerprint=hashlib.sha256(ROOT.verify_key.encode()).hexdigest(), signature="pending")
    obj.signature = base64.b64encode(ROOT.sign(obj.signed_bytes()).signature).decode()
    TrustDirectory.initialize_with_snapshot(obj)
    return obj, key


def token(key, *, issuer="TestOrg", jti="jti-1", amount='4"2\\00', payee="merchant@example.test", expiry=None):
    value = CountersignToken(kid="key-1", iss=issuer, jti=jti, amount=amount,
                             currency="INR", payee=payee, expires_at=expiry)
    return value.sign(key)


def check(signed, replay=None, **kwargs):
    return verify_token(signed, replay or ReplayStore(), TrustDirectory, current_time=NOW, **kwargs)


def test_valid_root_signed_directory_and_payload_mutation_rejected():
    obj, key = snapshot()
    assert TrustDirectory.verify_directory_signature(obj)
    obj.keys["key-1"]["trusted_organization"] = "Attacker"
    assert not TrustDirectory.verify_directory_signature(obj)
    result = check(token(key))
    assert result[0] == VerificationResult.UNVERIFIABLE


@pytest.mark.parametrize("case,expected", [
    ("expired", ErrorCode.DIRECTORY_EXPIRED),
    ("future", ErrorCode.DIRECTORY_NOT_YET_ACTIVE),
])
def test_directory_freshness(case, expected):
    kwargs = ({"expires": NOW - timedelta(seconds=1)} if case == "expired"
              else {"effective": NOW + timedelta(seconds=1)})
    _, key = snapshot(**kwargs)
    assert check(token(key))[1] == expected


def test_invalid_directory_signature_and_unknown_root_fail_closed():
    obj, key = snapshot()
    obj.signature = base64.b64encode(b"x" * 64).decode()
    assert check(token(key))[1] == ErrorCode.DIRECTORY_SIGNATURE_INVALID
    obj, key = snapshot()
    TrustDirectory.set_pinned_root_key(SigningKey.generate().verify_key.encode())
    assert check(token(key))[1] == ErrorCode.DIRECTORY_SIGNATURE_INVALID


def test_directory_version_downgrade_rejected():
    _, key = snapshot(version="3.0")
    prior = TrustDirectory._highest_version
    old = TrustDirectorySnapshot(snapshot_id="old", version="2.0", effective_from=NOW-timedelta(days=1),
        expires_at=NOW+timedelta(days=1), keys=TrustDirectory.current_snapshot().keys,
        root_key_fingerprint=TrustDirectory.get_pinned_root_fingerprint(), signature="pending")
    old.signature = base64.b64encode(ROOT.sign(old.signed_bytes()).signature).decode()
    TrustDirectory._highest_version = prior
    assert TrustDirectory.directory_rejected_reason(old, NOW) == ErrorCode.DIRECTORY_VERSION_DOWNGRADE


def test_issuer_binding_blocks_valid_signature_with_wrong_issuer():
    _, key = snapshot(issuer="TrustedOrg")
    result = check(token(key, issuer="OtherOrg"))
    assert result[:2] == (VerificationResult.UNVERIFIABLE, ErrorCode.DIRECTORY_NOT_TRUSTED)


def test_invalid_signature_does_not_poison_replay_and_valid_redemption_is_atomic():
    _, key = snapshot()
    valid = token(key, jti="poison-target")
    bad = valid.model_copy(update={"signature": base64.b64encode(b"z" * 64).decode()})
    replay = ReplayStore()
    assert check(bad, replay)[0] == VerificationResult.UNVERIFIABLE
    assert replay.entry_count() == 0
    assert check(valid, replay)[0] == VerificationResult.VERIFIED
    assert check(valid, replay)[1] == ErrorCode.REPLAY_DETECTED


def test_expired_token_does_not_poison_replay():
    _, key = snapshot()
    replay = ReplayStore()
    bad = token(key, jti="expiry-target", expiry=NOW-timedelta(seconds=1))
    assert check(bad, replay)[1] == ErrorCode.TOKEN_EXPIRED
    assert replay.entry_count() == 0


def test_concurrent_valid_redemption_only_succeeds_once():
    _, key = snapshot()
    replay = ReplayStore()
    signed = token(key, jti="concurrent-target")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: check(signed, replay)[0], range(12)))
    assert results.count(VerificationResult.VERIFIED) == 1
    assert results.count(VerificationResult.UNVERIFIABLE) == 11


@pytest.mark.parametrize("value", ['quote"value', r"back\\slash", "control\nchar", "Unicode e\u0301 / \u202e"])
def test_hostile_strings_round_trip_with_one_safe_canonical_encoder(value):
    _, key = snapshot()
    signed = token(key, jti="hostile-" + str(abs(hash(value))), amount=value)
    assert check(signed)[0] == VerificationResult.VERIFIED
    assert check(signed)[2]["signed_values"]["AMOUNT"] == value


def test_duplicate_keys_whitespace_and_unknown_payload_fields_rejected():
    canonical = CountersignToken(kid="key-1", iss="TestOrg", jti="j", amount="1").canonical()
    with pytest.raises(ValueError):
        parse_canonical_json(canonical[:-1] + ',"amount":"2"}')
    with pytest.raises(ValueError):
        parse_canonical_json((" " + canonical).encode())
    with pytest.raises(ValueError):
        parse_canonical_json(canonical[:-1] + ',"extra":1}')


def test_signed_payload_and_outer_fields_must_match_and_bytes_entrypoint_fails_closed():
    _, key = snapshot()
    signed = token(key)
    tampered = signed.model_copy(update={"amount": "999"})
    assert check(tampered)[0] == VerificationResult.UNVERIFIABLE
    result = verify_from_bytes(b"not-base64", ReplayStore(), TrustDirectory, current_time=NOW)
    assert result[0] == VerificationResult.UNVERIFIABLE


class MaliciousSensor:
    def __init__(self, output=None, raises=False): self.output, self.raises = output, raises
    def interpret(self, text):
        if self.raises: raise RuntimeError("sensor failure")
        return self.output


@pytest.mark.parametrize("output", [
    {"verdict": "VERIFIED"},
    {"organization": "TrustedOrg", "payment_claim": {"amount": "999", "payee": "evil", "currency": "USD"}, "grounding": {"start": 0, "end": 2}},
    {"requested_action": "REQUEST_OTP_DISCLOSURE", "grounding": None},
])
def test_malformed_or_untrusted_sensor_output_never_creates_verified(output):
    _, key = snapshot()
    signed = token(key, jti="sensor-case").model_copy(update={"raw_text": "hello world"})
    result = check(signed, ai_sensor=MaliciousSensor(output), policy_engine=PolicyEngine())
    assert result[0] == VerificationResult.UNVERIFIABLE


def test_ai_amount_payee_and_identity_cannot_override_signed_claims():
    _, key = snapshot()
    source = "AttackerOrg claims amount 999 payee evil currency USD"
    signed = token(key, jti="ai-inert").model_copy(update={"raw_text": source})
    output = {"organization": "AttackerOrg", "payment_claim": {"amount": "999", "payee": "evil", "currency": "USD"},
              "grounding": {"start": 0, "end": len(source)}}
    result = check(signed, ai_sensor=MaliciousSensor(output))
    assert result[0] == VerificationResult.VERIFIED
    assert result[2]["signed_values"]["AMOUNT"] == '4"2\\00'
    assert result[2]["signed_values"]["PAYEE"] == "merchant@example.test"



def test_in_range_but_unrelated_grounding_is_unverifiable():
    _, key = snapshot()
    source = "hello world"
    signed = token(key, jti="unrelated-grounding").model_copy(update={"raw_text": source})
    output = {"organization": "TrustedOrg", "payment_claim": {"amount": "999", "payee": "evil", "currency": "USD"},
              "grounding": {"start": 0, "end": 2}}
    assert check(signed, ai_sensor=MaliciousSensor(output))[0] == VerificationResult.UNVERIFIABLE


def test_grounded_no_action_claims_do_not_downgrade_crypto_verification():
    _, key = snapshot()
    source = "TrustedOrg payment amount 999 payee evil currency USD"
    signed = token(key, jti="grounded-no-action").model_copy(update={"raw_text": source})
    output = {"organization": "TrustedOrg", "payment_claim": {"amount": "999", "payee": "evil", "currency": "USD"},
              "requested_action": None, "grounding": {"start": 0, "end": len(source)}}
    result = check(signed, ai_sensor=MaliciousSensor(output))
    assert result[0] == VerificationResult.VERIFIED
    assert result[2]["signed_values"]["AMOUNT"] == '4"2\\00'
    assert result[2]["signed_values"]["PAYEE"] == "merchant@example.test"


def test_valid_crypto_without_ai_remains_verified():
    _, key = snapshot()
    assert check(token(key, jti="without-ai"))[0] == VerificationResult.VERIFIED


def test_sensor_exception_abstains_without_creating_trust():
    _, key = snapshot()
    signed = token(key, jti="ai-error").model_copy(update={"raw_text": "hello"})
    result = check(signed, ai_sensor=MaliciousSensor(raises=True))
    assert result[0] == VerificationResult.UNVERIFIABLE

