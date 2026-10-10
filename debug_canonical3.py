import os, sys, json
sys.path.insert(0, r'.')
from countersign_crypto.models import CountersignToken, SignedCountersignToken
from nacl.signing import SigningKey
import base64
from datetime import datetime, timezone

def _sign_message(sk, message):
    sig = sk.sign(message)
    return base64.b64encode(sig.signature)

def _make_signed_token_native(sk, expires_at=None):
    issued_at_val = 'null'
    not_before_val = 'null'
    expires_at_val = 'null'
    if expires_at is not None:
        expires_at_val = json.dumps(expires_at)

    canonical = (
        f'{{\"version\":1,\"alg\":\"Ed25519\",\"kid\":\"test-key-1\",\"iss\":\"TestOrg\",\"jti\":\"test-jti-123\",\"policy_version\":1,\"amount\":\"4200\",\"currency\":\"INR\",\"payee\":\"merchant@example.test\",\"issued_at\":{issued_at_val},\"not_before\":{not_before_val},\"expires_at\":{expires_at_val}}}'
    )

    signature_b64 = _sign_message(sk, canonical.encode("utf-8"))

    unsigned_token = CountersignToken(
        version=1,
        alg='Ed25519',
        kid='test-key-1',
        iss='TestOrg',
        jti='test-jti-123',
        policy_version=1,
        amount='4200',
        currency='INR',
        payee='merchant@example.test',
        issued_at=None,
        not_before=None,
        expires_at=None,
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
        not_before=unsigned_token.not_before,
        expires_at=unsigned_token.expires_at,
        signature=signature_b64.decode('ascii'),
        signed_canonical=unsigned_token.canonical(),
    )

    return signed, canonical

sk = SigningKey(os.urandom(32))

# Test 1: with expires_at="2020-01-01T00:00:00Z" like the failing tests
signed1, canonical1 = _make_signed_token_native(sk, expires_at="2020-01-01T00:00:00Z")
print('=== With expires_at="2020-01-01T00:00:00Z" ===')
print('Canonical:', canonical1)
print('Canonical len:', len(canonical1))
print('Signed canonical:', signed1.signed_canonical)
print('Signed canonical len:', len(signed1.signed_canonical))
print('Match:', canonical1 == signed1.signed_canonical)
print('Signature len (b64):', len(signed1.signature))
print()

# Test 2: with not_before="2099-01-01T00:00:00Z" like the failing tests
signed2, canonical2 = _make_signed_token_native(sk, not_before="2099-01-01T00:00:00Z")
print('=== With not_before="2099-01-01T00:00:00Z" ===')
print('Canonical:', canonical2)
print('Canonical len:', len(canonical2))
print('Signed canonical:', signed2.signed_canonical)
print('Signed canonical len:', len(signed2.signed_canonical))
print('Match:', canonical2 == signed2.signed_canonical)
print('Signature len (b64):', len(signed2.signature))
print()

# Test 3: with both
signed3, canonical3 = _make_signed_token_native(sk, expires_at="2020-01-01T00:00:00Z", not_before="2099-01-01T00:00:00Z")
print('=== With both expires_at and not_before ===')
print('Canonical:', canonical3)
print('Canonical len:', len(canonical3))
print('Signed canonical:', signed3.signed_canonical)
print('Signed canonical len:', len(signed3.signed_canonical))
print('Match:', canonical3 == signed3.signed_canonical)
print('Signature len (b64):', len(signed3.signature))
print()

# Now test with model sign method
token = CountersignToken(
    version=1,
    alg='Ed25519',
    kid='test-key-1',
    iss='TestOrg',
    jti='test-jti-123',
    policy_version=1,
    amount='4200',
    currency='INR',
    payee='merchant@example.test',
    issued_at=None,
    not_before=None,
    expires_at=None,
)

# Sign with expires_at
token1 = CountersignToken(
    version=1,
    alg='Ed25519',
    kid='test-key-1',
    iss='TestOrg',
    jti='test-jti-123',
    policy_version=1,
    amount='4200',
    currency='INR',
    payee='merchant@example.test',
    issued_at=None,
    not_before=None,
    expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
)
signed1_model = token1.sign(sk)
print('=== Model sign with expires_at datetime ===')
print('Model canonical():', token1.canonical())
print('Signed canonical:', signed1_model.signed_canonical)
print('Match:', token1.canonical() == signed1_model.signed_canonical)
print('Signature len (b64):', len(signed1_model.signature))
print()

# Now test with not_before
token2 = CountersignToken(
    version=1,
    alg='Ed25519',
    kid='test-key-1',
    iss='TestOrg',
    jti='test-jti-123',
    policy_version=1,
    amount='4200',
    currency='INR',
    payee='merchant@example.test',
    issued_at=None,
    not_before=datetime(2099, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
)
signed2_model = token2.sign(sk)
print('=== Model sign with not_before datetime ===')
print('Model canonical():', token2.canonical())
print('Signed canonical:', signed2_model.signed_canonical)
print('Match:', token2.canonical() == signed2_model.signed_canonical)
print('Signature len (b64):', len(signed2_model.signature))