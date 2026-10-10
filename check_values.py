#!/usr/bin/env python3
"""Check the exact values in the verification pipeline"""

import os, sys
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from nacl.signing import SigningKey, VerifyKey
import base64, uuid

# Create key pair
sk = SigningKey(os.urandom(32))
vk = sk.verify_key

# Build token using _make_signed_token_native logic
kid = 'test-key-1'
iss = 'TestOrg'
jti = str(uuid.uuid4())
amount = '4200'
currency = 'INR'
payee = 'merchant@example.test'
policy_version = 1

# Build canonical JSON (same as _make_signed_token_native)
canonical = (
    f'{{\"version\":1,\"alg\":\"Ed25519\",\"kid\":\"{kid}\",\"iss\":\"{iss}\"'
    f',\"jti\":\"{jti}\",\"policy_version\":{policy_version}'
    f',\"amount\":\"{amount}\",\"currency\":\"{currency}\",\"payee\":\"{payee}\"'
    f',\"issued_at\":null,\"not_before\":null,\"expires_at\":null}}'
)

# Sign it
signature_b64 = base64.b64encode(sk.sign(canonical.encode('utf-8')).signature).decode('ascii')

# Construct unsigned token
unsigned_token = CountersignToken(
    version=1, alg='Ed25519', kid=kid, iss=iss,
    jti=jti, policy_version=policy_version, amount=amount, currency=currency, payee=payee,
    issued_at=None, not_before=None, expires_at=None,
)

# Construct signed token
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
    signature=signature_b64,
    signed_canonical=unsigned_token.canonical(),
)

# Check all the key values
print('=== Signed Token Values ===')
print(f'kid: {signed.kid}')
print(f'alg: {signed.alg}')
print(f'version: {signed.version}')
print(f'amount: {signed.amount}')
print(f'currency: {signed.currency}')
print(f'payee: {signed.payee}')
print(f'signature (first 30 chars): {signed.signature[:30]}')
print(f'signed_canonical (first 60 chars): {signed.signed_canonical[:60]}')
print()

# Check _get_canonical_bytes()
canonical_bytes = signed._get_canonical_bytes()
print('=== Canonical Bytes ===')
print(f'_get_canonical_bytes(): {canonical_bytes.decode("utf-8")}')
print(f'signed_canonical.encode(): {signed.signed_canonical.encode("utf-8").decode("utf-8")}')
print(f'Match: {canonical_bytes.decode("utf-8") == signed.signed_canonical.encode("utf-8")}')
print()

# Now check what verify_token would do
# Step 2: canonical_bytes = token._get_canonical_bytes()
# Step 4: Look up key
snap = TrustDirectorySnapshot(
    snapshot_id='test',
    version='1.0',
    keys={
        'test-key-1': {
            'revoked': False,
            'valid_from': None,
            'valid_until': None,
            'public_key_b64': base64.b64encode(vk.encode()).decode('ascii'),
        }
    },
    root_key_fingerprint='TEST',
    signature='',
)
TrustDirectory.initialize_with_snapshot(snap)

# Step 3: Algorithm check
print(f'Algorithm: {signed.alg}')
print(f'Ed25519 check: {signed.alg == "Ed25519"}')

# Step 4: Key lookup
key_info = snap.lookup_key('test-key-1')
print(f'Key info: {key_info}')
pub_key_b64 = key_info.get('public_key_b64')
print(f'pub_key_b64: {pub_key_b64}')

# Create VerifyKey
pk_bytes = base64.b64decode(pub_key_b64)
verify_key = VerifyKey(pk_bytes)
print(f'VerifyKey created successfully')

# Step 4b: Verify signature
sig_b64 = signed.signature.encode('ascii')
sig_bytes = base64.b64decode(sig_b64)
print(f'sig_bytes length: {len(sig_bytes)}')

print(f'\\n=== Verification ===')
try:
    verify_key.verify(canonical_bytes, sig_bytes)
    print('SIGNATURE VALID')
except Exception as e:
    print(f'SIGNATURE INVALID: {type(e).__name__}: {e}')

# Also try with the canonical from _get_canonical_bytes()
print(f'\\n=== Using _get_canonical_bytes() ===')
try:
    verify_key.verify(canonical_bytes, sig_bytes)
    print('SIGNATURE VALID (using _get_canonical_bytes())')
except Exception as e:
    print(f'SIGNATURE INVALID: {type(e).__name__}: {e}')