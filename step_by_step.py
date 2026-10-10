#!/usr/bin/env python3
"""Test script with inline verification debug"""
import os, sys, traceback
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.replay import ReplayStore
from nacl.signing import SigningKey, VerifyKey
import base64, uuid

# Create key pair
sk = SigningKey(os.urandom(32))

# Build token exactly as _make_signed_token_native does
kid = 'test-key-1'
iss = 'TestOrg'
jti = str(uuid.uuid4())
amount = '4200'
currency = 'INR'
payee = 'merchant@example.test'
policy_version = 1

# Build canonical JSON
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

print('signed.signed_canonical:', signed.signed_canonical[:60] + '...')
cb = signed._get_canonical_bytes()
print('signed._get_canonical_bytes():', cb[:60] + b'...' if isinstance(cb, bytes) else cb[:60] + '...')
print('sig_b64:', signature_b64[:30] + '...')
print('sig length:', len(base64.b64decode(signature_b64)))
print()

# Create trust snapshot
snap = TrustDirectorySnapshot(
    snapshot_id='test',
    version='1.0',
    keys={
        'test-key-1': {
            'revoked': False,
            'valid_from': None,
            'valid_until': None,
            'public_key_b64': base64.b64encode(sk.verify_key.encode()).decode('ascii'),
        }
    },
    root_key_fingerprint='TEST',
    signature='',
)
TrustDirectory.initialize_with_snapshot(snap)

replay_store = ReplayStore()

# Now do EXACTLY what verify_token does step by step
print('=== Step-by-step verify_token replication ===')

# Step 1: Replay protection
jti_val = signed.jti
issuer_val = signed.iss
if jti_val is not None and issuer_val is not None:
    is_replay = replay_store.is_replay(jti_val, issuer_val, current_time=None)
    print(f'Step 1 - replay: {is_replay}')
else:
    print('Step 1 - skip replay (jti or iss None)')

# Step 2: Canonical JSON parsing
try:
    canonical_bytes = signed._get_canonical_bytes()
    cdecoded = canonical_bytes.decode('utf-8')
    print(f'Step 2 - canonical_bytes length: {len(canonical_bytes)}')
    print(f'Step 2 - canonical_bytes first 60: {cdecoded[:60]}...')
except Exception as e:
    print(f'Step 2 - ERROR: {e}')

# Step 3: Algorithm allowlist
if signed.alg == 'alg:none' or signed.alg.lower() == 'none':
    print('Step 3 - alg:none')
if signed.alg not in ('Ed25519',):
    print(f'Step 3 - alg unsupported: {signed.alg}')
print(f'Step 3 - alg: {signed.alg}')

# Step 4: Look up key
snap_curr = TrustDirectory.current_snapshot()
print(f'Step 4 - current_snapshot: {snap_curr is not None}')
key_info = snap_curr.lookup_key('test-key-1')
print(f'Step 4 - key_info: {key_info}')
pub_key_b64 = key_info.get('public_key_b64')
print(f'Step 4 - pub_key_b64: {pub_key_b64[:20] if pub_key_b64 else None}')

# Create VerifyKey
pk_bytes = base64.b64decode(pub_key_b64)
print(f'Step 4 - pk_bytes length: {len(pk_bytes)}')
verify_key = VerifyKey(pk_bytes)
print(f'Step 4 - VerifyKey created')

# Verify signature
sig_b64 = signed.signature.encode('ascii')
sig_bytes = base64.b64decode(sig_b64)
print(f'Step 4b - sig_bytes length: {len(sig_bytes)}')

print(f'\\n=== About to verify_key.verify ===')
try:
    verify_key.verify(canonical_bytes, sig_bytes)
    print('SIGNATURE VALID')
except Exception as e:
    print(f'SIGNATURE INVALID: {type(e).__name__}: {e}')
    traceback.print_exc()

print()
print('=== Now call actual verify_token ===')
# Call the actual verify_token
from countersign_crypto.verification import verify_token
try:
    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)
    print(f'verify_token verdict: {verdict}')
    print('verify_token error_code:', error_code)
except Exception as e:
    print(f'verify_token ERROR: {type(e).__name__}: {e}')
    traceback.print_exc()