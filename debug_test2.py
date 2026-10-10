import os
import sys
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.verification import verify_token, ErrorCode, VerificationResult
from countersign_crypto.replay import ReplayStore
from nacl.signing import SigningKey, VerifyKey
import base64
import uuid

# Replicate the test
sk = SigningKey(os.urandom(32))
vk = sk.verify_key

# Use _make_signed_token_native logic
kid = 'test-key-1'
iss = 'TestOrg'
jti = str(uuid.uuid4())
amount = '4200'
currency = 'INR'
payee = 'merchant@example.test'
policy_version = 1

# Build canonical JSON (same as _make_signed_token_native)
canonical = (
    f'{{"version":1,"alg":"Ed25519","kid":"{kid}","iss":"{iss}"'
    f',"jti":"{jti}","policy_version":{policy_version}'
    f',"amount":"{amount}","currency":"{currency}","payee":"{payee}"'
    f',"issued_at":null,"not_before":null,"expires_at":null}}'
)
print('canonical:', canonical)

# Sign it
signature_b64 = base64.b64encode(sk.sign(canonical.encode('utf-8')).signature).decode('ascii')
print('signature_b64:', signature_b64[:30])

# Construct SignedCountersignToken
from countersign_crypto.models import CountersignToken, SignedCountersignToken

unsigned_token = CountersignToken(
    version=1, alg='Ed25519', kid=kid, iss=iss,
    jti=jti, policy_version=policy_version, amount=amount, currency=currency, payee=payee,
    issued_at=None, not_before=None, expires_at=None,
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
    signature=signature_b64,
)

print('signed.kid:', signed.kid)
print('signed.alg:', signed.alg)
print('signed.signature:', signed.signature[:30] if signed.signature else None)

# Create trust snapshot
snap = TrustDirectorySnapshot(
    snapshot_id='test-snap',
    version='1.0',
    keys={
        'test-key-1': {
            'revoked': False,
            'valid_from': None,
            'valid_until': None,
            'public_key_b64': base64.b64encode(vk.encode()).decode('ascii'),
        }
    },
    root_key_fingerprint='TEST-ROOT-KEY-FP',
    signature='',
)

TrustDirectory.initialize_with_snapshot(snap)

replay_store = ReplayStore()

# Now manually replicate what verify_token does step by step
print('\n--- Step-by-step trace through verify_token ---')

# Step 1: Replay protection
print('Step 1: Replay protection')
if signed.jti is not None and signed.iss is not None:
    is_replay = replay_store.is_replay(signed.jti, signed.iss, current_time=None)
    print('  is_replay:', is_replay)
else:
    print('  jti or iss is None, skipping replay')

# Step 2: Canonical JSON parsing
print('\nStep 2: Canonical JSON parsing')
try:
    canonical_bytes = signed._get_canonical_bytes()
    print('  canonical_bytes:', canonical_bytes.decode('utf-8'))
except Exception as e:
    print('  ERROR:', e)

# Step 3: Algorithm allowlist
print('\nStep 3: Algorithm allowlist')
if signed.alg == 'alg:none' or signed.alg.lower() == 'none':
    print('  alg:none detected')
if signed.alg not in ('Ed25519',):
    print('  alg unsupported:', signed.alg)
print('  alg OK:', signed.alg)

# Step 4: Look up key
print('\nStep 4: Look up key')
snap_curr = TrustDirectory.current_snapshot()
print('  current_snapshot:', snap_curr is not None)
key_info = snap_curr.lookup_key('test-key-1')
print('  key_info:', key_info)

pub_key_b64 = key_info.get('public_key_b64')
print('  pub_key_b64:', pub_key_b64[:20] if pub_key_b64 else None)

# Create VerifyKey
pk_bytes = base64.b64decode(pub_key_b64)
print('  pk_bytes length:', len(pk_bytes))

verify_key = VerifyKey(pk_bytes)
print('  VerifyKey created')

# Verify signature
print('\nStep 4b: Verify signature')
try:
    sig_b64 = signed.signature.encode('ascii')
    sig_bytes = base64.b64decode(sig_b64)
    print('  sig_bytes length:', len(sig_bytes))
    print('  About to verify_key.verify...')
    verify_key.verify(canonical_bytes, sig_bytes)
    print('  SIGNATURE VALID')
except Exception as e:
    print('  SIGNATURE INVALID:', type(e).__name__, e)

# Step 5-9 would continue, but we already see the issue