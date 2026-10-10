#!/usr/bin/env python3
import os, sys, traceback
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.replay import ReplayStore
from countersign_crypto.verification import verify_token
from nacl.signing import SigningKey
import base64, uuid

# Create key pair
sk = SigningKey(os.urandom(32))

# Build token
kid = 'test-key-1'
iss = 'TestOrg'
jti = str(uuid.uuid4())
amount = '4200'
currency = 'INR'
payee = 'merchant@example.test'
policy_version = 1

canonical = (
    f'{{\"version\":1,\"alg\":\"Ed25519\",\"kid\":\"{kid}\",\"iss\":\"{iss}\"'
    f',\"jti\":\"{jti}\",\"policy_version\":{policy_version}'
    f',\"amount\":\"{amount}\",\"currency\":\"{currency}\",\"payee\":\"{payee}\"'
    f',\"issued_at\":null,\"not_before\":null,\"expires_at\":null}}'
)

signature_b64 = base64.b64encode(sk.sign(canonical.encode('utf-8')).signature).decode('ascii')

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
    signed_canonical=unsigned_token.canonical(),
)

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

# Create a NEW replay store (instance-based)
replay_store = ReplayStore()

# Check replay state before verify
print(f'Before verify - replay_store.entry_count(): {replay_store.entry_count()}')
result = replay_store.is_replay(jti, iss, current_time=None)
print(f'is_replay result: {result}')
print(f'After is_replay - replay_store.entry_count(): {replay_store.entry_count()}')

# Now verify
try:
    verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)
    print(f'\\nverify_token verdict: {verdict}')
    print('verify_token error_code:', error_code)
except Exception as e:
    print(f'verify_token ERROR: {type(e).__name__}: {e}')
    traceback.print_exc()