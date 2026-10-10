#!/usr/bin/env python3
import os, sys
sys.path.insert(0, r'D:\countersign')

# Monkeypatch verify_token to add debugging
import countersign_crypto.verification as v_mod

original_verify = v_mod.verify_token

def debug_verify(token, replay_store, trust_directory, current_time=None):
    print("=== debug_verify START ===")
    print(f"token.kid: {token.kid}")
    print(f"token.alg: {token.alg}")
    print(f"token.signature: {token.signature[:30] if token.signature else None}")
    print(f"token.signed_canonical: {token.signed_canonical[:50] if token.signed_canonical else None}")
    print(f"trust_directory._snapshot: {trust_directory._snapshot is not None if hasattr(trust_directory, '_snapshot') else 'N/A'}")
    
    # Call original
    result = original_verify(token, replay_store, trust_directory, current_time)
    print(f"=== debug_verify END: {result[0]} ===")
    return result

v_mod.verify_token = debug_verify

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.replay import ReplayStore
from nacl.signing import SigningKey, VerifyKey
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
snap = type('X', (), {
    'snapshot_id': 'test',
    'version': '1.0',
    'keys': {'test-key-1': {'revoked': False, 'valid_from': None, 'valid_until': None, 'public_key_b64': base64.b64encode(sk.verify_key.encode()).decode('ascii')}},
    'root_key_fingerprint': 'TEST',
    'signature': '',
})()
# Actually use TrustDirectorySnapshot
from countersign_crypto.trust import TrustDirectorySnapshot
snap = TrustDirectorySnapshot(
    snapshot_id='test',
    version='1.0',
    keys={'test-key-1': {'revoked': False, 'valid_from': None, 'valid_until': None, 'public_key_b64': base64.b64encode(sk.verify_key.encode()).decode('ascii')}},
    root_key_fingerprint='TEST',
    signature='',
)
TrustDirectory.initialize_with_snapshot(snap)

replay_store = ReplayStore()

# Call the debug version
result = debug_verify(signed, replay_store, TrustDirectory)
print('Final result:', result)