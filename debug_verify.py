import os, sys
sys.path.insert(0, r'.')
from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.verification import verify_token
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.replay import ReplayStore
from datetime import datetime, timezone
from nacl.signing import SigningKey
import base64

def _new_signing_key():
    return SigningKey(os.urandom(32))

def _make_trust_snapshot(keys=None, signing_key=None):
    import os as _os, base64 as _b64
    from nacl.signing import SigningKey as _Sk
    from countersign_crypto.trust import TrustDirectorySnapshot
    import uuid
    if keys is None:
        keys = {}
    snapshot_keys = {}
    for kid, key_props in keys.items():
        if signing_key is not None and kid in keys:
            vk = signing_key.verify_key
        else:
            sk = _Sk(_os.urandom(32))
            vk = sk.verify_key
        snapshot_keys[kid] = {
            'revoked': key_props.get('revoked', False),
            'valid_from': key_props.get('valid_from'),
            'valid_until': key_props.get('valid_until'),
            'public_key_b64': _b64.b64encode(vk.encode()).decode('ascii'),
        }
    return TrustDirectorySnapshot(
        snapshot_id=str(uuid.uuid4()),
        version='1.0',
        keys=snapshot_keys,
        root_key_fingerprint='TEST-ROOT-KEY-FP',
        signature='',
    )

# Create a signed token
sk = _new_signing_key()
print('Signing key created')

# Use the model's sign method
from countersign_crypto.models import CountersignToken, SignedCountersignToken

token = CountersignToken(
    version=1,
    alg='Ed25519',
    kid='test-key-1',
    iss='TestOrg',
    jti='test-jti-456',
    policy_version=1,
    amount='4200',
    currency='INR',
    payee='merchant@example.test',
    issued_at=None,
    not_before=None,
    expires_at=None,
)

print('Token created')
print('Token canonical():', token.canonical())

# Sign using the model's sign method
signed = token.sign(sk)
print('Signed token')
print('Signed signature:', signed.signature[:20], '...')
print('Signed canonical:', signed.signed_canonical)

# Now verify using verify_token
TrustDirectory.initialize_with_snapshot(_make_trust_snapshot(keys={'test-key-1': {'revoked': False}}, signing_key=sk))
replay_store = ReplayStore()

print()
print('=== Now calling verify_token ===')
verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)
print('Verdict:', verdict)
print('Error code:', error_code)
print('Metadata:', metadata)