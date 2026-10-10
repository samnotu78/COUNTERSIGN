import os, sys
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.verification import verify_token, ErrorCode, VerificationResult
from countersign_crypto.replay import ReplayStore
from nacl.signing import SigningKey
import base64, uuid

# Create key pair
sk = SigningKey(os.urandom(32))

# Use _make_signed_token_native logic directly
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
    signed_canonical=unsigned_token.canonical(),  # This is the key!
)

print('signed_canonical:', signed.signed_canonical[:50] + '...')
print('canonical (from f-string):', canonical[:50] + '...')
print('Match:', signed.signed_canonical == canonical)

# Create trust snapshot
snap = TrustDirectorySnapshot(
    snapshot_id='test-snap',
    version='1.0',
    keys={
        'test-key-1': {
            'revoked': False,
            'valid_from': None,
            'valid_until': None,
            'public_key_b64': base64.b64encode(sk.verify_key.encode()).decode('ascii'),
        }
    },
    root_key_fingerprint='TEST-ROOT-KEY-FP',
    signature='',
)

TrustDirectory.initialize_with_snapshot(snap)
replay_store = ReplayStore()

# Run verify_token
verdict, error_code, metadata = verify_token(signed, replay_store, TrustDirectory)
print('verdict:', verdict)
print('error_code:', error_code)