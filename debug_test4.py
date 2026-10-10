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

# Construct signed token - NOTE: signed_canonical is set to unsigned_token.canonical()
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

# Check what _get_canonical_bytes returns
canonical_bytes_from_method = signed._get_canonical_bytes()
print('_get_canonical_bytes() returns:')
print('  ', canonical_bytes_from_method.decode('utf-8'))
print()
print('signed_canonical field:')
print('  ', signed.signed_canonical)
print()
print('Are they equal (as strings)?')
print('  ', canonical_bytes_from_method.decode('utf-8') == signed.signed_canonical)
print()
print('Are they equal (as bytes)?')
print('  ', canonical_bytes_from_method == signed.signed_canonical.encode('utf-8'))
print()

# Now check what verify_token does step by step
# Step 2: canonical_bytes = token._get_canonical_bytes()
# Step 3: algorithm check (Ed25519)
# Step 4: look up key from trust directory
# Step 4b: verify_key.verify(canonical_bytes, sig_bytes)

# Create trust snapshot with the public key
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
print()
print('verify_token result:')
print('  verdict:', verdict)
print('  error_code:', error_code)
print()

# Now manually trace through verify_token
print('Manual trace:')
print('  Step 2: canonical_bytes from _get_canonical_bytes():')
print('    ', canonical_bytes_from_method.decode('utf-8'))
print('  Step 3: alg =', signed.alg)
print('  Step 4: key_info lookup...')
key_info = snap.lookup_key('test-key-1')
print('    key_info:', key_info)
pub_key_b64 = key_info.get('public_key_b64')
print('    pub_key_b64:', pub_key_b64[:20] if pub_key_b64 else None)
print('    pk_bytes length:', len(base64.b64decode(pub_key_b64)))
print('    verify_key created')
sig_b64 = signed.signature.encode('ascii')
sig_bytes = base64.b64decode(sig_b64)
print('    sig_bytes length:', len(sig_bytes))
print('    verify_key.verify(canonical_bytes_from_method, sig_bytes):')
try:
    __import__('nacl.signing').VerifyKey(base64.b64decode(pub_key_b64)).verify(canonical_bytes_from_method, sig_bytes)
    print('      VALID')
except Exception as e:
    print('      INVALID:', e)