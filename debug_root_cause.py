import sys, os
sys.path.insert(0, r'.')
from countersign_crypto.models import SignedCountersignToken, CountersignToken
from nacl.signing import SigningKey
import base64, json
from datetime import datetime, timezone

# Recreate what _make_signed_token_native does
sk = SigningKey(os.urandom(32))

# Build canonical with actual expires_at
expires_at_str = '2020-01-01T00:00:00Z'
canonical = '{"version":1,"alg":"Ed25519","kid":"test-key-1","iss":"TestOrg","jti":"test-jti-123","policy_version":1,"amount":"4200","currency":"INR","payee":"merchant@example.test","issued_at":null,"not_before":null,"expires_at":"2020-01-01T00:00:00Z"}'

signature_b64 = base64.b64encode(sk.sign(canonical.encode('utf-8')).signature).decode('ascii')

# Current behavior: model fields None, signed_canonical set
unsigned = CountersignToken(
    version=1, alg='Ed25519', kid='test-key-1', iss='TestOrg', jti='test-jti-123',
    policy_version=1, amount='4200', currency='INR', payee='merchant@example.test',
    issued_at=None, not_before=None, expires_at=None
)
signed = SignedCountersignToken(
    version=unsigned.version, alg=unsigned.alg, kid=unsigned.kid, iss=unsigned.iss,
    jti=unsigned.jti, policy_version=unsigned.policy_version, amount=unsigned.amount,
    currency=unsigned.currency, payee=unsigned.payee, issued_at=unsigned.issued_at,
    not_before=unsigned.not_before, expires_at=unsigned.expires_at,
    signature=signature_b64, signed_canonical=canonical
)

print('=== Current behavior ===')
print('signed.expires_at:', signed.expires_at)
print('signed.not_before:', signed.not_before)
print('signed.signed_canonical contains expires_at:', 'expires_at' in signed.signed_canonical)

# Now verify
from countersign_crypto.verification import verify_token
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot
from countersign_crypto.replay import ReplayStore

# Set up trust directory
td_snapshot = TrustDirectorySnapshot(
    snapshot_id='test', version='1.0',
    keys={'test-key-1': {'revoked': False, 'valid_from': None, 'valid_until': None,
        'public_key_b64': base64.b64encode(sk.verify_key.encode()).decode('ascii')}},
    root_key_fingerprint='TEST', signature=''
)
TrustDirectory.initialize_with_snapshot(td_snapshot)
replay = ReplayStore()

verdict, error_code, metadata = verify_token(signed, replay, TrustDirectory)
print('verdict:', verdict, 'error_code:', error_code)