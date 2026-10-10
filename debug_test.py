import sys, os
sys.path.insert(0, r'.')
from countersign_crypto.models import SignedCountersignToken, CountersignToken
from nacl.signing import SigningKey
import base64
from datetime import datetime

sk = SigningKey(os.urandom(32))
canonical = '{"version":1,"alg":"Ed25519","kid":"test-key-1","iss":"TestOrg","jti":"test-jti-123","policy_version":1,"amount":"4200","currency":"INR","payee":"merchant@example.test","issued_at":null,"not_before":null,"expires_at":"2020-01-01T00:00:00Z"}'
sig_bytes = sk.sign(canonical.encode('utf-8')).signature
sig_b64 = base64.b64encode(sig_bytes).decode('ascii')
expires_at_dt = datetime.fromisoformat('2020-01-01T00:00:00Z'.replace('Z', '+00:00'))
UC = CountersignToken
uc = UC(version=1, alg='Ed25519', kid='test-key-1', iss='TestOrg', jti='test-jti-123', policy_version=1, amount='4200', currency='INR', payee='merchant@example.test', issued_at=None, not_before=None, expires_at=expires_at_dt)
SCT = SignedCountersignToken
signed = SCT(version=uc.version, alg=uc.alg, kid=uc.kid, iss=uc.iss, jti=uc.jti, policy_version=uc.policy_version, amount=uc.amount, currency=uc.currency, payee=uc.payee, issued_at=uc.issued_at, not_before=uc.not_before, expires_at=uc.expires_at, signature=sig_b64, signed_canonical=canonical)
print('expires_at:', signed.expires_at, type(signed.expires_at))
print('canonical[:50]:', canonical[:50])
print('signed_canonical[:50]:', signed.signed_canonical[:50])
print('Match:', signed.signed_canonical == canonical)