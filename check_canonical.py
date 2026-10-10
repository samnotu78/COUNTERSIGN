#!/usr/bin/env python3
import os, sys
sys.path.insert(0, r'D:\countersign')

from countersign_crypto.models import CountersignToken, SignedCountersignToken
from nacl.signing import SigningKey
import base64, uuid

sk = SigningKey(os.urandom(32))

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

print('signed.signed_canonical repr:', repr(signed.signed_canonical))
print('signed._get_canonical_bytes() repr:', repr(signed._get_canonical_bytes()))
print('Are they equal?', signed.signed_canonical == signed._get_canonical_bytes().decode('utf-8'))
print()
print('signed_canonical length:', len(signed.signed_canonical))
print('_get_canonical_bytes() length:', len(signed._get_canonical_bytes()))
print('Match as bytes?', signed.signed_canonical.encode('utf-8') == signed._get_canonical_bytes())