import os, sys, json
sys.path.insert(0, r'.')
from countersign_crypto.models import CountersignToken, SignedCountersignToken
from nacl.signing import SigningKey

def _sign_message(sk, message):
    import base64
    sig = sk.sign(message)
    return base64.b64encode(sig.signature)

def _make_signed_token_native(sk, kid='test-key-1', amount='4200', currency='INR', payee='merchant@example.test'):
    issued_at_val = 'null'
    not_before_val = 'null'
    expires_at_val = 'null'

    canonical = (
        f'{{\"version\":1,\"alg\":\"Ed25519\",\"kid\":\"{kid}\",\"iss\":\"TestOrg\",\"jti\":\"test-jti-123\",\"policy_version\":1,\"amount\":\"{amount}\",\"currency\":\"{currency}\",\"payee\":\"{payee}\",\"issued_at\":{issued_at_val},\"not_before\":{not_before_val},\"expires_at\":{expires_at_val}}}'
    )

    signature_b64 = _sign_message(sk, canonical.encode('utf-8'))

    unsigned_token = CountersignToken(
        version=1,
        alg='Ed25519',
        kid=kid,
        iss='TestOrg',
        jti='test-jti-123',
        policy_version=1,
        amount=amount,
        currency=currency,
        payee=payee,
        issued_at=None,
        not_before=None,
        expires_at=None,
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
        signature=signature_b64.decode('ascii'),
        signed_canonical=unsigned_token.canonical(),
    )

    return signed

sk = SigningKey(os.urandom(32))
token = _make_signed_token_native(sk)
print('native canonical():', token.signed_canonical)

# Now compare with model canonical
token2 = CountersignToken(
    version=1,
    alg='Ed25519',
    kid='test-key-1',
    iss='TestOrg',
    jti='test-jti-123',
    policy_version=1,
    amount='4200',
    currency='INR',
    payee='merchant@example.test',
    issued_at=None,
    not_before=None,
    expires_at=None,
)
print('model canonical():', token2.canonical())

# Check if they match
print('Match:', token.signed_canonical == token2.canonical())