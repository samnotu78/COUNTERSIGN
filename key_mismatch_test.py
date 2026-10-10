#!/usr/bin/env python3
"""Verify the key mismatch theory"""
import os, sys
sys.path.insert(0, r'D:\countersign')

from nacl.signing import SigningKey
import uuid

# Simulate what _make_signed_token_native does
sk = SigningKey(os.urandom(32))
kid = 'test-key-1'

# Build and sign token (this is what _make_signed_token_native does)
from countersign_crypto.models import CountersignToken, SignedCountersignToken
import base64, json

issued_at_val = 'null'
not_before_val = 'null'
expires_at_val = 'null'

canonical = (
    f'{{"version":1,"alg":"Ed25519","kid":"{kid}","iss":"TestOrg"'
    f',"jti":"{uuid.uuid4()}","policy_version":1'
    f',"amount":"4200","currency":"INR","payee":"merchant@example.test"'
    f',"issued_at":{issued_at_val},"not_before":{not_before_val},"expires_at":{expires_at_val}}}'
)

signature_b64 = base64.b64encode(sk.sign(canonical.encode("utf-8")).signature).decode('ascii')

unsigned_token = CountersignToken(
    version=1, alg='Ed25519', kid=kid, iss='TestOrg',
    jti=str(uuid.uuid4()), policy_version=1, amount='4200', currency='INR', payee='merchant@example.test',
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

print(f'signed.kid: {signed.kid}')
print(f'sk (the signing key): {sk}')
print(f'sk.verify_key: {sk.verify_key}')
print(f'sk.verify_key.encode(): {sk.verify_key.encode()}')

# Now simulate _make_trust_snapshot - it creates a NEW key
import base64 as b64
new_sk = __import__('nacl.signing').signing.SigningKey(os.urandom(32))
new_vk = new_sk.verify_key
print(f'\\nnew_sk (from _make_trust_snapshot): {new_sk}')
print(f'new_vk: {new_vk}')
print(f'new_vk.encode(): {new_vk.encode()}')

print(f'\\nAre they the same? {sk.verify_key == new_sk.verify_key}')
print(f'sk.verify_key.encode(): {sk.verify_key.encode()[:20]}...')
print(f'new_vk.encode(): {new_vk.encode()[:20]}...')