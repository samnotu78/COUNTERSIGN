#!/usr/bin/env python3
import os, sys, base64
sys.path.insert(0, r'D:\countersign')
from nacl.signing import SigningKey
from countersign_crypto.trust import TrustDirectorySnapshot

# Simulate what _make_trust_snapshot does with signing_key
sk = SigningKey(os.urandom(32))
keys = {'revoked-key': {'revoked': True}}

snapshot_keys = {}
for kid, key_props in keys.items():
    signing_key = sk  # This is the signing_key parameter
    print('Loop kid:', kid)
    print('signing_key is not None:', signing_key is not None)
    print('kid in keys:', kid in keys)
    if signing_key is not None and kid in keys:
        vk = signing_key.verify_key
        print('Using signing_key.verify_key')
    else:
        sk2 = SigningKey(os.urandom(32))
        vk = sk2.verify_key
        print('Generating new key')
    snapshot_keys[kid] = {
        'revoked': key_props.get('revoked', False),
        'valid_from': key_props.get('valid_from'),
        'valid_until': key_props.get('valid_until'),
        'public_key_b64': base64.b64encode(vk.encode()).decode('ascii'),
    }
    print('snapshot_keys:', snapshot_keys)

snap = TrustDirectorySnapshot(
    snapshot_id='test',
    version='1.0',
    keys=snapshot_keys,
    root_key_fingerprint='TEST',
    signature='',
)
print('Snapshot keys dict:', snap.keys)
print('public_key_b64 for revoked-key:', snap.keys["revoked-key"]["public_key_b64"])