#!/usr/bin/env python3
import os, sys, base64
sys.path.insert(0, r'D:\countersign')
from nacl.signing import SigningKey
from countersign_crypto.trust import TrustDirectory, TrustDirectorySnapshot

# Simulate the full test scenario
sk = SigningKey(os.urandom(32))
kid = 'revoked-key'

# Create trust snapshot WITH signing_key (as the test does)
from countersign_crypto.test_phase1 import _make_trust_snapshot

snap = _make_trust_snapshot(keys={kid: {'revoked': True}}, signing_key=sk)
print('Snapshot keys:', snap.keys)
print('public_key_b64 for revoked-key:', snap.keys[kid]['public_key_b64'])
print('Length:', len(snap.keys[kid]['public_key_b64']))

# Check what current_snapshot returns
print()
print('Current snapshot:', TrustDirectory.current_snapshot())
if TrustDirectory.current_snapshot():
    print('Lookup key info:', TrustDirectory.current_snapshot().lookup_key(kid))