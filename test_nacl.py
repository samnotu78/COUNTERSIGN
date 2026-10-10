import os, sys
sys.path.insert(0, r'D:\countersign')

# Test that nacl.signing.VerifyKey can be imported
from nacl.signing import SigningKey, VerifyKey
print('VerifyKey import successful')

# Create a key pair
sk = SigningKey(os.urandom(32))
vk = sk.verify_key
print('Key pair created')

# Test verification
msg = b'hello world'
sig = sk.sign(msg)
try:
    vk_check = VerifyKey(vk.encode())
    vk_check.verify(msg, sig.signature)
    print('Manual verification: VALID')
except Exception as e:
    print('Manual verification: INVALID', e)
