#!/usr/bin/env python3
"""Revert the debug changes to verification.py"""

with open('D:\\countersign\\countersign_crypto\\verification.py', 'r') as f:
    content = f.read()

# Remove the debug import and print statements
# Look for "import base64 as _b64mod" and remove it
lines = content.split('\n')
new_lines = []
skip_until = -1

for i, line in enumerate(lines):
    if i >= 153 and i <= 164:
        # Skip debug lines
        if 'import base64 as _b64mod' in line:
            continue
        if 'print(f"[DEBUG]"' in line:
            continue
        if 'print(f"[DEBUG] sig_b64' in line:
            continue
        if 'print(f"[DEBUG] sig_bytes length' in line:
            continue
        if 'print(f"[DEBUG] canonical_bytes length' in line:
            continue
        if 'print(f"[DEBUG] verify_key type' in line:
            continue
        if 'print(f"[DEBUG] About to verify..."' in line:
            continue
        if 'print(f"[DEBUG] Signature VERIFIED"' in line:
            continue
        if 'verify_key.verify(canonical_bytes, sig_bytes)' in line and i > 155:
            # This is the actual verify line, keep it
            new_lines.append(line)
            continue
    new_lines.append(line)

with open('D:\\countersign\\countersign_crypto\\verification.py', 'w') as f:
    f.write('\n'.join(new_lines))

print('Debug changes reverted')