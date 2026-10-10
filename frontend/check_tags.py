import re

with open('src/App.tsx', 'r') as f:
    lines = f.readlines()

open_tags = []
for i in range(670, 960):
    line = lines[i]
    tags = re.findall(r'<(/?)([a-z][a-z0-9]*)', line)
    for closing, tag in tags:
        if closing:
            open_tags.append(('close', tag, i+1))
        else:
            if tag not in ['br', 'hr', 'img', 'input', 'meta', 'link']:
                open_tags.append(('open', tag, i+1))

stack = []
for action, tag, line in open_tags:
    if action == 'open':
        stack.append((tag, line))
    else:
        if stack and stack[-1][0] == tag:
            stack.pop()
        else:
            print(f'  MISMATCH: closing {tag} at line {line}, expected {stack[-1][0] if stack else "none"}')

print('Remaining unclosed tags:', stack)