#!/usr/bin/env python3
import sys
sys.path.insert(0, r'D:\countersign')
from countersign_crypto.models import SignedCountersignToken
print('Model fields:')
for name, field in SignedCountersignToken.model_fields.items():
    print(f'  {name}: {field.annotation}')
    if hasattr(field, 'validators'):
        print(f'    validators: {field.validators}')