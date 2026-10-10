from countersign_crypto.models import SignedCountersignToken
print('Fields:')
for name, field in SignedCountersignToken.model_fields.items():
    print(f'  {name}: {field.annotation}')