import inspect
from countersign_crypto.models import SignedCountersignToken
try:
    print(inspect.getsource(SignedCountersignToken.__init__))
except:
    print('No __init__ found')