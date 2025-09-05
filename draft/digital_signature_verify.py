from nacl.signing import VerifyKey
from .digital_signature_sign import verify_key_bytes
from  .digital_signature_sign import sign_key


verify_key = VerifyKey(verify_key_bytes)

verify_key.verify(sign_key)


