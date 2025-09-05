from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder

with open("verify_key.b64", "rb") as f:
    verify_key_base64 = f.read()

verify_key =  VerifyKey(verify_key_base64, encoder=Base64Encoder)

with open("signed_combined.bin", "rb") as f:
    signed_blob = f.read()

try:
    message = verify_key.verify(signed_blob)
    print("ITs done right sign")
except Exception as e:
    print("Bad signature", e)

    