from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder


sign_key = SigningKey.generate()

verify_key = sign_key.verify_key

verify_key_base64 = verify_key.encode(encoder=Base64Encoder)
with open("verify_key.b64", "wb") as f:
    f.write(verify_key_base64)

text = b"Message for sign"
signed = sign_key.sign(text)

with open("signed_combined.bin", "wb") as f:
    f.write(signed)
