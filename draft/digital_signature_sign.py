from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

sign_key = SigningKey.generate()

text = b"Text for sign"
signed = sign_key.sign(text)
txt = signed.message
print("Text of signed message", txt)
print("singed=", signed)

verify_key = sign_key.verify_key
print("verify key=", verify_key)

verify_key_bytes = verify_key.encode()
print("decoded key ready to send:", verify_key_bytes)

verify_key = VerifyKey(verify_key_bytes)

try:
    verify_key.verify(signed)
    print("Successfull verification")
except BadSignatureError:
    print("Error signature")

