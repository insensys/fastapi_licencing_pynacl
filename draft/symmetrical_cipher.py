from nacl import secret, utils


key = utils.random(secret.SecretBox.KEY_SIZE)

print("Random key", key)

box = secret.SecretBox(key)

message = b"Hello cryptography"

cipher = box.encrypt(message)

print("Cipher message", cipher)

plain_text = box.decrypt(cipher)
print("Plain text after decoding", plain_text)