from cryptography.hazmat.primitives import hashes, hmac

key = b"secret"
message = b"Hello World"

h = hmac.HMAC(key, hashes.SHA256())
h.update(message)

result = h.finalize().hex()

print("Cryptography HMAC:", result)
