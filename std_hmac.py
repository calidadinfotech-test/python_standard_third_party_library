import hmac
import hashlib

key = b"secret"
message = b"Hello World"

result = hmac.new(
    key, message, hashlib.sha256
).hexdigest()

print("Standard HMAC:", result)
