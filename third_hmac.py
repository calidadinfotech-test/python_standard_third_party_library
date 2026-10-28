from Crypto.Hash import HMAC, SHA256

key = b"secret"
message = b"Hello World"

result = HMAC.new(
    key, message, SHA256
).hexdigest()

print("Third-party HMAC:", result)
