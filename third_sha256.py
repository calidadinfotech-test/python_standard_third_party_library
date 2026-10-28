from Crypto.Hash import SHA256

message = b"Hello World"

result = SHA256.new(message).hexdigest()

print("Third-party SHA-256:", result)
