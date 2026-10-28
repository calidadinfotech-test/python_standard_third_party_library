import hashlib

message = b"Hello World"

result = hashlib.sha256(message).hexdigest()

print("Standard SHA-256:", result)
