import hashlib

message = b"Hello Quantum World"
print(hashlib.sha3_256(message).hexdigest())
