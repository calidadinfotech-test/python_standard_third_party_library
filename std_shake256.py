import hashlib

message = b"Hello Quantum World"
print(hashlib.shake_256(message).hexdigest(32))
