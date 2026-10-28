from Crypto.Hash import SHA3_256

message = b"Hello Quantum World"
print(SHA3_256.new(message).hexdigest())
