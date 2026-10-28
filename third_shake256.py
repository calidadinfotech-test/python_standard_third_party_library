from Crypto.Hash import SHAKE256

message = b"Hello Quantum World"
print(SHAKE256.new(message).read(32).hex())
