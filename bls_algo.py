from py_ecc.bls import G2ProofOfPossession as bls

# Example private key for demonstration only.
# In production, generate keys securely.
private_key = 5566

# Generate the public key
public_key = bls.SkToPk(private_key)

# Message to sign
message = b"Hello, BLS digital signature!"

# Sign the message
signature = bls.Sign(private_key, message)

# Verify the signature
is_valid = bls.Verify(public_key, message, signature)

print("Public key:", public_key.hex())
print("Signature:", signature.hex())
print("Signature valid:", is_valid)

# Check that a modified message fails verification
modified_message = b"Modified message"
print(
    "Modified message valid:",
    bls.Verify(public_key, modified_message, signature)
)


from blspy import AugSchemeMPL, PrivateKey

sk = AugSchemeMPL.key_gen(b"0123456789abcdef0123456789abcdef")
pk = sk.get_g1()
signature = AugSchemeMPL.sign(sk, b"test message")

from blspy import AugSchemeMPL, PrivateKey

# Generate a key for demonstration
sk = AugSchemeMPL.key_gen(b"0123456789abcdef0123456789abcdef")
pk = sk.get_g1()

# Sign a message
message = b"Block approved"
signature = AugSchemeMPL.sign(sk, message)

# Verify the signature
valid = AugSchemeMPL.verify(pk, message, signature)
print(valid)  # True
