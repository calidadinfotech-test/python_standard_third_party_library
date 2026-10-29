from py_ecc.bls import bls12_381 as bls
import os

def generate_keypair():
    """
    Generates a private key and its corresponding public key.
    The private key is a random integer, and the public key is a point on the curve (G1).
    """
    # Generate a random 32-byte private key
    private_key_bytes = os.urandom(32)
    # Convert bytes to an integer private key used by the BLS library
    private_key = int.from_bytes(private_key_bytes, byteorder="big")
    
    # Derive the public key (Point on G1)
    public_key = bls.sk_to_pk(private_key)
    return private_key, public_key

def sign_message(private_key: int, message: bytes) -> bytes:
    """
    Signs a message using the private key.
    The signature is a point on the curve (G2) hashed from the message.
    """
    return bls.Sign(private_key, message)

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verifies that a signature is valid for a given message and public key.
    """
    return bls.Verify(public_key, message, signature)

def aggregate_signatures(signatures: list) -> bytes:
    """
    Aggregates multiple individual signatures into a single, compact signature.
    """
    return bls.Aggregate(signatures)

def verify_aggregated_signature(public_keys: list, messages: list, aggregated_signature: bytes) -> bool:
    """
    Verifies an aggregated signature against a list of public keys and their corresponding messages.
    """
    return bls.AggregateVerify(public_keys, messages, aggregated_signature)


# ==========================================
# Execution & Testing
# ==========================================
if __name__ == "__main__":
    print("--- Step 1: Standard Signing & Verification ---")
    # 1. Generate keys
    alice_priv, alice_pub = generate_keypair()
    msg = b"Transaction: Alice pays Bob 5 ETH"
    
    # 2. Sign
    sig = sign_message(alice_priv, msg)
    print(f"Alice's Public Key (truncated): {alice_pub[:15].hex()}...")
    print(f"Signature (truncated):         {sig[:15].hex()}...")
    
    # 3. Verify
    is_valid = verify_signature(alice_pub, msg, sig)
    print(f"Is signature valid? {is_valid}\n")

    
    print("--- Step 2: Signature Aggregation (The BLS 'Magic') ---")
    # Simulate three different validators signing three different messages
    validators = [generate_keypair() for _ in range(3)]
    messages = [
        b"Block Header #1001",
        b"Block Header #1002",
        b"Block Header #1003"
    ]
    
    # Collect individual signatures and public keys
    individual_sigs = []
    pub_keys = []
    
    for (priv, pub), msg in zip(validators, messages):
        individual_sigs.append(sign_message(priv, msg))
        pub_keys.append(pub)
        
    # Aggregate all 3 signatures into exactly ONE signature
    agg_sig = aggregate_signatures(individual_sigs)
    print(f"Aggregated Signature (truncated): {agg_sig[:15].hex()}...")
    
    # Verify all signatures at once
    is_agg_valid = verify_aggregated_signature(pub_keys, messages, agg_sig)
    print(f"Is aggregated signature valid? {is_agg_valid}")
