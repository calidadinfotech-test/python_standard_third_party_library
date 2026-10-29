"""Public-key signatures and encryption beyond the usual RSA / ECDSA set."""
from py_ecc.bls import G2ProofOfPossession as bls_pop
from blspy import AugSchemeMPL
from bip340 import schnorr_sign
from gmssl import sm9
from pygost import gost3410
from pygost.gost3410 import CURVES
from ecies import encrypt as ecies_encrypt
from phe import paillier
import rabin_crypto as rabin
from jwcrypto import jwk
import botan3


def sign_attestation(secret_key: int, message: bytes) -> bytes:
    return bls_pop.Sign(secret_key, message)


def sign_block(seed: bytes, message: bytes) -> bytes:
    sk = AugSchemeMPL.key_gen(seed)
    return AugSchemeMPL.sign(sk, message)


def sign_taproot(msg32: bytes, private_key: bytes, aux: bytes) -> bytes:
    return schnorr_sign(msg32, private_key, aux)


def sign_identity(master_public, user_private, message: bytes):
    return sm9.sign(master_public, user_private, message)


def sign_gost(private_key: int, digest: bytes) -> bytes:
    return gost3410.sign(CURVES["id-tc26-gost-3410-12-512-paramSetA"], private_key, digest)


def seal_for_wallet(receiver_public_hex: str, data: bytes) -> bytes:
    return ecies_encrypt(receiver_public_hex, data)


def homomorphic_keys():
    public_key, private_key = paillier.generate_paillier_keypair(n_length=3072)
    return public_key, private_key


def rabin_seal(message_int: int, public_n: int) -> int:
    return rabin.encrypt(message_int, public_n)


def new_web_key():
    return jwk.JWK.generate(kty="EC", crv="P-256")


def new_korean_signing_key(rng):
    return botan3.PrivateKey.create("ECKCDSA", "secp256r1", rng)
