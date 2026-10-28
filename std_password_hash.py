import hashlib
import secrets

password = b"my-password"
salt = secrets.token_bytes(16)

result = hashlib.pbkdf2_hmac(
    "sha256", password, salt, 600_000
)

print("PBKDF2:", result.hex())
