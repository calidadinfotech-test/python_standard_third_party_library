from argon2 import PasswordHasher

hasher = PasswordHasher()

result = hasher.hash("my-password")

print("Argon2:", result)
