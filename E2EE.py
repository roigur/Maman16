from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 as the hashing algorithm
        length=32,                  # The length of the derived key (256 bits)
        salt=salt,                  # The salt for the key derivation
        iterations=100000,          # Number of iterations to make the process slower and more secure
        backend=default_backend()   # The backend for cryptographic operations
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key

def encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)  # Generate a random 16-byte salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    # Encode the salt, IV, and ciphertext in base64 for easy storage and transmission
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt(ciphertext: str, password: str) -> str:
    data = base64.b64decode(ciphertext.encode('utf-8'))
    salt = data[:16]  # Extract the salt (first 16 bytes)
    iv = data[16:32]  # Extract the IV (next 16 bytes)
    actual_ciphertext = data[32:]  # The remaining bytes are the actual ciphertext
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    original_message = "This is a secret message."
    password = "StrongPassword123"

    encrypted_message = encrypt(original_message, password)
    print(f"Encrypted Message: {encrypted_message}")

    decrypted_message = decrypt(encrypted_message, password)
    print(f"Decrypted Message: {decrypted_message}")