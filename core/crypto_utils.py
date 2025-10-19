"""
This file implements the core cryptographic utilities used by the authentication protocols

Includes:
- Key generation
- Nonce generation
- HMAC computation (SHA-256)
- Random byte utilities
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from config import KEY_SIZE, NONCE_SIZE

#Key generation
def generate_key(size: int = KEY_SIZE) -> bytes:
    return secrets.token_bytes(size)

#Nonce generation
def generate_nonce(size: int = NONCE_SIZE) -> bytes:
    return secrets.token_bytes(size)

#AES-CBC mode with PKCS7 padding
def encrypt_message(key: bytes, plaintext:bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext