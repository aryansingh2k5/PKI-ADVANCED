import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key():
    return AESGCM.generate_key(bit_length=128)

def encrypt_aes(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_aes(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)