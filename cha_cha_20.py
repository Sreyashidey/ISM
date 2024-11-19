# -*- coding: utf-8 -*-
"""
Created on Wed Mar 13 20:18:14 2024

@author: sreya
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_file(key, input_file_path, output_file_path):
    # Read the plaintext file
    with open(input_file_path, "rb") as input_file:
        plaintext = input_file.read()

    # Generate a random nonce
    nonce = os.urandom(16)

    # Create a ChaCha20 cipher object
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())

    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the encrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(nonce + ciphertext)

def decrypt_file(key, input_file_path, output_file_path):
    # Read the encrypted file
    with open(input_file_path, "rb") as input_file:
        nonce = input_file.read(16)
        ciphertext = input_file.read()

    # Create a ChaCha20 cipher object
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(plaintext)

# Example usage
key = b'\x00' * 32
input_file_path = 'D:\encryption\plaintext.txt'
encrypted_file_path = 'D:\encryption\encrypted.bin'
decrypted_file_path = 'D:\encryption\decrypted.txt'

# Encrypt the plaintext file
encrypt_file(key, input_file_path, encrypted_file_path)

# Decrypt the encrypted file
decrypt_file(key, encrypted_file_path, decrypted_file_path)