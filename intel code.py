#!/usr/bin/env python
# coding: utf-8

# In[ ]:


pip install cryptography


# In[2]:


pip install python-utils


# In[3]:


pip install cryptography library


# In[1]:


import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
import base64

SALT_SIZE = 16
ITERATIONS = 100000
KEY_SIZE = 32

def generate_password_hash(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt data using Fernet symmetric encryption
def encrypt_data(data: bytes, encryption_key: bytes) -> bytes:
    fernet = Fernet(encryption_key)
    return fernet.encrypt(data)

# Decrypt data using Fernet symmetric encryption
def decrypt_data(encrypted_data: bytes, encryption_key: bytes) -> bytes:
    fernet = Fernet(encryption_key)
    return fernet.decrypt(encrypted_data)

# Encrypt a file
def encrypt_file(file_path: str, encryption_key: bytes):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = encrypt_data(file_data, encryption_key)
    with open(file_path + ".enc", 'wb') as file:
        file.write(encrypted_data)

# Decrypt a file
def decrypt_file(file_path: str, encryption_key: bytes):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = decrypt_data(encrypted_data, encryption_key)
    with open(file_path[:-4], 'wb') as file:
        file.write(decrypted_data)

# Main encryption workflow
def main():
    file_path = input("Enter the file path to encrypt: ")
    password = input("Enter a password: ")

    # Generate random encryption key for file encryption
    file_encryption_key = Fernet.generate_key()

    # Encrypt the file
    encrypt_file(file_path, file_encryption_key)

    # Generate salt and derive key from password
    salt = os.urandom(SALT_SIZE)
    derived_key = generate_password_hash(password, salt)

    # Encrypt the file encryption key using the derived key
    encrypted_file_key = encrypt_data(file_encryption_key, base64.urlsafe_b64encode(derived_key))

    # Store the encrypted file key and salt
    with open(file_path + ".key", 'wb') as key_file:
        key_file.write(salt + encrypted_file_key)

    print(f"File encrypted and key stored in {file_path}.key")

    # For decryption
    password = input("Enter the password to decrypt: ")
    with open(file_path + ".key", 'rb') as key_file:
        salt = key_file.read(SALT_SIZE)
        encrypted_file_key = key_file.read()
    derived_key = generate_password_hash(password, salt)
    decrypted_file_key = decrypt_data(encrypted_file_key, base64.urlsafe_b64encode(derived_key))

    decrypt_file(file_path + ".enc", decrypted_file_key)
    print(f"File decrypted and saved as {file_path}")

if __name__ == "__main__":
    main()

