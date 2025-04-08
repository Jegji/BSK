import binascii
import os

from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CONSTANT_SALT = b'\x00' * 16
CONSTANT_IV = b'\x00' * 16

def gen_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key

def get_pin():
    pin = input("Enter your PIN: ")
    if len(pin) != 4:
        print("PIN must be 4 digits long.")
        return get_pin()
    return pin

def encrypt_pin(pin, key):
    pin_bytes = pin.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=CONSTANT_SALT,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(pin_bytes)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(CONSTANT_IV), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(key) + padder.finalize()

    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_key

def decrypt_key(encrypted_key, pin):
    pin_bytes = pin.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=CONSTANT_SALT,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(pin_bytes)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(CONSTANT_IV), backend=default_backend())
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

def save_key_to_file(file_path, key):
    with open(file_path, 'wb') as f:
        f.write(key)

def main():
    private_key, public_key = gen_key()
    print("Private Key:", private_key.decode())
    pin = get_pin()
    encrypted_key = encrypt_pin(pin, private_key)
    save_key_to_file('E:\\private_key.pem', encrypted_key)
    save_key_to_file('S:\\Downloads\\public_key.pem', public_key)

    if private_key != encrypted_key:
        print("Key encrypted successfully!")
    if private_key == decrypt_key(encrypted_key, pin):
        print("Key decrypted successfully!")

if __name__ == '__main__':
    main()
