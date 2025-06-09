import tkinter as tk
from tkinter import messagebox
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
    print("Keys generated successfully.")
    return private_key, public_key

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

    print("Private key encrypted successfully.")
    return encrypted_key

def save_key_to_file(file_path, key):
    with open(file_path, 'wb') as f:
        f.write(key)
    print(f"Key saved to {file_path}.")

class KeyGenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Key Generator")
        self.root.geometry("400x300")

        self.label = tk.Label(root, text="Enter PIN (4 digits):", font=("Arial", 12))
        self.label.pack(pady=10)

        self.pin_entry = tk.Entry(root, show="*", font=("Arial", 12), width=10)
        self.pin_entry.pack(pady=10)

        self.generate_button = tk.Button(root, text="Generate Keys", command=self.generate_keys, font=("Arial", 12))
        self.generate_button.pack(pady=20)

        self.status_label = tk.Label(root, text="Status: Waiting for action", font=("Arial", 10))
        self.status_label.pack(pady=10)

    def generate_keys(self):
        pin = self.pin_entry.get()
        if len(pin) != 4 or not pin.isdigit():
            messagebox.showerror("Error", "PIN must be exactly 4 digits.")
            print("Error: Invalid PIN format.")
            return

        try:
            private_key, public_key = gen_key()
            encrypted_key = encrypt_pin(pin, private_key)

            save_key_to_file('E:\\private_key.pem', encrypted_key)
            save_key_to_file('S:\\Downloads\\public_key.pem', public_key)

            self.status_label.config(text="Status: Keys generated successfully!")
            messagebox.showinfo("Success", "Keys have been generated and saved.")
            print("Keys generation and saving completed successfully.")
        except Exception as e:
            self.status_label.config(text="Status: Error during key generation.")
            messagebox.showerror("Error", f"An error occurred: {e}")
            print(f"Error: {e}")

def main():
    root = tk.Tk()
    app = KeyGenApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()