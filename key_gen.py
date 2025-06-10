"""
@file key_gen.py
@brief This file contains the implementation of an RSA key generator application with encryption functionality.
"""
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CONSTANT_SALT = b'\x00' * 16
CONSTANT_IV = b'\x00' * 16

def gen_key():
    """
    @brief Generates an RSA private and public key pair.
    @return A tuple containing the private key and public key in PEM format.
    """
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
    """
    @brief Encrypts the private key using a PIN.
    @param pin The PIN used for encryption.
    @param key The private key to be encrypted.
    @return The encrypted private key.
    """
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
    """
    @brief Saves a key to a specified file.
    @param file_path The path to the file where the key will be saved.
    @param key The key to be saved.
    """
    with open(file_path, 'wb') as f:
        f.write(key)
    print(f"Key saved to {file_path}.")

class KeyGenApp:
    """
    @class KeyGenApp
    @brief A GUI application for generating and encrypting RSA keys.
    """
    def __init__(self, root):
        """
        @brief Initializes the KeyGenApp class.
        @param root The root Tkinter window.
        """
        self.root = root
        self.root.title("RSA Key Generator")
        self.root.geometry("400x400")

        self.private_key_dir = None
        self.public_key_dir = None

        self.label = tk.Label(root, text="Enter PIN (4 digits):", font=("Arial", 12))
        self.label.pack(pady=10)

        self.pin_entry = tk.Entry(root, show="*", font=("Arial", 12), width=10)
        self.pin_entry.pack(pady=10)

        self.select_private_dir_button = tk.Button(root, text="Select Private Key Directory", command=self.select_private_directory, font=("Arial", 12))
        self.select_private_dir_button.pack(pady=10)

        self.select_public_dir_button = tk.Button(root, text="Select Public Key Directory", command=self.select_public_directory, font=("Arial", 12))
        self.select_public_dir_button.pack(pady=10)

        self.generate_button = tk.Button(root, text="Generate Keys", command=self.generate_keys, font=("Arial", 12))
        self.generate_button.pack(pady=20)

        self.status_label = tk.Label(root, text="Status: Waiting for action", font=("Arial", 10))
        self.status_label.pack(pady=10)

    def select_private_directory(self):
        """
        @brief Opens a dialog to select the directory for saving the private key.
        """
        directory = filedialog.askdirectory(title="Select Private Key Directory")
        if directory:
            self.private_key_dir = directory
            self.status_label.config(text=f"Status: Private key directory selected: {directory}")
            print(f"Private key directory selected: {directory}")
        else:
            self.status_label.config(text="Status: No private key directory selected")
            print("No private key directory selected.")

    def select_public_directory(self):
        """
        @brief Opens a dialog to select the directory for saving the public key.
        """
        directory = filedialog.askdirectory(title="Select Public Key Directory")
        if directory:
            self.public_key_dir = directory
            self.status_label.config(text=f"Status: Public key directory selected: {directory}")
            print(f"Public key directory selected: {directory}")
        else:
            self.status_label.config(text="Status: No public key directory selected")
            print("No public key directory selected.")

    def generate_keys(self):
        """
        @brief Generates RSA keys, encrypts the private key, and saves them to the selected directories.
        """
        if not self.private_key_dir or not self.public_key_dir:
            messagebox.showerror("Error", "Please select both private and public key directories.")
            print("Error: Directories not selected.")
            return

        pin = self.pin_entry.get()
        if len(pin) != 4 or not pin.isdigit():
            messagebox.showerror("Error", "PIN must be exactly 4 digits.")
            print("Error: Invalid PIN format.")
            return

        try:
            private_key, public_key = gen_key()
            encrypted_key = encrypt_pin(pin, private_key)

            private_key_path = f"{self.private_key_dir}/private_key.pem"
            public_key_path = f"{self.public_key_dir}/public_key.pem"

            save_key_to_file(private_key_path, encrypted_key)
            save_key_to_file(public_key_path, public_key)

            self.status_label.config(text="Status: Keys generated successfully!")
            messagebox.showinfo("Success", "Keys have been generated and saved.")
            print("Keys generation and saving completed successfully.")
        except Exception as e:
            self.status_label.config(text="Status: Error during key generation.")
            messagebox.showerror("Error", f"An error occurred: {e}")
            print(f"Error: {e}")

def main():
    """
    @brief The main entry point of the application.
    """
    root = tk.Tk()
    app = KeyGenApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()