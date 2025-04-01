import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, simpledialog

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding


CONSTANT_SALT = b'\x00' * 16
CONSTANT_IV = b'\x00' * 16

class App:
    is_usb_connected = False
    key = None
    pin = None
    file = None

    def __init__(self, root):
        self.root = root
        self.root.title("PDF Encryption Tool")
        self.root.geometry("350x200")

        self.status_label = tk.Label(root, text="Status: No file selected", height=2)
        self.status_label.pack(pady=10)

        self.browse_button = tk.Button(root, text="Browse File", command=self.browse_file, width=20, height=2)
        self.browse_button.pack(pady=10)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)

        self.sign_button = tk.Button(button_frame, text="Sign", command=self.sign_button_click, width=12, height=3)
        self.sign_button.pack(side=tk.LEFT, padx=10)

        self.validate_button = tk.Button(button_frame, text="Validate", command=self.validate_button_click, width=12, height=3)
        self.validate_button.pack(side=tk.LEFT, padx=10)

        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def check_usb(self):
        drive_letter = "E:"
        if os.path.exists(drive_letter + "\\"):
            return True
        else:
            return False

    def get_key(self):
        drive_letter = "E:"
        key_file_path = os.path.join(drive_letter, "private_key.pem")
        if not os.path.exists(key_file_path):
            return False

        with open(key_file_path, 'rb') as f:
            self.key = f.read()

        self.root.after(0, self.ask_for_pin)

        while self.pin is None:
            time.sleep(1)

        pin_bytes = self.pin.encode('utf-8')
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
        decrypted_data = decryptor.update(self.key) + decryptor.finalize()
        try:
            self.key = unpadder.update(decrypted_data) + unpadder.finalize()
            self.key = serialization.load_pem_private_key(self.key, password=None, backend=default_backend())
        except ValueError as e:
            print("Wrong pin")

    def ask_for_pin(self):
        pin_input = simpledialog.askstring("Input", "Please enter pin:")
        self.pin = pin_input

    def monitor_usb(self):
        while True:
            if self.check_usb():
                if not self.is_usb_connected:
                    self.is_usb_connected = True
                    self.root.after(0,self.get_key())
                    if self.key:
                        self.status_label.config(text="Status: USB drive detected with key")
                    else:
                        self.status_label.config(text="Status: USB drive detected but no key found")
            else:
                if self.is_usb_connected:
                    self.is_usb_connected = False
                    self.key = None
                    self.pin = None
                    self.status_label.config(text="Status: No USB drive detected")
            time.sleep(1)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.status_label.config(text=f"Status: File selected: {file_path}")
            self.file = file_path
        else:
            self.status_label.config(text="Status: No file selected")

    def sign_data(self, data: bytes):
        self.key.sign(
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def sign_button_click(self):
        if not self.file:
            self.status_label.config(text="Status: No file selected")
            return
        if not self.key:
            self.status_label.config(text="Status: No key found")
            return
        self.status_label.config(text="Status: Signing...")

        with open(self.file, 'rb') as f:
            data = f.read()

        self.sign_data(data)
        self.status_label.config(text="Status: File signed successfully")

    def validate_button_click(self):
        self.status_label.config(text="Status: Validating...")
def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()