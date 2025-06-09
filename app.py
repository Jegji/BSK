import datetime
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, simpledialog

from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

CONSTANT_SALT = b'\x00' * 16
CONSTANT_IV = b'\x00' * 16

class App:
    is_usb_connected = False
    private_key = None
    pin = None
    file = None
    correct_pin = None
    sign = None
    dataTest = None

    def __init__(self, root):
        self.root = root
        self.root.title("PDF Encryption Tool")
        self.root.geometry("350x200")

        self.status_label = tk.Label(root, text="Status: No file selected", height=2)
        self.status_label.pack(pady=10)

        self.browse_button = tk.Button(root, text="Browse File", command=lambda: setattr(self,'file',self.browse_file()), width=20, height=2)
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
            self.private_key = f.read()

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
        decrypted_data = decryptor.update(self.private_key) + decryptor.finalize()
        try:
            self.private_key = unpadder.update(decrypted_data) + unpadder.finalize()
            self.private_key = load_pem_private_key(self.private_key, password=None, backend=default_backend())
            correct_pin = True
        except ValueError as e:
            self.status_label.config(text="Status: Invalid pin")
            self.private_key = None
            self.pin = None
            self.correct_pin = None

    def ask_for_pin(self):
        pin_input = simpledialog.askstring("Input", "Please enter pin:")
        self.pin = pin_input

    def monitor_usb(self):
        while True:
            if self.check_usb():
                if not self.is_usb_connected:
                    self.is_usb_connected = True
                    self.root.after(0,self.get_key())
                    if self.private_key:
                        self.status_label.config(text="Status: USB drive detected with key")
                    else:
                        if not self.correct_pin:
                            self.status_label.config(text="Status: USB drive detected but invalid key")
                        else:
                            self.status_label.config(text="Status: USB drive detected but no key found")
            else:
                if self.is_usb_connected:
                    self.is_usb_connected = False
                    self.private_key = None
                    self.pin = None
                    self.status_label.config(text="Status: No USB drive detected")
            time.sleep(1)

    def browse_file(self, title= "Select a file"):
        file_path = filedialog.askopenfilename(title= title)
        if file_path:
            self.status_label.config(text=f"Status: File selected: {file_path}")
            return file_path
        else:
            self.status_label.config(text="Status: No file selected")
            return None

    def sign_data(self, file_path):
        reader = PdfReader(file_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        data = b"".join([page.extract_text().encode() for page in reader.pages])

        self.dataTest = data

        signature = self.private_key.sign(
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature:", signature.hex())
        self.sign = signature.hex()
        writer.add_metadata({
        "/Signature": signature.hex(),
        })

        with open(file_path, 'wb') as f:
            writer.write(f)

    def sign_button_click(self):
        if not self.file:
            self.status_label.config(text="Status: No file selected")
            return
        if not self.private_key:
            self.status_label.config(text="Status: No key found")
            return
        self.status_label.config(text="Status: Signing...")

        self.sign_data(self.file)
        self.status_label.config(text="Status: File signed successfully")

    def validate_signature(self, file_path,public_key_path):
        reader = PdfReader(file_path)

        signature_hex = reader.metadata.get("/Signature", "")
        if not signature_hex:
            print("Brak podpisu w metadanych")
            return False

        signature = bytes.fromhex(signature_hex)

        data = b"".join([page.extract_text().encode() for page in reader.pages])

        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())

        try:
            public_key.verify(
                signature,
                data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid")
            return True
        except Exception as e:
            print("Signature is invalid:", e)
            return False

    def validate_button_click(self):
        if not self.file:
            self.status_label.config(text="Status: No file selected")
            return
        public_key_path = self.browse_file(title= "Select a file with public key")
        if not public_key_path:
            self.status_label.config(text="Status: No public key selected")
            return

        self.status_label.config(text="Status: Validating...")
        if self.validate_signature(self.file,public_key_path):
            self.status_label.config(text="Status: Signature is valid")
        else:
            self.status_label.config(text="Status: Signature is invalid")

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":

    main()