# securecomm_app.py
# The unified SecureComm application

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os


class SecureComm:
    """
    A unified secure communication system combining symmetric encryption,
    asymmetric encryption, digital signatures, and file encryption.
    """

    def __init__(self):
        """This runs automatically when we create a SecureComm object."""
        self.fernet_key = None
        self.private_key = None
        self.public_key = None
        print("SecureComm system initialized.")

    def generate_fernet_key(self):
        """Generate a new Fernet key and store it in this object."""
        self.fernet_key = Fernet.generate_key()
        print("Fernet key generated and stored in memory.")

    def save_fernet_key(self, filename="secret.key"):
        """Save the current Fernet key to a file."""
        if self.fernet_key is None:
            print("Error: No key to save. Generate a key first.")
            return
        try:
            with open(filename, "wb") as key_file:
                key_file.write(self.fernet_key)
            print(f"Key saved to {filename}")
        except PermissionError:
            print(f"Error: Permission denied writing to {filename}")

    def generate_rsa_keys(self):
        """Generate RSA private and public key pair, store in this object."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        print("RSA key pair generated and stored in memory.")

    def save_rsa_keys(self, private_filename="private_key.pem", public_filename="public_key.pem"):
        """Save the RSA private and public keys to files."""
        if self.private_key is None or self.public_key is None:
            print("Error: No RSA keys to save. Generate keys first.")
            return
        try:
            with open(private_filename, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            with open(public_filename, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )

            print(f"RSA keys saved to {private_filename} and {public_filename}")

        except PermissionError:
            print("Error: Permission denied writing RSA key files.")

    def load_rsa_keys(self, private_filename="private_key.pem", public_filename="public_key.pem"):
        """Load existing RSA keys from files into this object."""
        try:
            with open(private_filename, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )

            with open(public_filename, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read()
                )

            print("RSA keys loaded successfully.")

        except FileNotFoundError:
            print("Error: RSA key files not found. Generate keys first.")

    def encrypt_text(self, message):
        """Encrypt a text message using the stored Fernet key."""
        if self.fernet_key is None:
            print("Error: No Fernet key available. Generate or load one first.")
            return None

        fernet = Fernet(self.fernet_key)
        encrypted = fernet.encrypt(message.encode())
        return encrypted

    def decrypt_text(self, encrypted_message):
        """Decrypt a text message using the stored Fernet key."""
        if self.fernet_key is None:
            print("Error: No Fernet key available. Generate or load one first.")
            return None

        fernet = Fernet(self.fernet_key)

        try:
            decrypted = fernet.decrypt(encrypted_message)
            return decrypted.decode()

        except InvalidToken:
            print("Error: Decryption failed. Wrong key or corrupted message.")
            return None

    def sign_message(self, message):
        """Sign a message using the stored private key."""
        if self.private_key is None:
            print("Error: No private key available. Generate or load RSA keys first.")
            return None

        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message, signature):
        """Verify a message's signature using the stored public key."""
        if self.public_key is None:
            print("Error: No public key available. Generate or load RSA keys first.")
            return False

        try:
            self.public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False  
    def encrypt_file(self, filename):
        """Encrypt a file using the stored Fernet key."""
        if self.fernet_key is None:
            print("Error: No Fernet key available. Generate or load one first.")
            return False

        if not os.path.exists(filename):
            print(f"Error: '{filename}' does not exist.")
            return False

        try:
            fernet = Fernet(self.fernet_key)

            with open(filename, "rb") as file:
                file_data = file.read()

            encrypted_data = fernet.encrypt(file_data)

            encrypted_filename = filename + ".encrypted"
            with open(encrypted_filename, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)

            print(f"File encrypted successfully! Saved as: {encrypted_filename}")
            return True

        except PermissionError:
            print(f"Error: Permission denied when accessing '{filename}'.")
            return False

    def decrypt_file(self, encrypted_filename):
        """Decrypt a file using the stored Fernet key."""
        if self.fernet_key is None:
            print("Error: No Fernet key available. Generate or load one first.")
            return False

        if not os.path.exists(encrypted_filename):
            print(f"Error: '{encrypted_filename}' does not exist.")
            return False

        try:
            fernet = Fernet(self.fernet_key)

            with open(encrypted_filename, "rb") as file:
                encrypted_data = file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            decrypted_filename = encrypted_filename.replace(".encrypted", ".decrypted")
            with open(decrypted_filename, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            print(f"File decrypted successfully! Saved as: {decrypted_filename}")
            return True

        except InvalidToken:
            print("Error: Decryption failed. Wrong key or corrupted file.")
            return False
        except PermissionError:
            print(f"Error: Permission denied when accessing '{encrypted_filename}'.")
            return False  
        
    def run_menu(self):
        """Interactive menu to use all SecureComm features."""
        while True:
            print("\n" + "=" * 40)
            print("       SECURECOMM MAIN MENU")
            print("=" * 40)
            print("1. Generate Fernet key")
            print("2. Generate RSA key pair")
            print("3. Load existing RSA keys")
            print("4. Encrypt a text message")
            print("5. Decrypt a text message")
            print("6. Sign a message")
            print("7. Verify a signature")
            print("8. Encrypt a file")
            print("9. Decrypt a file")
            print("0. Exit")

            choice = input("Choose an option: ").strip()

            if choice == "1":
                self.generate_fernet_key()
                self.save_fernet_key()

            elif choice == "2":
                self.generate_rsa_keys()
                self.save_rsa_keys()

            elif choice == "3":
                self.load_rsa_keys()

            elif choice == "4":
                msg = input("Enter message to encrypt: ")
                result = self.encrypt_text(msg)
                if result:
                    print(f"Encrypted: {result}")

            elif choice == "5":
                print("Note: paste encrypted bytes exactly as shown, including b'...'")
                enc_input = input("Enter encrypted message: ")
                try:
                    enc_bytes = eval(enc_input)
                    result = self.decrypt_text(enc_bytes)
                    if result:
                        print(f"Decrypted: {result}")
                except Exception:
                    print("Error: Invalid encrypted message format.")

            elif choice == "6":
                msg = input("Enter message to sign: ")
                sig = self.sign_message(msg)
                if sig:
                    print(f"Signature: {sig}")
                    self.last_signature = sig
                    self.last_signed_message = msg

            elif choice == "7":
                if hasattr(self, "last_signature"):
                    is_valid = self.verify_signature(self.last_signed_message, self.last_signature)
                    print(f"Signature valid: {is_valid}")
                else:
                    print("Error: No signature created yet in this session.")

            elif choice == "8":
                filename = input("Enter filename to encrypt: ").strip()
                self.encrypt_file(filename)

            elif choice == "9":
                filename = input("Enter filename to decrypt: ").strip()
                self.decrypt_file(filename)

            elif choice == "0":
                print("Exiting SecureComm. Goodbye!")
                break

            else:
                print("Invalid choice! Please try again.")
if __name__=="__main__":
    app=SecureComm()
    app.run_menu()