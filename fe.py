# file_encryptor.py
# Professional version with exception handling

from cryptography.fernet import Fernet, InvalidToken
import os

def load_key():
    """Load the secret key from secret.key file."""
    try:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        print("Error: secret.key not found. Run key_generator.py first.")
        return None

def encrypt_file(filename, key):
    """Encrypt a file and save it with .encrypted extension."""
    if not os.path.exists(filename):
        print(f"Error: '{filename}' does not exist. Check the filename and try again.")
        return False

    try:
        fernet = Fernet(key)

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
    except Exception as e:
        print(f"Unexpected error during encryption: {e}")
        return False

def decrypt_file(encrypted_filename, key):
    """Decrypt a file and save it with .decrypted extension."""
    if not os.path.exists(encrypted_filename):
        print(f"Error: '{encrypted_filename}' does not exist. Check the filename and try again.")
        return False

    try:
        fernet = Fernet(key)

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
    except Exception as e:
        print(f"Unexpected error during decryption: {e}")
        return False

def main():
    print("=== SecureComm File Encryption System ===")

    key = load_key()
    if key is None:
        return

    print("Key loaded successfully!")

    print("\n1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose an option (1 or 2): ").strip()

    if choice == "1":
        filename = input("Enter the filename to encrypt: ").strip()
        encrypt_file(filename, key)
    elif choice == "2":
        filename = input("Enter the filename to decrypt: ").strip()
        decrypt_file(filename, key)
    else:
        print("Invalid choice! Please enter 1 or 2.")

if __name__ == "__main__":
    main()