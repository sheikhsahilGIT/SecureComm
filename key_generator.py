# key_generator.py
# This file generates a secret key for encrypting messages

from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    return key

def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key saved successfully to secret.key!")

def main():
    print("=== SecureComm Key Generator ===")
    key = generate_key()
    print(f"Your secret key is: {key}")
    save_key(key)

main()