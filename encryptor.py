# encryptor.py
# This file encrypts and decrypts secret messages

from cryptography.fernet import Fernet

def load_key():
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
    return key

def encrypt_message(message, key):
    fernet = Fernet(key)
    message_bytes = message.encode()
    encrypted = fernet.encrypt(message_bytes)
    return encrypted

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_message)
    message = decrypted.decode()
    return message

def main():
    print("=== SecureComm Encryption Engine ===")
    
    key = load_key()
    print("Key loaded successfully!")
    
    message = input("Enter your secret message: ")
    
    encrypted = encrypt_message(message, key)
    print(f"\nEncrypted message: {encrypted}")
    
    decrypted = decrypt_message(encrypted, key)
    print(f"\nDecrypted message: {decrypted}")
    
    print("\nEncryption and Decryption successful!")

main()