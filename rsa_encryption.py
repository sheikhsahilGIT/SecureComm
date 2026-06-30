# rsa_encryption.py
# This file generates RSA keys and encrypts/decrypts messages

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keys():
    print("Generating RSA keys...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    
    return private_key, public_key

def save_private_key(private_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Private key saved to private_key.pem!")
def save_public_key(public_key):
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Public key saved to public_key.pem!")

def encrypt_with_rsa(message, public_key):
    message_bytes = message.encode()
    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_with_rsa(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()
def main():
    print("=== SecureComm RSA Encryption ===")
    
    private_key, public_key = generate_rsa_keys()
    print("RSA keys generated successfully!")
    
    save_private_key(private_key)
    save_public_key(public_key)
    
    message = input("\nEnter your secret message: ")
    
    encrypted = encrypt_with_rsa(message, public_key)
    print(f"\nEncrypted message: {encrypted}")
    
    decrypted = decrypt_with_rsa(encrypted, private_key)
    print(f"\nDecrypted message: {decrypted}")
    
    print("\nRSA Encryption and Decryption successful!")

main()