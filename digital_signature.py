# digital_signature.py
# This file signs messages and verifies digital signatures

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def load_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key

def load_public_key():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )
    return public_key

def sign_message(message, private_key):
    message_bytes = message.encode()
    
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    message_bytes = message.encode()
    
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    print("=== SecureComm Digital Signature System ===")
    
    private_key = load_private_key()
    public_key = load_public_key()
    print("Keys loaded successfully!")
    
    message = input("\nEnter the message to sign: ")
    
    signature = sign_message(message, private_key)
    print(f"\nSignature created: {signature}")
    
    is_valid = verify_signature(message, signature, public_key)
    print(f"\nSignature valid: {is_valid}")
    
    print("\nNow let's test with a TAMPERED message...")
    fake_message = message + " (HACKED)"
    is_valid_fake = verify_signature(fake_message, signature, public_key)
    print(f"Tampered message signature valid: {is_valid_fake}")

main()