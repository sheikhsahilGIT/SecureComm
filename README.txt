#cryptography communication toolkit
A python application demonstrating cryptography concept like symmetric and asymmetric encryption, digital signatures along with file encryption and decryption.
Built using the cryptography library in python interactive learning purpose


#functionalities
*Symmetric encryption-Fernet/AES
*Asymmetric encryption-RSA
*DigitaL signature
*File encryption and decryption
*Interactive menu
*Exception handling

#Working
This is built as a single securecomm app.This stores its keys as object state,rather than passing keys around as loose variables.

#setup and working
***bash
git clone https://github.com/yourusername/SecureComm.git
cd SecureComm
python -m venv venv
venv\Scripts\activate
pip install cryptography==41.0.7
python securecomm_app.py