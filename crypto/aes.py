from cryptography.fernet import Fernet
import os

KEY_PATH = 'data/aes.key'
os.makedirs('data', exist_ok=True)

if os.path.exists(KEY_PATH):
    with open(KEY_PATH, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_PATH, 'wb') as f:
        f.write(key)

fernet = Fernet(key)

def encrypt(data):
    return fernet.encrypt(data)

def decrypt(data):
    return fernet.decrypt(data)
