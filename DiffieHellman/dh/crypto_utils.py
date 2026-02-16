from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def derive_key(shared):
    return SHA256.new(str(shared).encode()).digest()

def encrypt(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    return iv, cipher.encrypt(data)

def decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    pad = plaintext[-1]
    return plaintext[:-pad]
