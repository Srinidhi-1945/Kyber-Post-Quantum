from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import secrets

# ================= REAL DIFFIE-HELLMAN =================

def dh_generate():
    p = 23
    g = 5

    a = secrets.randbelow(p)
    b = secrets.randbelow(p)

    A = pow(g, a, p)
    B = pow(g, b, p)

    shared_a = pow(B, a, p)
    shared_b = pow(A, b, p)

    return {
        "p": p,
        "g": g,
        "A": A,
        "B": B,
        "key": shared_a
    }

# ================= AES ENCRYPTION =================

def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), 16))

    return encrypted


def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)

    return decrypted.decode()