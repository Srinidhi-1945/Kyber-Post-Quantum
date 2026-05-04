def encrypt(msg, key):
    return ''.join(chr(ord(c) ^ key) for c in msg)

def decrypt(cipher, key):
    return ''.join(chr(ord(c) ^ key) for c in cipher)