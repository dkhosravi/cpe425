from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad, unpad
import itertools

PLAINTEXT = "this is the wireless security lab"

# RC4 key = 40 bit 1s = 5 bytes
RC4_KEY = bytes([0xFF] * 5)
RC4_KEY_SIZE = 40

# AES key = 128 bit 1s = 16 bytes
AES_KEY = bytes([0xFF] * 16)
AES_KEY_SIZE = 128

def aes_encryption():
    plaintext_encoded = PLAINTEXT.encode()
    cipher = AES.new(AES_KEY, AES.MODE_ECB)

    encrypted_aes = cipher.encrypt(pad(plaintext_encoded, AES.block_size))
    
    return encrypted_aes

def rc4_encryption():
    plaintext_encoded = PLAINTEXT.encode()
    cipher = ARC4.new(RC4_KEY)

    encrypted_rc4 = cipher.encrypt(plaintext_encoded)

    return encrypted_rc4

def crack_rc4(ciphertext):
    all_keys = itertools.product(range(256), repeat=int(RC4_KEY_SIZE / 8))
    for key in all_keys:
        key = bytes(key)
        cipher = ARC4.new(key)
        decrypted_ciphertext = cipher.decrypt(ciphertext)
        if PLAINTEXT.encode() in decrypted_ciphertext:
            print("RC4 Key:", key, "Decrypted Text:", decrypted_ciphertext.decode())
            return
    print("RC4 key not found.")

def crack_aes(ciphertext):
    all_keys = itertools.product(range(256), repeat=int(AES_KEY_SIZE / 8))
    for key in all_keys:
        key = bytes(key)
        cipher = AES.new(key, AES.MODE_ECB)
        try:
            decrypted_ciphertext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            if PLAINTEXT.encode() in decrypted_ciphertext:
                print("AES Key:", key, "Decrypted Text:", decrypted_ciphertext.decode())
                return
        except:
            pass
    print("AES key not found.")

if __name__ == "__main__":
    aes_encrypted = aes_encryption()
    print("AES Ciphertext:", " ".join(f'{byte:02x}' for byte in aes_encrypted))
    
    rc4_encrypted = rc4_encryption()
    print("RC4 Ciphertext:", " ".join(f'{byte:02x}' for byte in rc4_encrypted))
    
    crack_rc4(rc4_encrypted)
    crack_aes(aes_encrypted)