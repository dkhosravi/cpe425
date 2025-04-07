from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

PLAINTEXT = "this is a repeatthis is a repeatthis is a repeat"
AES_KEY = get_random_bytes(16)
AES_IV = get_random_bytes(16)
AES_NONCE = get_random_bytes(8)

def aes_encryption(mode):
    plaintext_encoded = PLAINTEXT.encode()
    if mode == AES.MODE_ECB:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
    elif mode == AES.MODE_CTR:
        cipher = AES.new(AES_KEY, AES.MODE_CTR, nonce=AES_NONCE)
    else:
        cipher = AES.new(AES_KEY, mode, iv=AES_IV)

    encrypted_aes = cipher.encrypt(pad(plaintext_encoded, AES.block_size))
    
    return encrypted_aes

def aes_decryption(mode, ciphertext):
    if mode == AES.MODE_ECB:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
    elif mode == AES.MODE_CTR:
        cipher = AES.new(AES_KEY, AES.MODE_CTR, nonce=AES_NONCE)
    else:
        cipher = AES.new(AES_KEY, mode, iv=AES_IV)

    decrypted_aes = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return decrypted_aes

if __name__ == "__main__":
    plaintext_encoded = PLAINTEXT.encode()
    modes = [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB, AES.MODE_CTR]

    for mode in modes:
        aes_encrypted = aes_encryption(mode)
        print("Ciphertext:", " ".join(f'{byte:02x}' for byte in aes_encrypted))

        aes_modified = aes_encrypted[0:2] + bytes([aes_encrypted[3]]) + bytes([aes_encrypted[2]]) + aes_encrypted[4:]

        aes_decrypted = aes_decryption(mode, aes_modified)
        print("Original plaintext:", " ".join(f'{byte:02x}' for byte in plaintext_encoded))
        print("Decoded:           ", " ".join(f'{byte:02x}' for byte in aes_decrypted))
        print()
