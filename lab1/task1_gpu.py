import numpy as np
from numba import cuda
from Crypto.Cipher import ARC4

PLAINTEXT = "this is the wireless security lab"
PLAINTEXT_BYTES = PLAINTEXT.encode()

RC4_KEY_SIZE = 40  # Full 40-bit key
RC4_KEY = bytes([0xFF] * 5)
KEYSPACE_SIZE = 2 ** RC4_KEY_SIZE

def rc4_encryption():
    cipher = ARC4.new(RC4_KEY)
    encrypted = cipher.encrypt(PLAINTEXT_BYTES)
    return encrypted

@cuda.jit
def rc4_crack_kernel(ciphertext, plaintext, key_offset, found_key, found_flag):
    idx = cuda.grid(1)
    global_idx = idx + key_offset

    if found_flag[0]:
        return

    if global_idx >= KEYSPACE_SIZE:
        return

    key = cuda.local.array(5, dtype=np.uint8)

    tmp = global_idx
    for i in range(5):
        key[i] = tmp & 0xFF
        tmp >>= 8

    S = cuda.local.array(256, dtype=np.uint8)
    for i in range(256):
        S[i] = i

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % 5]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = j = 0
    match = True
    for c in range(len(plaintext)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        decrypted_byte = ciphertext[c] ^ K
        if decrypted_byte != plaintext[c]:
            match = False
            break

    if match:
        found_flag[0] = True
        for n in range(5):
            found_key[n] = key[n]

def crack_rc4_gpu_iterative(ciphertext, plaintext, batch_size=2**20):
    threads_per_block = 512
    blocks_per_batch = (batch_size + threads_per_block - 1) // threads_per_block

    ciphertext_gpu = cuda.to_device(np.frombuffer(ciphertext, dtype=np.uint8))
    plaintext_gpu = cuda.to_device(np.frombuffer(plaintext, dtype=np.uint8))
    found_key_gpu = cuda.device_array(5, dtype=np.uint8)
    found_flag_gpu = cuda.to_device(np.array([False], dtype=np.bool_))

    total_batches = (KEYSPACE_SIZE + batch_size - 1) // batch_size

    print(f"Total batches: {total_batches}, Batch size: {batch_size}")

    for batch in range(total_batches):
        key_offset = batch * batch_size

        print(f"Checking batch {batch + 1}/{total_batches} starting at key {key_offset}")

        rc4_crack_kernel[blocks_per_batch, threads_per_block](
            ciphertext_gpu, plaintext_gpu, key_offset, found_key_gpu, found_flag_gpu)

        cuda.synchronize()

        if found_flag_gpu.copy_to_host()[0]:
            key_found = bytes(found_key_gpu.copy_to_host())
            print("RC4 Key found:", key_found.hex())
            return

    print("RC4 Key not found in keyspace.")

if __name__ == "__main__":
    rc4_encrypted = rc4_encryption()
    print("RC4 Ciphertext:", " ".join(f'{byte:02x}' for byte in rc4_encrypted))

    # Try batch sizes of 1 million (~1 second per batch on modern GPUs)
    crack_rc4_gpu_iterative(rc4_encrypted, PLAINTEXT_BYTES, batch_size=2**20)