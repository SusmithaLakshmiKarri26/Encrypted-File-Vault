import os
import secrets
import numpy as np
import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 64 * 1024  # 64KB per chunk

def generate_s_box():
    """Generate a random S-Box permutation of 256 values."""
    s_box = list(range(256))  # Standard 0-255 range
    secrets.SystemRandom().shuffle(s_box)  # Cryptographic shuffle
    return np.array(s_box, dtype=np.uint8)  # Convert to NumPy array

def reverse_s_box_lookup(s_box):
    """Compute the reverse S-Box for decryption."""
    return np.argsort(s_box).astype(np.uint8)

def derive_keys(password, salt):
    """Derive encryption keys using PBKDF2 with SHA-512."""
    keys = PBKDF2(password, salt, 64, count=1_000_000, hmac_hash_module=SHA512)
    return keys[:32], keys[32:]  # Split into AES key and S-Box key

def encrypt_file(file_path, password):
    """Encrypt a file using AES-GCM with dynamic S-Box and PBKDF2."""
    salt = get_random_bytes(16)
    key_aes, key_sbox = derive_keys(password, salt)

    iv = get_random_bytes(16)
    s_box = generate_s_box()

    sbox_cipher = AES.new(key_sbox, AES.MODE_GCM)
    encrypted_s_box, sbox_tag = sbox_cipher.encrypt_and_digest(s_box.tobytes())

    encrypted_path = file_path + ".enc"

    with open(file_path, 'rb') as infile, open(encrypted_path, 'wb') as outfile:
        outfile.write(salt)
        outfile.write(iv)
        outfile.write(sbox_cipher.nonce)
        outfile.write(encrypted_s_box)
        outfile.write(sbox_tag)

        cipher = AES.new(key_aes, AES.MODE_GCM, nonce=iv)

        while chunk := infile.read(CHUNK_SIZE):
            chunk_array = np.frombuffer(chunk, dtype=np.uint8)
            substituted_chunk = s_box[chunk_array]
            ciphertext, tag = cipher.encrypt_and_digest(substituted_chunk.tobytes())
            outfile.write(ciphertext + tag)

    return encrypted_path

def decrypt_file(file_url, password):
    """Download and decrypt an encrypted file from a URL."""
    response = requests.get(file_url)
    if response.status_code != 200:
        return None

    encrypted_data = response.content
    from io import BytesIO
    infile = BytesIO(encrypted_data)

    salt = infile.read(16)
    key_aes, key_sbox = derive_keys(password, salt)

    iv = infile.read(16)
    sbox_nonce = infile.read(16)
    encrypted_s_box = infile.read(256)
    sbox_tag = infile.read(16)

    try:
        sbox_cipher = AES.new(key_sbox, AES.MODE_GCM, nonce=sbox_nonce)
        s_box = np.frombuffer(sbox_cipher.decrypt_and_verify(encrypted_s_box, sbox_tag), dtype=np.uint8)
        reverse_s_box = reverse_s_box_lookup(s_box)

        cipher = AES.new(key_aes, AES.MODE_GCM, nonce=iv)

        decrypted_path = "decrypted_output"
        with open(decrypted_path, 'wb') as outfile:
            while chunk := infile.read(CHUNK_SIZE + 16):
                ciphertext, tag = chunk[:-16], chunk[-16:]
                decrypted_chunk = cipher.decrypt_and_verify(ciphertext, tag)
                original_chunk = reverse_s_box[np.frombuffer(decrypted_chunk, dtype=np.uint8)]
                outfile.write(original_chunk.tobytes())
        return decrypted_path
    except Exception:
        return None
