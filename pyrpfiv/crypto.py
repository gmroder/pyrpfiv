import os
import hashlib
from Crypto.Cipher import AES

from .constants import KEY_OFFSET, EXPECTED_KEY_SHA1
from .exceptions import AESKeyExtractionError, TOCDecryptionError


def extract_aes_key(exe_path):
    """Extracts the AES key from GTAIV.exe."""
    if not os.path.exists(exe_path):
        raise AESKeyExtractionError(f"GTAIV.exe not found at path: {exe_path}")

    print(f"Extracting AES key from {exe_path}...")
    try:
        with open(exe_path, 'rb') as f:
            f.seek(KEY_OFFSET)
            possible_key = f.read(32)
            if len(possible_key) != 32:
                raise AESKeyExtractionError('Could not read 32 bytes at the expected key offset.')
            key_sha1 = hashlib.sha1(possible_key).hexdigest().upper()
            if key_sha1 == EXPECTED_KEY_SHA1:
                print(f"AES key found and verified at offset 0x{KEY_OFFSET:X}.")
                return possible_key
            else:
                raise AESKeyExtractionError('AES key SHA1 hash does not match the expected value.')
    except Exception as e:
        raise AESKeyExtractionError(f'Error extracting AES key: {e}')


def decrypt_toc(data, aes_key):
    """Decrypts the TOC data using AES ECB mode."""
    if len(data) % 16 != 0:
        raise TOCDecryptionError('Encrypted TOC data size is not a multiple of 16 bytes.')

    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_data = data

    for _ in range(16):
        decrypted_data = cipher.decrypt(decrypted_data)

    return decrypted_data
