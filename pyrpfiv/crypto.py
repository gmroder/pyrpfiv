import os
import hashlib
from Crypto.Cipher import AES

from .constants import KEY_OFFSETS, KEY_SHA1S
from .exceptions import AESKeyExtractionError, TOCDecryptionError


def try_extract_key(exe_path, offset, expected_sha1):
    """Helper function to try extracting key from a specific offset."""
    with open(exe_path, 'rb') as f:
        f.seek(offset)
        possible_key = f.read(32)
        if len(possible_key) != 32:
            return None
        key_sha1 = hashlib.sha1(possible_key).hexdigest().upper()
        if key_sha1 == expected_sha1:
            return possible_key
    return None


def extract_aes_key(exe_path):
    """Extracts the AES key from GTAIV.exe, supporting multiple versions."""
    if not os.path.exists(exe_path):
        raise AESKeyExtractionError(f"GTAIV.exe not found at path: {exe_path}")

    print(f"Extracting AES key from {exe_path}...")
    try:
        for version, offset in KEY_OFFSETS.items():
            key = try_extract_key(exe_path, offset, KEY_SHA1S[version])
            if key:
                print(f"AES key found and verified at offset 0x{offset:X} (Version {version}).")
                return key

        raise AESKeyExtractionError('Could not find valid AES key at any known offset.')
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
