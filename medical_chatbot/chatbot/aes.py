import os
from dotenv import load_dotenv

ENV_FILE = ".env"
KEY_NAME = "AES_SECRET_KEY"

# Load existing .env
load_dotenv()

class SimpleEncryptor:
    def __init__(self):
        self.key = self._get_or_create_key()

    def _get_or_create_key(self):
        key = os.getenv(KEY_NAME)

        if key:
            return bytes.fromhex(key)        # if key available then convert it into bytes

        random_key = os.urandom(32)            # otherwise generata
        self._write_key_to_env(random_key)
        return random_key

    def _write_key_to_env(self, key_bytes):
        hex_key = key_bytes.hex()
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, 'a') as f:                     #file exist then write 
                f.write(f'\n{KEY_NAME}={hex_key}\n')
        else:
            with open(ENV_FILE, 'w') as f:
                f.write(f'{KEY_NAME}={hex_key}\n')

    def _pad(self, data: bytes):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes):
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, plain_text: str) -> bytes:
        data = self._pad(plain_text.encode())
        iv = os.urandom(16)
        result = iv
        prev = iv

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            step1 = bytes(a ^ b for a, b in zip(block, prev))             # XOR with IV/prev block line we do in cbc 
            step2 = bytes(a ^ b for a, b in zip(step1, self.key[:16]))    # XOR with first 16B of key
            result += step2
            prev = step2

        return result

    def decrypt(self, encrypted_data: bytes) -> str:
        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        prev = iv
        result = b''

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            step1 = bytes(a ^ b for a, b in zip(block, self.key[:16]))    # XOR with key
            step2 = bytes(a ^ b for a, b in zip(step1, prev))             # XOR with prev block
            result += step2
            prev = block

        return self._unpad(result).decode()
