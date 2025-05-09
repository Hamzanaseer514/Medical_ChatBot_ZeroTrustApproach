import random
import json
import os
import logging

# Set up logging
logger = logging.getLogger(__name__)

# ---------- RSA Helper Functions ----------

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0: return False
    return True

def generate_prime(start=1000, end=5000):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

# ---------- RSA Core ----------

def generate_keys():
    logger.info("Generating new RSA keys")
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(text, pub_key, use_nonce=True):
    if not text:
        return ''
    e, n = pub_key
    if use_nonce:
        nonce = str(os.urandom(8).hex())
        text_with_nonce = f"{text}:{nonce}"
        logger.debug(f"Encrypting text {text_with_nonce} with public key (e={e}, n={n})")
        return json.dumps([pow(ord(c), e, n) for c in text_with_nonce])
    else:
        logger.debug(f"Encrypting text {text} with public key (e={e}, n={n}) without nonce")
        return json.dumps([pow(ord(c), e, n) for c in text])

def rsa_decrypt(cipher_json, priv_key):
    if not cipher_json:
        return ''
    d, n = priv_key
    try:
        logger.debug(f"Decrypting with private key (d={d}, n={n})")
        cipher = json.loads(cipher_json)
        decrypted_text = ''.join([chr(pow(c, d, n)) for c in cipher])
        # Remove nonce if present
        return decrypted_text.split(':')[0]
    except Exception as ex:
        logger.error(f"Decryption failed: {str(ex)}")
        return cipher_json