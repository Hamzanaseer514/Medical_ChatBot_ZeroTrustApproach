import random
import string

def generate_salt(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def custom_manual_hash(combined):
    hash_value = 0
    for i, char in enumerate(combined):
        hash_value += (ord(char) * (i + 1)) ^ (hash_value >> 2)
        hash_value = (hash_value * 17) & 0xFFFFFFFF
    return format(hash_value, 'x').zfill(8)

def hash_password(password):
    salt = generate_salt()
    combined = password + salt
    hash_value = custom_manual_hash(combined)
    return salt + '$' + hash_value  # Store salt and hash together

def verify_password(stored_password, provided_password):
    salt, stored_hash = stored_password.split('$')
    combined = provided_password + salt
    provided_hash = custom_manual_hash(combined)
    return stored_hash == provided_hash


