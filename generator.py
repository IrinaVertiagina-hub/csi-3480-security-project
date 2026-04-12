import secrets
import string
import math

# Uses secrets module to generate a crypographically secure password.
def generate_password(length: int, use_digits: bool, use_symbols: bool, use_uppercase: bool) -> str:
    charset = string.ascii_lowercase
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += string.punctuation

    return ''.join(secrets.choice(charset) for _ in range(length))

def calculate_entropy(password: str) -> float:
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)