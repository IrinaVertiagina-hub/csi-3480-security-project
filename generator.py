import secrets
import string
import math

# Uses secrets module to generate a crypographically secure password.
def generate_password(length: int, charset: string) -> str:
    return ''.join(secrets.choice(charset) for _ in range(length))

def calculate_entropy(password: str, charset_size: int) -> float:
    # Flawed code, only adds charset_size if a character from that charset is used in the password, which isn't a 100% chance. (Though mathematical entropy isn't the same as practical entropy, as simple passwords are still picked out and guessed even if having theoretical high entropy due to length or the charset variety provided.)
    # charset_size = 0
    # if any(c in string.ascii_lowercase for c in password):
    #     charset_size += 26
    # if any(c in string.ascii_uppercase for c in password):
    #     charset_size += 26
    # if any(c in string.digits for c in password):
    #     charset_size += 10
    # if any(c in string.punctuation for c in password):
    #     charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)