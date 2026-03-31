def hash_password(password: str, algorithm: str = "Argon2") -> str:
    """
    Hash a password using the specified algorithm.
    Supported: Argon2, SHA-256
    TODO: implement using argon2-cffi and hashlib
    """
    pass

def verify_password(password: str, hashed: str, algorithm: str = "Argon2") -> bool:
    """
    Verify a password against a stored hash.
    TODO: implement
    """
    pass