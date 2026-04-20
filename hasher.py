import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import bcrypt

# Initialize Argon2 hasher with default parameters
argon2_hasher = PasswordHasher()

def hash_password(password: str, algorithm: str = "Argon2") -> str:
    """
    Hash a password using the specified algorithm.
    
    Args:
        password: The plaintext password to hash
        algorithm: Hashing algorithm - "Argon2" (recommended) or "SHA-256"
    
    Returns:
        The hashed password string
    
    Raises:
        ValueError: If algorithm is not supported
    """
    if algorithm == "Argon2":
        return argon2_hasher.hash(password)
    elif algorithm == "SHA-256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "bcrypt":
        return str(bcrypt.hashpw(password.encode(), bcrypt.gensalt()))
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'Argon2' or 'SHA-256'")

def verify_password(password: str, hashed: str, algorithm: str = "Argon2") -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The plaintext password to verify
        hashed: The stored hash to compare against
        algorithm: Hashing algorithm - must match the algorithm used for hashing
    
    Returns:
        True if password matches the hash, False otherwise
    
    Raises:
        ValueError: If algorithm is not supported
    """
    try:
        if algorithm == "Argon2":
            argon2_hasher.verify(hashed, password)
            return True
        elif algorithm == "SHA-256":
            return hashlib.sha256(password.encode()).hexdigest() == hashed
        elif algorithm == "bcrypt":
            password = password.removeprefix("b'").removesuffix("'")
            hashed = hashed.removeprefix("b'").removesuffix("'")
            return bcrypt.checkpw(password.encode(), hashed.encode())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'Argon2', 'SHA-256', or 'bcrypt'")
    except (VerifyMismatchError, VerificationError):
        return False
    except Exception:
        return False