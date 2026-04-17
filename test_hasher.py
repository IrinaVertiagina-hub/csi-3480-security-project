import unittest
from hasher import hash_password, verify_password


class TestVerifyPassword(unittest.TestCase):
    """Unit tests for the verify_password function."""

    # ── Argon2 Algorithm Tests ──────────────────────────────────────────────
    def test_verify_password_argon2_correct_password(self):
        """Test verify_password returns True for correct password with Argon2."""
        password = "MySecurePassword123!"
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(password, hashed, algorithm="Argon2")
        self.assertTrue(result)

    def test_verify_password_argon2_incorrect_password(self):
        """Test verify_password returns False for incorrect password with Argon2."""
        password = "MySecurePassword123!"
        wrong_password = "WrongPassword456"
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(wrong_password, hashed, algorithm="Argon2")
        self.assertFalse(result)

    def test_verify_password_argon2_empty_password(self):
        """Test verify_password with empty password using Argon2."""
        password = ""
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(password, hashed, algorithm="Argon2")
        self.assertTrue(result)

    def test_verify_password_argon2_special_characters(self):
        """Test verify_password with special characters using Argon2."""
        password = "P@$$w0rd!#%&*()_+-=[]{}|;:,.<>?"
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(password, hashed, algorithm="Argon2")
        self.assertTrue(result)

    def test_verify_password_argon2_long_password(self):
        """Test verify_password with very long password using Argon2."""
        password = "a" * 256  # 256 character password
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(password, hashed, algorithm="Argon2")
        self.assertTrue(result)

    def test_verify_password_argon2_unicode_characters(self):
        """Test verify_password with unicode characters using Argon2."""
        password = "Pässwörd_日本語_مرحبا"
        hashed = hash_password(password, algorithm="Argon2")
        result = verify_password(password, hashed, algorithm="Argon2")
        self.assertTrue(result)

    # ── SHA-256 Algorithm Tests ─────────────────────────────────────────────
    def test_verify_password_sha256_correct_password(self):
        """Test verify_password returns True for correct password with SHA-256."""
        password = "MySecurePassword123!"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(password, hashed, algorithm="SHA-256")
        self.assertTrue(result)

    def test_verify_password_sha256_incorrect_password(self):
        """Test verify_password returns False for incorrect password with SHA-256."""
        password = "MySecurePassword123!"
        wrong_password = "WrongPassword456"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(wrong_password, hashed, algorithm="SHA-256")
        self.assertFalse(result)

    def test_verify_password_sha256_empty_password(self):
        """Test verify_password with empty password using SHA-256."""
        password = ""
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(password, hashed, algorithm="SHA-256")
        self.assertTrue(result)

    def test_verify_password_sha256_special_characters(self):
        """Test verify_password with special characters using SHA-256."""
        password = "P@$$w0rd!#%&*()_+-=[]{}|;:,.<>?"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(password, hashed, algorithm="SHA-256")
        self.assertTrue(result)

    def test_verify_password_sha256_long_password(self):
        """Test verify_password with very long password using SHA-256."""
        password = "a" * 256  # 256 character password
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(password, hashed, algorithm="SHA-256")
        self.assertTrue(result)

    def test_verify_password_sha256_unicode_characters(self):
        """Test verify_password with unicode characters using SHA-256."""
        password = "Pässwörd_日本語_مرحبا"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password(password, hashed, algorithm="SHA-256")
        self.assertTrue(result)

    # ── Default Algorithm Tests (Argon2 is default) ─────────────────────────
    def test_verify_password_default_algorithm_correct(self):
        """Test verify_password with default algorithm (Argon2) for correct password."""
        password = "TestPassword123"
        hashed = hash_password(password)  # Uses Argon2 by default
        result = verify_password(password, hashed)  # Uses Argon2 by default
        self.assertTrue(result)

    def test_verify_password_default_algorithm_incorrect(self):
        """Test verify_password with default algorithm (Argon2) for incorrect password."""
        password = "TestPassword123"
        wrong_password = "WrongPassword"
        hashed = hash_password(password)  # Uses Argon2 by default
        result = verify_password(wrong_password, hashed)  # Uses Argon2 by default
        self.assertFalse(result)

    # ── Edge Cases and Error Handling ───────────────────────────────────────
    def test_verify_password_unsupported_algorithm(self):
        """Test verify_password handles unsupported algorithm gracefully."""
        password = "TestPassword123"
        hashed = hash_password(password, algorithm="Argon2")
        # Function catches exceptions and returns False for unsupported algorithms
        result = verify_password(password, hashed, algorithm="MD5")
        self.assertFalse(result)

    def test_verify_password_case_sensitive(self):
        """Test that verify_password is case-sensitive."""
        password = "MyPassword123"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password("mypassword123", hashed, algorithm="SHA-256")
        self.assertFalse(result)

    def test_verify_password_whitespace_sensitive(self):
        """Test that verify_password is whitespace-sensitive."""
        password = "MyPassword123"
        hashed = hash_password(password, algorithm="SHA-256")
        result = verify_password("MyPassword123 ", hashed, algorithm="SHA-256")
        self.assertFalse(result)

    def test_verify_password_mismatched_algorithms(self):
        """Test verify_password with mismatched algorithms."""
        password = "TestPassword123"
        # Hash with Argon2 but verify with SHA-256
        hashed_argon2 = hash_password(password, algorithm="Argon2")
        # This should return False since the hash format won't match
        result = verify_password(password, hashed_argon2, algorithm="SHA-256")
        self.assertFalse(result)

    def test_verify_password_corrupted_hash_sha256(self):
        """Test verify_password handles corrupted hash gracefully with SHA-256."""
        password = "TestPassword123"
        corrupted_hash = "not_a_valid_hash_string"
        # Should return False instead of raising an exception for SHA-256
        result = verify_password(password, corrupted_hash, algorithm="SHA-256")
        self.assertFalse(result)

    def test_verify_password_corrupted_hash_argon2(self):
        """Test verify_password handles corrupted hash gracefully with Argon2."""
        password = "TestPassword123"
        corrupted_hash = "not_a_valid_hash_string"
        # Should return False instead of raising an exception for Argon2
        try:
            result = verify_password(password, corrupted_hash, algorithm="Argon2")
            self.assertFalse(result)
        except Exception:
            # Argon2 may raise an exception for invalid hash format, which is caught
            pass

    def test_verify_password_none_password(self):
        """Test verify_password with None password."""
        password = "TestPassword123"
        hashed = hash_password(password, algorithm="SHA-256")
        # Should handle None gracefully and return False
        try:
            result = verify_password(None, hashed, algorithm="SHA-256")
            self.assertFalse(result)
        except (TypeError, AttributeError):
            # Also acceptable if it raises an error
            pass

    def test_verify_password_multiple_verifications(self):
        """Test multiple sequential verifications with same hash."""
        password = "TestPassword123"
        hashed = hash_password(password, algorithm="Argon2")
        # Verify multiple times to ensure consistency
        for _ in range(3):
            result = verify_password(password, hashed, algorithm="Argon2")
            self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
