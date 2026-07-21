import itertools

from cracker.hash_detector import HashDetector


class BruteForceAttack:
    """Brute force attack mode: generates all possible combinations."""

    def __init__(self):
        self.hash_detector = HashDetector()
        self.CHARSETS = {
            "lowercase": "abcdefghijklmnopqrstuvwxyz",
            "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "digits": "0123456789",
            "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "lowerupper": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "all": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
        }

    def attack(
        self,
        hash_string,
        hash_type,
        min_length,
        max_length,
        charset,
        increment_callback,
        salt=None,
        salt_position="append",
        **kwargs,
    ):
        if charset in self.CHARSETS:
            chars = self.CHARSETS[charset]
        else:
            chars = charset
        if not chars:
            return {"success": False, "error": "Character set is empty"}
        try:
            for length in range(min_length, max_length + 1):
                for combination in itertools.product(chars, repeat=length):
                    password = "".join(combination)
                    increment_callback(1)
                    if salt is not None:
                        hashed = self.hash_detector.hash_string(
                            password,
                            hash_type,
                            salt=salt,
                            salt_position=salt_position,
                            **kwargs,
                        )
                    else:
                        hashed = self.hash_detector.hash_string(password, hash_type)
                    if hashed == hash_string:
                        return {"success": True, "password": password, "attempts": 0}
            return {
                "success": False,
                "error": "Exhausted all combinations without finding password",
            }
        except (ValueError, MemoryError, OverflowError) as e:
            return {
                "success": False,
                "error": f"Brute force configuration error: {str(e)}",
            }
