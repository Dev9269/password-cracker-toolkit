import os
from cracker.hash_detector import HashDetector


class CombinatorAttack:
    def __init__(self):
        self.hash_detector = HashDetector()

    def attack(
        self,
        hash_string,
        hash_type,
        wordlist1,
        wordlist2,
        increment_callback,
        salt=None,
        salt_position="append",
        **kwargs,
    ):
        try:
            if not os.path.exists(wordlist1):
                return {"success": False, "error": f"Wordlist 1 not found: {wordlist1}"}
            if not os.path.exists(wordlist2):
                return {"success": False, "error": f"Wordlist 2 not found: {wordlist2}"}

            with open(wordlist1, "r", encoding="utf-8", errors="ignore") as f1:
                words1 = [line.strip() for line in f1 if line.strip()]

            with open(wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
                words2 = [line.strip() for line in f2 if line.strip()]

            for w1 in words1:
                for w2 in words2:
                    password = w1 + w2
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
                "error": "Password not found via combinator attack",
            }
        except (OSError, ValueError) as e:
            return {"success": False, "error": f"Combinator error: {str(e)}"}

    def candidates_generator(self, wordlist1, wordlist2):
        with open(wordlist1, "r", encoding="utf-8", errors="ignore") as f1:
            words1 = [line.strip() for line in f1 if line.strip()]
        with open(wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
            for line2 in f2:
                w2 = line2.strip()
                if not w2:
                    continue
                for w1 in words1:
                    yield w1 + w2
