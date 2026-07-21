import os

from cracker.hash_detector import HashDetector


class RuleBasedAttack:
    """Rule-based attack mode: applies transformations to wordlist entries."""

    ALLOWED_BASE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "wordlists")
    )

    def __init__(self):
        self.hash_detector = HashDetector()
        self.LEET_SUBSTITUTIONS = {
            "a": ["@", "4"],
            "e": ["3"],
            "i": ["1", "!"],
            "o": ["0"],
            "s": ["5", "$"],
            "t": ["7"],
        }

    def attack(
        self,
        hash_string,
        hash_type,
        wordlist_path,
        increment_callback,
        salt=None,
        salt_position="append",
        **kwargs,
    ):
        try:
            if os.path.isabs(wordlist_path):
                safe_path = os.path.realpath(wordlist_path)
            else:
                safe_path = os.path.realpath(
                    os.path.join(self.ALLOWED_BASE_DIR, os.path.basename(wordlist_path))
                )
                allowed = os.path.realpath(self.ALLOWED_BASE_DIR)
                if not safe_path.startswith(allowed + os.sep):
                    return {
                        "success": False,
                        "error": "Access denied: wordlist path is outside the allowed directory",
                    }
            if not os.path.isfile(safe_path):
                return {"success": False, "error": "Wordlist file not found"}
            with open(safe_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]

            def hash_candidate(pw):
                increment_callback(1)
                if salt is not None:
                    return self.hash_detector.hash_string(
                        pw, hash_type, salt=salt, salt_position=salt_position, **kwargs
                    )
                return self.hash_detector.hash_string(pw, hash_type)

            for word in words:
                variations = self._generate_variations(word)
                for variation in variations:
                    if hash_candidate(variation) == hash_string:
                        return {"success": True, "password": variation, "attempts": 0}
            return {
                "success": False,
                "error": "Password not found with rule-based transformations",
            }
        except FileNotFoundError:
            return {"success": False, "error": "Wordlist file not found"}
        except (OSError, ValueError) as e:
            return {
                "success": False,
                "error": f"Error during rule-based attack: {str(e)}",
            }

    def _generate_variations(self, word):
        variations = set()
        MAX_VARIATIONS = 10000
        variations.add(word)
        variations.add(word.capitalize())
        variations.add(word.upper())
        variations.add(word.lower())
        leet_variations = self._apply_leet_substitutions(word)
        variations.update(leet_variations)
        for base in list(variations):
            if len(variations) > MAX_VARIATIONS:
                break
            for i in range(100):
                if len(variations) > MAX_VARIATIONS:
                    break
                variations.add(f"{i}{base}")
                variations.add(f"{base}{i}")
            if len(variations) > MAX_VARIATIONS:
                break
            for year in [2020, 2021, 2022, 2023, 2024, 2025, 2026]:
                variations.add(f"{base}{year}")
            if len(variations) > MAX_VARIATIONS:
                break
            symbols = ["@", "#", "!", "$", "%", "&", "*"]
            for sym in symbols:
                variations.add(f"{base}{sym}")
                variations.add(f"{sym}{base}")
        return list(variations)[:MAX_VARIATIONS]

    def _apply_leet_substitutions(self, word):
        variations = {word}
        for i, char in enumerate(word.lower()):
            if char in self.LEET_SUBSTITUTIONS:
                for sub in self.LEET_SUBSTITUTIONS[char]:
                    new_word = word[:i] + sub + word[i + 1 :]
                    variations.add(new_word)
                    if i < len(word) - 1:
                        sub_variations = self._apply_leet_substitutions(
                            new_word[i + 1 :]
                        )
                        for sub_var in sub_variations:
                            variations.add(word[:i] + sub + sub_var)
        return variations
