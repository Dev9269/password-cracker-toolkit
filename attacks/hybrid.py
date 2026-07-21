import os
from datetime import datetime

from cracker.hash_detector import HashDetector


class HybridAttack:
    """Hybrid attack mode: combines wordlist with patterns."""

    ALLOWED_BASE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "wordlists")
    )

    def __init__(self):
        self.hash_detector = HashDetector()

    def attack(
        self,
        hash_string,
        hash_type,
        wordlist_path,
        increment_callback,
        max_number=1000,
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
                for i in range(0, max_number):
                    if hash_candidate(f"{word}{i}") == hash_string:
                        return {
                            "success": True,
                            "password": f"{word}{i}",
                            "attempts": 0,
                        }
                for year in range(1900, datetime.now().year + 1):
                    if hash_candidate(f"{word}{year}") == hash_string:
                        return {
                            "success": True,
                            "password": f"{word}{year}",
                            "attempts": 0,
                        }
                symbols = ["@", "#", "!", "$", "%"]
                for sym in symbols:
                    for i in range(0, 100):
                        if hash_candidate(f"{word}{sym}{i}") == hash_string:
                            return {
                                "success": True,
                                "password": f"{word}{sym}{i}",
                                "attempts": 0,
                            }
            return {
                "success": False,
                "error": "Password not found with hybrid patterns",
            }
        except FileNotFoundError:
            return {"success": False, "error": "Wordlist file not found"}
        except (OSError, ValueError) as e:
            return {"success": False, "error": f"Error during hybrid attack: {str(e)}"}
