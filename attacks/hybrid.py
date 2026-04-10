import os
from datetime import datetime

from cracker.hash_detector import HashDetector

class HybridAttack:
    """Hybrid attack mode: combines wordlist with patterns (e.g., word + numbers)."""

    ALLOWED_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wordlists'))

    def __init__(self):
        self.hash_detector = HashDetector()
    
    def attack(self, hash_string, hash_type, wordlist_path, increment_callback, max_number=1000):
        try:
            # Support both absolute paths and relative paths inside wordlists/
            if os.path.isabs(wordlist_path):
                safe_path = os.path.realpath(wordlist_path)
            else:
                safe_path = os.path.realpath(
                    os.path.join(self.ALLOWED_BASE_DIR, os.path.basename(wordlist_path))
                )
                allowed = os.path.realpath(self.ALLOWED_BASE_DIR)
                if not safe_path.startswith(allowed + os.sep):
                    return {'success': False, 'error': 'Access denied: wordlist path is outside the allowed directory'}
            if not os.path.isfile(safe_path):
                return {'success': False, 'error': 'Wordlist file not found'}
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            
            # Common patterns: append numbers (0-999), append year (1900-2025), etc.
            for word in words:
                # Pattern 1: word + numbers (0-999)
                for i in range(0, max_number):
                    password = f"{word}{i}"
                    increment_callback(1)
                    hashed = self.hash_detector.hash_string(password, hash_type)
                    if hashed == hash_string:
                        return {'success': True, 'password': password, 'attempts': 0}
                
                # Pattern 2: word + year (1900-current year)
                for year in range(1900, datetime.now().year + 1):
                    password = f"{word}{year}"
                    increment_callback(1)
                    hashed = self.hash_detector.hash_string(password, hash_type)
                    if hashed == hash_string:
                        return {'success': True, 'password': password, 'attempts': 0}
                
                # Pattern 3: word + common symbols (@, #, !, etc.) + numbers
                symbols = ['@', '#', '!', '$', '%']
                for sym in symbols:
                    for i in range(0, 100):
                        password = f"{word}{sym}{i}"
                        increment_callback(1)
                        hashed = self.hash_detector.hash_string(password, hash_type)
                        if hashed == hash_string:
                            return {'success': True, 'password': password, 'attempts': 0}
            
            return {
                'success': False,
                'error': 'Password not found with hybrid patterns'
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Wordlist file not found'
            }
        except (OSError, ValueError) as e:
            return {
                'success': False,
                'error': f'Error during hybrid attack: {str(e)}'
            }