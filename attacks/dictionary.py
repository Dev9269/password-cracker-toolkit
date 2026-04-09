import os

from cracker.hash_detector import HashDetector

class DictionaryAttack:
    """Dictionary attack mode: compares hash against a wordlist."""

    ALLOWED_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wordlists'))

    def __init__(self):
        self.hash_detector = HashDetector()
    
    def attack(self, hash_string, hash_type, wordlist_path, increment_callback):
        """
        Perform dictionary attack.
        
        Args:
            hash_string (str): The target hash
            hash_type (str): Type of hash (md5, sha1, sha256)
            wordlist_path (str): Path to wordlist file
            increment_callback (function): Callback to increment attempt counter
            
        Returns:
            dict: Result of the attack
        """
        try:
            safe_path = os.path.realpath(
                os.path.join(self.ALLOWED_BASE_DIR, os.path.basename(wordlist_path))
            )
            allowed = os.path.realpath(self.ALLOWED_BASE_DIR)
            if not safe_path.startswith(allowed + os.sep) or not os.path.isfile(safe_path):
                return {
                    'success': False,
                    'error': 'Access denied: wordlist path is outside the allowed directory'
                }
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if not password:
                        continue
                    
                    # Increment attempt counter
                    increment_callback(1)
                    
                    # Hash the password
                    hashed = self.hash_detector.hash_string(password, hash_type)
                    
                    # Compare
                    if hashed == hash_string:
                        return {
                            'success': True,
                            'password': password,
                            'attempts': 0  # Will be updated by caller
                        }
            
            return {
                'success': False,
                'error': 'Password not found in wordlist'
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Wordlist file not found'
            }
        except (OSError, ValueError) as e:
            return {
                'success': False,
                'error': f'Error during dictionary attack: {str(e)}'
            }