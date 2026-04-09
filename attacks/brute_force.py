import itertools
import hashlib

from cracker.hash_detector import HashDetector

class BruteForceAttack:
    """Brute force attack mode: generates all possible combinations."""
    
    def __init__(self):
        self.hash_detector = HashDetector()
        
        # Predefined character sets
        self.CHARSETS = {
            'lowercase': 'abcdefghijklmnopqrstuvwxyz',
            'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'digits': '0123456789',
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'lowerupper': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'alnum': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'all': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
    
    def attack(self, hash_string, hash_type, min_length, max_length, charset, increment_callback):
        """
        Perform brute force attack.
        
        Args:
            hash_string (str): The target hash
            hash_type (str): Type of hash (md5, sha1, sha256)
            min_length (int): Minimum password length
            max_length (int): Maximum password length
            charset (str): Character set key (lowercase, uppercase, etc.) or custom string
            increment_callback (function): Callback to increment attempt counter
            
        Returns:
            dict: Result of the attack
        """
        # Determine the character set to use
        if charset in self.CHARSETS:
            chars = self.CHARSETS[charset]
        else:
            # Assume it's a custom character set
            chars = charset
            
        if not chars:
            return {
                'success': False,
                'error': 'Character set is empty'
            }
        
        try:
            # Iterate over lengths from min_length to max_length
            for length in range(min_length, max_length + 1):
                # Generate all combinations of the current length
                for combination in itertools.product(chars, repeat=length):
                    password = ''.join(combination)
                    
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
                'error': 'Exhausted all combinations without finding password'
            }
        
        except (ValueError, MemoryError, OverflowError) as e:
            return {
                'success': False,
                'error': f'Brute force configuration error: {str(e)}'
            }
