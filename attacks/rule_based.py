import os
import re

from cracker.hash_detector import HashDetector

class RuleBasedAttack:
    """Rule-based attack mode: applies transformations to wordlist entries."""

    ALLOWED_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wordlists'))

    def __init__(self):
        self.hash_detector = HashDetector()
        
        # Common leet speak substitutions
        self.LEET_SUBSTITUTIONS = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7']
        }
    
    def attack(self, hash_string, hash_type, wordlist_path, increment_callback):
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
            
            for word in words:
                # Generate variations of the word
                variations = self._generate_variations(word)
                
                for variation in variations:
                    increment_callback(1)
                    hashed = self.hash_detector.hash_string(variation, hash_type)
                    if hashed == hash_string:
                        return {'success': True, 'password': variation, 'attempts': 0}
            
            return {
                'success': False,
                'error': 'Password not found with rule-based transformations'
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Wordlist file not found'
            }
        except (OSError, ValueError) as e:
            return {
                'success': False,
                'error': f'Error during rule-based attack: {str(e)}'
            }
    
    def _generate_variations(self, word):
        """
        Generate variations of a word using various rules.
        
        Args:
            word (str): Original word
            
        Returns:
            list: List of word variations
        """
        variations = set()
        MAX_VARIATIONS = 10000  # Prevent memory explosion
        
        # Original word
        variations.add(word)
        
        # Capitalization variations
        variations.add(word.capitalize())  # First letter uppercase
        variations.add(word.upper())       # All uppercase
        variations.add(word.lower())       # All lowercase
        
        # Leet speak substitutions
        leet_variations = self._apply_leet_substitutions(word)
        variations.update(leet_variations)
        
        # Common prefixes/suffixes
        for base in list(variations):  # Work on a copy to avoid infinite loop
            if len(variations) > MAX_VARIATIONS:
                break
            # Add numbers 0-99 as prefix/suffix
            for i in range(100):
                if len(variations) > MAX_VARIATIONS:
                    break
                variations.add(f"{i}{base}")
                variations.add(f"{base}{i}")
            
            if len(variations) > MAX_VARIATIONS:
                break
            # Add common years as suffix
            for year in [2020, 2021, 2022, 2023, 2024, 2025]:
                variations.add(f"{base}{year}")
            
            if len(variations) > MAX_VARIATIONS:
                break
            # Add common symbols as suffix
            symbols = ['@', '#', '!', '$', '%', '&', '*']
            for sym in symbols:
                variations.add(f"{base}{sym}")
                variations.add(f"{sym}{base}")
        
        return list(variations)[:MAX_VARIATIONS]
    
    def _apply_leet_substitutions(self, word):
        """
        Apply leet speak substitutions to generate variations.
        
        Args:
            word (str): Original word
            
        Returns:
            set: Set of leet-substituted variations
        """
        variations = {word}
        
        # For each character that can be substituted
        for i, char in enumerate(word.lower()):
            if char in self.LEET_SUBSTITUTIONS:
                # For each substitution of this character
                for sub in self.LEET_SUBSTITUTIONS[char]:
                    # Create new word with substitution
                    new_word = word[:i] + sub + word[i+1:]
                    variations.add(new_word)
                    
                    # Also apply substitutions recursively (for multiple substitutions)
                    # But limit depth to avoid explosion
                    if i < len(word) - 1:  # Not the last character
                        sub_variations = self._apply_leet_substitutions(new_word[i+1:])
                        for sub_var in sub_variations:
                            variations.add(word[:i] + sub + sub_var)
        
        return variations