import re
import hashlib

class HashDetector:
    """Detects hash types based on length and pattern."""
    
    # Hash type patterns
    HASH_PATTERNS = {
        'md5': {
            'length': 32,
            'pattern': r'^[a-fA-F0-9]{32}$',
            'name': 'MD5'
        },
        'sha1': {
            'length': 40,
            'pattern': r'^[a-fA-F0-9]{40}$',
            'name': 'SHA1'
        },
        'sha256': {
            'length': 64,
            'pattern': r'^[a-fA-F0-9]{64}$',
            'name': 'SHA256'
        }
    }
    
    @classmethod
    def detect_hash_type(cls, hash_string):
        """
        Detect the type of hash based on length and pattern.
        
        Args:
            hash_string (str): The hash string to analyze
            
        Returns:
            str: Detected hash type ('md5', 'sha1', 'sha256') or None if unknown
        """
        if not hash_string:
            return None
            
        hash_string = hash_string.strip()
        
        # Check each hash type
        for hash_type, specs in cls.HASH_PATTERNS.items():
            if len(hash_string) == specs['length']:
                if re.match(specs['pattern'], hash_string):
                    return hash_type
                    
        return None
    
    @classmethod
    def get_hash_name(cls, hash_type):
        """
        Get the display name for a hash type.
        
        Args:
            hash_type (str): The hash type ('md5', 'sha1', 'sha256')
            
        Returns:
            str: Display name of the hash type
        """
        if hash_type in cls.HASH_PATTERNS:
            return cls.HASH_PATTERNS[hash_type]['name']
        return "Unknown"
    
    @classmethod
    def is_valid_hash(cls, hash_string):
        """
        Check if a string is a valid hash of any supported type.
        
        Args:
            hash_string (str): The string to validate
            
        Returns:
            bool: True if valid hash, False otherwise
        """
        return cls.detect_hash_type(hash_string) is not None

    @classmethod
    def is_valid_hash_for_type(cls, hash_string, hash_type):
        """
        Validate a hash string for a specific hash type.

        Args:
            hash_string (str): Hash string to validate
            hash_type (str): Hash type ('md5', 'sha1', 'sha256')

        Returns:
            bool: True if valid for the hash type, False otherwise
        """
        if hash_type not in cls.HASH_PATTERNS:
            return False

        specs = cls.HASH_PATTERNS[hash_type]
        return bool(re.match(specs['pattern'], hash_string.strip()))    
    @classmethod
    def hash_string(cls, text, algorithm):
        """
        Generate a hash of the given text using specified algorithm.
        
        Args:
            text (str): Text to hash
            algorithm (str): Hash algorithm ('md5', 'sha1', 'sha256')
            
        Returns:
            str: Hexadecimal hash string
        """
        if algorithm == 'md5':
            return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(text.encode(), usedforsecurity=False).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")