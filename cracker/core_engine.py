import time

from cracker.hash_detector import HashDetector
from attacks.dictionary import DictionaryAttack
from attacks.brute_force import BruteForceAttack
from attacks.hybrid import HybridAttack
from attacks.rule_based import RuleBasedAttack
from gpu.hashcat_wrapper import HashcatWrapper
from cracker.analyzer import PasswordAnalyzer
from cracker.logger import PasswordLogger

class CoreEngine:
    """Main engine that coordinates the password cracking process."""
    
    def __init__(self):
        self.hash_detector = HashDetector()
        self.dictionary_attack = DictionaryAttack()
        self.brute_force_attack = BruteForceAttack()
        self.hybrid_attack = HybridAttack()
        self.rule_based_attack = RuleBasedAttack()
        self.hashcat_wrapper = HashcatWrapper()
        self.analyzer = PasswordAnalyzer()
        self.logger = PasswordLogger()
        
        # Stats tracking
        self.start_time = None
        self.attempts = 0
        self.found = False
        self.cracked_password = None
        
    def crack_hash(self, hash_string, wordlist_path=None, mode='auto', 
                   min_length=1, max_length=8, charset=None, use_gpu=False, algo=None):
        """
        Attempt to crack a hash using the specified attack mode.
        
        Args:
            hash_string (str): The hash to crack
            wordlist_path (str): Path to wordlist file (for dictionary/hybrid/rule)
            mode (str): Attack mode ('auto', 'dictionary', 'brute', 'hybrid', 'rule')
            min_length (int): Minimum password length for brute force
            max_length (int): Maximum password length for brute force
            charset (str): Character set for brute force (e.g., 'lowercase', 'all')
            use_gpu (bool): Whether to use GPU acceleration via hashcat
            
        Returns:
            dict: Result containing success status, password, and stats
        """
        # Validate hash type based on provided algorithm or detect automatically
        if algo:
            algo_lower = algo.lower()
            if algo_lower not in self.hash_detector.HASH_PATTERNS:
                return {
                    'success': False,
                    'error': 'Invalid algorithm override. Supported: md5, sha1, sha256'
                }
            hash_type = algo_lower
            if not self.hash_detector.is_valid_hash_for_type(hash_string, hash_type):
                return {
                    'success': False,
                    'error': 'Invalid hash format for the provided algorithm'
                }
        else:
            hash_type = self.hash_detector.detect_hash_type(hash_string)
            if not hash_type:
                return {
                    'success': False,
                    'error': 'Invalid or unsupported hash format'
                }
        
        # Validate brute-force range parameters
        if min_length < 1 or max_length < min_length:
            return {
                'success': False,
                'error': 'Invalid min/max length parameters'
            }

        # Reset stats
        self.start_time = time.time()
        self.attempts = 0
        self.found = False
        self.cracked_password = None
        
        # Log the start of cracking attempt
        self.logger.log_attempt_start(hash_string, hash_type, mode, use_gpu)
        
        # If GPU mode is requested and available, use hashcat
        if use_gpu:
            result = self.hashcat_wrapper.crack_hash(
                hash_string, hash_type, wordlist_path=wordlist_path, mode=mode, 
                min_length=min_length, max_length=max_length, charset=charset
            )
            result['used_gpu'] = use_gpu
            self.attempts = result.get('attempts', 0)

            if result['success']:
                self.found = True
                self.cracked_password = result['password']

            elapsed_time = time.time() - self.start_time
            attempts_per_second = self.attempts / elapsed_time if elapsed_time > 0 else 0
            self.logger.log_result(self.found, self.cracked_password, elapsed_time, self.attempts)

            # Analyze the password if found
            analysis = None
            if self.found:
                analysis = self.analyzer.analyze_password(self.cracked_password)

            result.update({
                'hash_type': hash_type,
                'time_elapsed': elapsed_time,
                'attempts_per_second': attempts_per_second,
                'analysis': analysis
            })
            return result
        
        # CPU-based attacks
        if mode == 'auto':
            # Try dictionary first, then hybrid, then brute force
            for attack_mode in ['dictionary', 'hybrid', 'brute']:
                result = self._run_attack(
                    attack_mode, hash_string, hash_type, wordlist_path,
                    min_length, max_length, charset
                )
                if result['success']:
                    self.found = True
                    self.cracked_password = result['password']
                    # Attempts have been updated via the callback, so we don't overwrite them
                    break
        else:
            result = self._run_attack(
                mode, hash_string, hash_type, wordlist_path,
                min_length, max_length, charset
            )
            if result['success']:
                self.found = True
                self.cracked_password = result['password']
                # Attempts have been updated via the callback, so we don't overwrite them
        
        # Calculate final stats
        elapsed_time = time.time() - self.start_time
        attempts_per_second = self.attempts / elapsed_time if elapsed_time > 0 else 0
        
        # Log the result
        self.logger.log_result(self.found, self.cracked_password, 
                             elapsed_time, self.attempts)
        
        # Analyze the password if found
        analysis = None
        if self.found:
            analysis = self.analyzer.analyze_password(self.cracked_password)
        
        return {
            'success': self.found,
            'password': self.cracked_password,
            'hash_type': hash_type,
            'attempts': self.attempts,
            'time_elapsed': elapsed_time,
            'attempts_per_second': attempts_per_second,
            'analysis': analysis
        }
    
    def _run_attack(self, mode, hash_string, hash_type, wordlist_path, 
                   min_length, max_length, charset):
        """
        Run a specific attack mode.
        
        Args:
            mode (str): Attack mode to run
            hash_string (str): The hash to crack
            hash_type (str): Detected hash type
            wordlist_path (str): Path to wordlist
            min_length (int): Minimum password length
            max_length (int): Maximum password length
            charset (str): Character set for brute force
            
        Returns:
            dict: Result of the attack attempt
        """
        if mode == 'dictionary':
            return self.dictionary_attack.attack(
                hash_string, hash_type, wordlist_path, 
                self._increment_attempts
            )
        elif mode == 'brute':
            return self.brute_force_attack.attack(
                hash_string, hash_type, min_length, max_length, charset,
                self._increment_attempts
            )
        elif mode == 'hybrid':
            return self.hybrid_attack.attack(
                hash_string, hash_type, wordlist_path,
                self._increment_attempts
            )
        elif mode == 'rule':
            return self.rule_based_attack.attack(
                hash_string, hash_type, wordlist_path,
                self._increment_attempts
            )
        else:
            return {
                'success': False,
                'error': f'Unknown attack mode: {mode}'
            }
    
    def _increment_attempts(self, count=1):
        """Increment the attempts counter."""
        self.attempts += count