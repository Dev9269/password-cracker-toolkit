import json
import logging
import os
from datetime import datetime

class PasswordLogger:
    """Handles logging of password cracking attempts and results."""
    
    def __init__(self, log_dir='logs'):
        """
        Initialize the logger.
        
        Args:
            log_dir (str): Directory to store log files
        """
        # Resolve relative to cwd so it works on Windows, Linux, ChromeOS, Kali
        self.log_dir = os.path.abspath(log_dir)
        self.BASE_DIR = self.log_dir
        self.ensure_log_directory()
        
        # Setup logging
        self.setup_logging()
    
    def ensure_log_directory(self):
        """Create log directory if it doesn't exist."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_filename = f'password_cracker_{datetime.now().strftime("%Y%m%d")}.log'
        log_file = os.path.realpath(os.path.join(self.log_dir, log_filename))
        if not log_file.startswith(os.path.realpath(self.log_dir) + os.sep):
            raise ValueError("Log file path resolves outside the allowed log directory")
        
        self.logger = logging.getLogger('password_cracker')
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            self.logger.addHandler(stream_handler)
    
    def log_attempt_start(self, hash_string, hash_type, mode, use_gpu):
        """
        Log the start of a cracking attempt.
        
        Args:
            hash_string (str): The hash being cracked
            hash_type (str): Type of hash
            mode (str): Attack mode being used
            use_gpu (bool): Whether GPU acceleration is being used
        """
        self.logger.info(f"Starting password crack attempt")
        self.logger.info(f"Hash: {hash_string}")
        self.logger.info(f"Hash type: {hash_type}")
        self.logger.info(f"Attack mode: {mode}")
        self.logger.info(f"GPU acceleration: {'Enabled' if use_gpu else 'Disabled'}")
    
    def log_result(self, success, password, elapsed_time, attempts):
        """
        Log the result of a cracking attempt.
        
        Args:
            success (bool): Whether the password was found
            password (str): The cracked password (if successful)
            elapsed_time (float): Time taken in seconds
            attempts (int): Number of attempts made
        """
        if success:
            self.logger.info(f"SUCCESS: Password found: {password}")
        else:
            self.logger.info("FAILED: Password not found")
        
        self.logger.info(f"Time elapsed: {elapsed_time:.2f} seconds")
        self.logger.info(f"Attempts made: {attempts}")
        if elapsed_time > 0:
            self.logger.info(f"Attempts per second: {attempts/elapsed_time:.2f}")
        self.logger.info("-" * 50)
    
    def log_to_json(self, hash_string, hash_type, mode, success, password, 
                   elapsed_time, attempts, analysis=None, filename=None):
        """
        Log results to a JSON file for later analysis.
        
        Args:
            hash_string (str): The hash that was cracked
            hash_type (str): Type of hash
            mode (str): Attack mode used
            success (bool): Whether cracking was successful
            password (str): The cracked password (if successful)
            elapsed_time (float): Time taken in seconds
            attempts (int): Number of attempts made
            analysis (dict): Password analysis results (if successful)
            filename (str): Optional custom filename for JSON log
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crack_result_{timestamp}.json"

        # Prevent path traversal: strip directory components and confine to log_dir
        filename = os.path.basename(filename)
        safe_path = os.path.realpath(os.path.join(self.log_dir, filename))
        if not safe_path.startswith(os.path.realpath(self.log_dir) + os.sep):
            self.logger.error("Access denied: log filename resolves outside the log directory")
            return
        
        result_data = {
            'timestamp': datetime.now().isoformat(),
            'hash': hash_string,
            'hash_type': hash_type,
            'attack_mode': mode,
            'success': success,
            'password': password if success else None,
            'time_elapsed_seconds': elapsed_time,
            'attempts': attempts,
            'attempts_per_second': attempts/elapsed_time if elapsed_time > 0 else 0,
            'password_analysis': analysis if success else None
        }
        
        safe_path = os.path.realpath(os.path.join(self.log_dir, filename))
        try:
            with open(safe_path, 'w') as f:
                json.dump(result_data, f, indent=2)
            self.logger.info("Results logged to JSON: %s", os.path.basename(safe_path))
        except (OSError, ValueError) as e:
            self.logger.error(f"Failed to write JSON log: {str(e)}")