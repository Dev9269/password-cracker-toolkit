import subprocess
import json
import os
import tempfile

from cracker.hash_detector import HashDetector

class HashcatWrapper:
    """Wrapper for hashcat integration for GPU-accelerated cracking."""
    
    def __init__(self):
        self.hash_detector = HashDetector()
        self.hashcat_path = self._find_hashcat()
    
    def _find_hashcat(self):
        """
        Find hashcat executable in PATH or common locations.
        
        Returns:
            str: Path to hashcat executable or None if not found
        """
        # Common hashcat executable names
        hashcat_names = ['hashcat', 'hashcat64.exe', 'hashcat32.exe']
        
        # Check in PATH (cross-platform)
        for name in hashcat_names:
            cmd = ['where', name] if os.name == 'nt' else ['which', name]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, shell=False)
                if result.returncode == 0:
                    return result.stdout.strip().split('\n')[0]  # First match
            except (FileNotFoundError, OSError):
                pass
        
        # If not found in PATH, return None (will be handled in crack_hash)
        return None
    
    def is_available(self):
        """
        Check if hashcat is available.
        
        Returns:
            bool: True if hashcat is found, False otherwise
        """
        return self.hashcat_path is not None
    
    def _build_cmd(self, hashcat_mode, hash_file_path, output_file_path,
                    mode, wordlist_path, min_length, max_length, charset):
        """
        Build the hashcat command list.

        Returns:
            list | dict: Argument list, or error dict if wordlist missing.
        """
        cmd = [self.hashcat_path, '-m', str(hashcat_mode), hash_file_path]

        if mode == 'brute' or (mode == 'auto' and not wordlist_path):
            hc_charset = self._convert_charset_to_hashcat(charset) if charset else '?l?u?d?s'
            cmd[1:1] = ['-a', '3']
            cmd.extend(['-1', hc_charset,
                        '--increment',
                        '--increment-min', str(min_length),
                        '--increment-max', str(max_length),
                        '?' * max_length])
        else:
            if not wordlist_path:
                return {'success': False,
                        'error': 'Wordlist path required for dictionary/hybrid/rule attacks'}
            cmd.extend(['-a', '0', wordlist_path])

        cmd.extend(['--outfile', output_file_path, '--outfile-format', '2'])
        return cmd

    def _parse_output_file(self, output_file_path, hash_string, stdout, stderr):
        """
        Read hashcat output file and return a result dict.

        Returns:
            dict: success/failure result.
        """
        if not os.path.exists(output_file_path):
            return {'success': False, 'error': 'Hashcat did not recover the password'}

        with open(output_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    recovered_hash, password = line.split(':', 1)
                    if recovered_hash == hash_string:
                        attempts = self._parse_attempts_from_output(stdout + '\n' + stderr)
                        return {'success': True, 'password': password, 'attempts': attempts}

        return {'success': False, 'error': 'Hashcat did not recover the password'}

    def _cleanup(self, *paths):
        """Remove temporary files, ignoring errors."""
        for path in paths:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except (FileNotFoundError, OSError):
                pass

    def crack_hash(self, hash_string, hash_type, wordlist_path=None, mode='auto',
                   min_length=1, max_length=8, charset=None):
        """
        Attempt to crack hash using hashcat.

        Args:
            hash_string (str): The hash to crack
            hash_type (str): Type of hash (md5, sha1, sha256)
            wordlist_path (str): Path to wordlist file
            mode (str): Attack mode ('auto', 'dictionary', 'brute', 'hybrid', 'rule')
            min_length (int): Minimum password length for brute force
            max_length (int): Maximum password length for brute force
            charset (str): Character set for brute force

        Returns:
            dict: Result containing success status, password, and stats
        """
        if not self.is_available():
            return {'success': False,
                    'error': 'Hashcat not found. Please install hashcat and ensure it is in your PATH.'}

        hashcat_modes = {'md5': 0, 'sha1': 100, 'sha256': 1400}
        if hash_type not in hashcat_modes:
            return {'success': False, 'error': f'Unsupported hash type for hashcat: {hash_type}'}

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as hash_file:
            hash_file.write(hash_string)
            hash_file_path = hash_file.name
        output_file_path = hash_file_path + '.out'

        try:
            cmd = self._build_cmd(
                hashcat_modes[hash_type], hash_file_path, output_file_path,
                mode, wordlist_path, min_length, max_length, charset
            )
            if isinstance(cmd, dict):
                return cmd

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            return self._parse_output_file(
                output_file_path, hash_string, result.stdout, result.stderr
            )
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Hashcat timed out after 1 hour'}
        except (OSError, ValueError) as e:
            return {'success': False, 'error': f'Error running hashcat: {str(e)}'}
        finally:
            self._cleanup(hash_file_path, output_file_path)
    
    def _convert_charset_to_hashcat(self, charset):
        """
        Convert our charset representation to hashcat charset format.
        
        Args:
            charset (str): Character set string
            
        Returns:
            str: Hashcat-compatible charset string
        """
        # Define hashcat charset placeholders
        # ?l = lowercase letters
        # ?u = uppercase letters
        # ?d = digits
        # ?s = special characters
        
        has_lower = any(c.islower() for c in charset)
        has_upper = any(c.isupper() for c in charset)
        has_digit = any(c.isdigit() for c in charset)
        has_special = any(not c.isalnum() for c in charset)
        
        hc_charset = ''
        if has_lower:
            hc_charset += '?l'
        if has_upper:
            hc_charset += '?u'
        if has_digit:
            hc_charset += '?d'
        if has_special:
            hc_charset += '?s'
        
        # If no specific characteristics, use all
        if not hc_charset:
            hc_charset = '?l?u?d?s'
        
        return hc_charset

    def _parse_attempts_from_output(self, text):
        """
        Parse the number of attempts from hashcat output text.

        Args:
            text (str): Combined stdout/stderr text from hashcat

        Returns:
            int: Attempt count (0 if not found)
        """
        import re
        attempts = 0

        for line in text.splitlines():
            # Hashcat session restore: "Restored session... XX/YY (X%)"
            if 'Restored' in line and '(' in line:
                m = re.search(r'(\d+)/', line)
                if m:
                    attempts = max(attempts, int(m.group(1)))

            # Recovered/Progress patterns
            m = re.search(r'(?i)(?:Recovered|Progress|Candidates|Excavated|Guesses|Attempts)[:\s]*(\d+)', line)
            if m:
                try:
                    value = int(m.group(1))
                    attempts = max(attempts, value)
                except ValueError:
                    pass

            # Speed lines like "123.4 kH/s" → estimate attempts = speed * time (rough)
            # Skip for accuracy

        return attempts
