import unittest
import hashlib
import os
from cracker.core_engine import CoreEngine
from cracker.hash_detector import HashDetector
from cracker.analyzer import PasswordAnalyzer

class TestHashDetector(unittest.TestCase):
    """Test hash detection functionality."""
    
    def test_detect_md5(self):
        """Test MD5 hash detection."""
        md5_hash = hashlib.md5(b'password', usedforsecurity=False).hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(md5_hash), 'md5')
        
    def test_detect_sha1(self):
        """Test SHA1 hash detection."""
        sha1_hash = hashlib.sha1(b'password', usedforsecurity=False).hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(sha1_hash), 'sha1')
        
    def test_detect_sha256(self):
        """Test SHA256 hash detection."""
        sha256_hash = hashlib.sha256("password".encode()).hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(sha256_hash), 'sha256')
    
    def test_invalid_hash(self):
        """Test invalid hash detection."""
        self.assertIsNone(HashDetector.detect_hash_type("invalidhash"))
    
    def test_is_valid_hash(self):
        """Test hash validation."""
        sha256_hash = hashlib.sha256(b'test').hexdigest()
        self.assertTrue(HashDetector.is_valid_hash(sha256_hash))
        self.assertFalse(HashDetector.is_valid_hash("not_a_hash"))
    
    def test_is_valid_hash_for_type(self):
        """Test hash validation for specific type."""
        sha256_hash = hashlib.sha256(b'test').hexdigest()
        self.assertTrue(HashDetector.is_valid_hash_for_type(sha256_hash, 'sha256'))
        self.assertFalse(HashDetector.is_valid_hash_for_type(sha256_hash, 'sha1'))


class TestPasswordAnalyzer(unittest.TestCase):
    """Test password strength analysis."""
    
    def setUp(self):
        self.analyzer = PasswordAnalyzer()
    
    def test_analyze_weak_password(self):
        """Test analysis of weak password."""
        result = self.analyzer.analyze_password("abc")
        self.assertLess(result['score'], 30)
    
    def test_analyze_strong_password(self):
        """Test analysis of strong password."""
        result = self.analyzer.analyze_password("MyP@ssw0rd123!")
        self.assertGreater(result['score'], 60)
    
    def test_common_pattern_detection(self):
        """Test detection of common patterns."""
        result = self.analyzer.analyze_password("password123")
        self.assertFalse(all(feedback.startswith('[+]') for feedback in result['feedback']))
    
    def test_character_analysis(self):
        """Test character type analysis."""
        result = self.analyzer.analyze_password("Test123!")
        chars = result['character_analysis']
        self.assertTrue(chars['lowercase'])
        self.assertTrue(chars['uppercase'])
        self.assertTrue(chars['digits'])
        self.assertTrue(chars['special'])


class TestDictionaryAttack(unittest.TestCase):
    """Test dictionary attack mode."""
    
    def setUp(self):
        self.engine = CoreEngine()
        self.md5_password = hashlib.sha256("password".encode()).hexdigest()
        self.wordlist_path = "wordlists/sample.txt"
    
    def test_dictionary_attack_success(self):
        """Test successful dictionary attack."""
        if os.path.exists(self.wordlist_path):
            result = self.engine.crack_hash(
                hash_string=self.md5_password,
                wordlist_path=self.wordlist_path,
                mode='dictionary'
            )
            self.assertTrue(result['success'])
            self.assertEqual(result['password'], 'password')
            self.assertGreater(result['attempts'], 0)


class TestBruteForceAttack(unittest.TestCase):
    """Test brute force attack mode."""
    
    def setUp(self):
        self.engine = CoreEngine()
        self.md5_test = hashlib.sha256(b'test').hexdigest()
    
    def test_brute_force_attack_success(self):
        """Test successful brute force attack."""
        result = self.engine.crack_hash(
            hash_string=self.md5_test,
            mode='brute',
            min_length=4,
            max_length=4,
            charset='lowercase',
            algo='sha256'
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['password'], 'test')
        self.assertGreater(result['attempts'], 0)


class TestCoreEngine(unittest.TestCase):
    """Test core engine functionality."""
    
    def setUp(self):
        self.engine = CoreEngine()
    
    def test_invalid_hash(self):
        """Test handling of invalid hash."""
        result = self.engine.crack_hash(
            hash_string="invalidenthash",
            mode='dictionary'
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_invalid_min_max_length(self):
        """Test validation of min/max length."""
        result = self.engine.crack_hash(
            hash_string=hashlib.sha256(b'test').hexdigest(),
            mode='brute',
            min_length=10,
            max_length=5
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_algo_override_valid(self):
        """Test algorithm override with valid hash."""
        md5_hash = hashlib.sha256(b'test').hexdigest()
        result = self.engine.crack_hash(
            hash_string=md5_hash,
            mode='brute',
            min_length=4,
            max_length=4,
            charset='lowercase',
            algo='sha256'
        )
        self.assertEqual(result['hash_type'], 'sha256')
    
    def test_algo_override_invalid(self):
        """Test algorithm override with invalid algorithm."""
        md5_hash = hashlib.sha256(b'test').hexdigest()
        result = self.engine.crack_hash(
            hash_string=md5_hash,
            algo='invalid_algo'
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)


class TestHashcatWrapper(unittest.TestCase):
    """Test GPU hashcat wrapper."""
    
    def test_is_available_without_hashcat(self):
        """Test when hashcat is not installed."""
        from gpu.hashcat_wrapper import HashcatWrapper
        wrapper = HashcatWrapper()
        self.assertFalse(wrapper.is_available())
    
    def test_hashcat_modes_supported(self):
        """Test hashcat mode mapping."""
        from gpu.hashcat_wrapper import HashcatWrapper
        wrapper = HashcatWrapper()
        # Test crack_hash mode mapping (fails gracefully without hashcat)
        result_md5 = wrapper.crack_hash('test', 'md5', mode='dictionary')
        self.assertIn('success', result_md5)
        self.assertFalse(result_md5['success'])  # No hashcat, expected fail
        
        result_sha1 = wrapper.crack_hash('test', 'sha1')
        self.assertFalse(result_sha1['success'])

if __name__ == '__main__':
    unittest.main()
