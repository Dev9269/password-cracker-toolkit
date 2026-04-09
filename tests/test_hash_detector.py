import unittest
from cracker.hash_detector import HashDetector

class TestHashDetector(unittest.TestCase):
    def test_detect_md5(self):
        self.assertEqual(HashDetector.detect_hash_type('5f4dcc3b5aa765d61d8327deb882cf99'), 'md5')

    def test_detect_sha1(self):
        self.assertEqual(HashDetector.detect_hash_type('a9993e364706816aba3e25717850c26c9cd0d89d'), 'sha1')

    def test_detect_sha256(self):
        self.assertEqual(HashDetector.detect_hash_type('5e884898da28047151d0e56f8dc6292773603d0d6aabbddfbeef1a4d69ee0d0e'), 'sha256')

    def test_invalid_hash(self):
        self.assertIsNone(HashDetector.detect_hash_type('invalidhash'))

if __name__ == '__main__':
    unittest.main()
