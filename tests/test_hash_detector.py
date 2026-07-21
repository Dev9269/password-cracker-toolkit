import unittest
from cracker.hash_detector import HashDetector


class TestHashDetector(unittest.TestCase):
    def test_detect_md5(self):
        result = HashDetector.detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "md5")

    def test_detect_sha1(self):
        result = HashDetector.detect_hash_type(
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "sha1")

    def test_detect_sha256(self):
        result = HashDetector.detect_hash_type(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbddfbeef1a4d69ee0d0e"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "sha256")

    def test_invalid_hash(self):
        self.assertIsNone(HashDetector.detect_hash_type("invalidhash"))

    def test_confidence_scoring(self):
        result = HashDetector.detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIn("candidates", result)
        self.assertGreater(len(result["candidates"]), 1)


if __name__ == "__main__":
    unittest.main()
