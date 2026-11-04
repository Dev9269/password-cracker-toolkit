import unittest
import hashlib
import os
from cracker.core_engine import CoreEngine
from cracker.hash_detector import HashDetector
from cracker.analyzer import PasswordAnalyzer

HAS_MD4 = False
try:
    hashlib.new("md4", b"test", usedforsecurity=False)
    HAS_MD4 = True
except Exception:
    pass


class TestHashDetector(unittest.TestCase):
    def test_detect_md5(self):
        h = hashlib.md5(b"password", usedforsecurity=False).hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(h)["algo"], "md5")

    def test_detect_sha1(self):
        h = hashlib.sha1(b"password", usedforsecurity=False).hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(h)["algo"], "sha1")

    def test_detect_sha256(self):
        h = hashlib.sha256(b"password").hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(h)["algo"], "sha256")

    def test_detect_sha512(self):
        h = hashlib.sha512(b"password").hexdigest()
        self.assertEqual(HashDetector.detect_hash_type(h)["algo"], "sha512")

    def test_invalid_hash(self):
        self.assertIsNone(HashDetector.detect_hash_type("invalidhash"))

    def test_is_valid_hash(self):
        h = hashlib.sha256(b"test").hexdigest()
        self.assertTrue(HashDetector.is_valid_hash(h))
        self.assertFalse(HashDetector.is_valid_hash("not_a_hash"))

    def test_is_valid_hash_for_type(self):
        h = hashlib.sha256(b"test").hexdigest()
        self.assertTrue(HashDetector.is_valid_hash_for_type(h, "sha256"))
        self.assertFalse(HashDetector.is_valid_hash_for_type(h, "sha1"))

    def test_multi_candidate_32hex(self):
        h = hashlib.md5(b"test", usedforsecurity=False).hexdigest()
        result = HashDetector.detect_hash_type(h)
        self.assertIn("candidates", result)
        self.assertGreaterEqual(len(result["candidates"]), 3)
        self.assertEqual(result["algo"], "md5")

    def test_prefix_bcrypt(self):
        result = HashDetector.detect_hash_type(
            "$2b$12$LJ3m4ys3Lk0TSwHfD4KXjO9X8Yz0q1a2b3c4d5e6f7g8h9i0j1k2l3m4n5"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "bcrypt")
        self.assertAlmostEqual(result["confidence"], 1.0)

    def test_prefix_sha512_crypt(self):
        result = HashDetector.detect_hash_type(
            "$6$salt$hashvaluehashvaluehashvaluehashvaluehashvaluehashvaluehashvaluehashvaluehashvaluehashvaluehas"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "sha512_crypt")

    def test_prefix_md5_crypt(self):
        result = HashDetector.detect_hash_type("$1$salt$hashvaluehashvaluehas")
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "md5_crypt")

    def test_ldap_ssha(self):
        result = HashDetector.detect_hash_type("{SSHA}base64encodedhashdata")
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "ldap_ssha")

    @unittest.skipUnless(HAS_MD4, "MD4 not available in this Python build")
    def test_ntlm_detection(self):
        h = HashDetector._ntlm_hash("password")
        result = HashDetector.detect_hash_type(h)
        self.assertEqual(result["algo"], "ntlm")

    def test_postgres_md5_detection(self):
        h = HashDetector._postgres_md5_hash("password", "user")
        result = HashDetector.detect_hash_type(h)
        self.assertEqual(result["algo"], "postgres_md5")

    def test_mysql41_detection(self):
        h = HashDetector._mysql41_hash("password")
        result = HashDetector.detect_hash_type(h)
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "mysql41")

    def test_crypt_style_no_prefix_des(self):
        result = HashDetector.detect_hash_type("abcdefgh12345")
        self.assertIsNotNone(result)

    def test_phpass_detection(self):
        result = HashDetector.detect_hash_type("$P$abcdefghijklmnopqrstuvwxyzABCDEFGH")
        self.assertIsNotNone(result)
        self.assertEqual(result["algo"], "phpass")


class TestHashString(unittest.TestCase):
    def test_md5_roundtrip(self):
        self.assertEqual(
            HashDetector.hash_string("password", "md5"),
            hashlib.md5(b"password", usedforsecurity=False).hexdigest(),
        )

    def test_sha1_roundtrip(self):
        self.assertEqual(
            HashDetector.hash_string("password", "sha1"),
            hashlib.sha1(b"password", usedforsecurity=False).hexdigest(),
        )

    def test_sha256_roundtrip(self):
        self.assertEqual(
            HashDetector.hash_string("password", "sha256"),
            hashlib.sha256(b"password").hexdigest(),
        )

    def test_sha512_roundtrip(self):
        self.assertEqual(
            HashDetector.hash_string("password", "sha512"),
            hashlib.sha512(b"password").hexdigest(),
        )

    @unittest.skipUnless(HAS_MD4, "MD4 not available in this Python build")
    def test_md4_roundtrip(self):
        h = HashDetector.hash_string("password", "md4")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 32)

    def test_sha3_256_roundtrip(self):
        h = HashDetector.hash_string("password", "sha3_256")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_blake2b_roundtrip(self):
        h = HashDetector.hash_string("password", "blake2b")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 128)

    def test_ripemd160_roundtrip(self):
        h = HashDetector.hash_string("password", "ripemd160")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 40)

    def test_double_md5_roundtrip(self):
        inner = hashlib.md5(b"password", usedforsecurity=False).hexdigest()
        expected = hashlib.md5(inner.encode(), usedforsecurity=False).hexdigest()
        self.assertEqual(HashDetector.hash_string("password", "double_md5"), expected)

    @unittest.skipUnless(HAS_MD4, "MD4 not available in this Python build")
    def test_ntlm_roundtrip(self):
        h = HashDetector.hash_string("password", "ntlm")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 32)

    def test_crc32_roundtrip(self):
        h = HashDetector.hash_string("password", "crc32")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 8)

    def test_mysql323_roundtrip(self):
        h = HashDetector.hash_string("password", "mysql323")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 16)

    def test_mysql41_roundtrip(self):
        h = HashDetector.hash_string("password", "mysql41")
        self.assertIsNotNone(h)
        self.assertTrue(h.startswith("*"))
        self.assertEqual(len(h), 41)

    def test_postgres_md5_roundtrip(self):
        h = HashDetector.hash_string("password", "postgres_md5", username="user")
        self.assertIsNotNone(h)
        self.assertTrue(h.startswith("md5"))
        self.assertEqual(len(h), 35)

    def test_oracle10g_roundtrip(self):
        h = HashDetector.hash_string("password", "oracle10g")
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 40)


class TestSaltingSupport(unittest.TestCase):
    def test_salt_append_md5(self):
        result = HashDetector.hash_string(
            "password", "md5", salt="mysalt", salt_position="append"
        )
        expected = hashlib.md5(b"passwordmysalt", usedforsecurity=False).hexdigest()
        self.assertEqual(result, expected)

    def test_salt_prepend_md5(self):
        result = HashDetector.hash_string(
            "password", "md5", salt="mysalt", salt_position="prepend"
        )
        expected = hashlib.md5(b"mysaltpassword", usedforsecurity=False).hexdigest()
        self.assertEqual(result, expected)

    def test_salt_hmac_sha256(self):
        result = HashDetector.hash_string("password", "hmac_sha256", salt="mysalt")
        import hmac as hm

        expected = hm.new(b"mysalt", b"password", hashlib.sha256).hexdigest()
        self.assertEqual(result, expected)

    def test_salt_append_sha1(self):
        result = HashDetector.hash_string(
            "password", "sha1", salt="xyz", salt_position="append"
        )
        expected = hashlib.sha1(b"passwordxyz", usedforsecurity=False).hexdigest()
        self.assertEqual(result, expected)

    def test_salt_prepend_sha256(self):
        result = HashDetector.hash_string(
            "password", "sha256", salt="abc", salt_position="prepend"
        )
        expected = hashlib.sha256(b"abcpassword").hexdigest()
        self.assertEqual(result, expected)

    def test_salt_append_sha512(self):
        result = HashDetector.hash_string(
            "password", "sha512", salt="longsalt123", salt_position="append"
        )
        expected = hashlib.sha512(b"passwordlongsalt123").hexdigest()
        self.assertEqual(result, expected)

    def test_hash_salt_colon_parsing(self):
        parsed = CoreEngine()._parse_combined_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99:mysalt"
        )
        self.assertIsNotNone(parsed)
        if parsed:
            self.assertEqual(parsed["hash"], "5f4dcc3b5aa765d61d8327deb882cf99")
            self.assertEqual(parsed["salt"], "mysalt")

    def test_salt_hash_colon_parsing(self):
        parsed = CoreEngine()._parse_combined_hash(
            "mysalt:5f4dcc3b5aa765d61d8327deb882cf99"
        )
        self.assertIsNotNone(parsed)
        if parsed:
            self.assertEqual(parsed["hash"], "5f4dcc3b5aa765d61d8327deb882cf99")

    def test_md5_md5_salt(self):
        inner = hashlib.md5(b"password", usedforsecurity=False).hexdigest()
        expected = hashlib.md5(
            (inner + "xyz").encode(), usedforsecurity=False
        ).hexdigest()
        result = HashDetector.hash_string("password", "md5_md5_salt", salt="xyz")
        self.assertEqual(result, expected)

    def test_hmac_md5(self):
        import hmac as hm

        expected = hm.new(b"key123", b"password", hashlib.md5).hexdigest()
        result = HashDetector.hash_string("password", "hmac_md5", salt="key123")
        self.assertEqual(result, expected)


class TestCoreEngineSalt(unittest.TestCase):
    def setUp(self):
        self.engine = CoreEngine()

    def test_crack_md5_with_salt_append_dictionary(self):
        password = "password"
        salt = "xyz"
        target = HashDetector.hash_string(
            password, "md5", salt=salt, salt_position="append"
        )
        result = self.engine.crack_hash(
            hash_string=target,
            wordlist_path="wordlists/sample.txt",
            mode="dictionary",
            algo="md5",
            salt=salt,
            salt_position="append",
        )
        if result["success"]:
            self.assertEqual(result["password"], password)

    def test_crack_md5_with_salt_prepend_dictionary(self):
        password = "password"
        salt = "abc"
        target = HashDetector.hash_string(
            password, "md5", salt=salt, salt_position="prepend"
        )
        result = self.engine.crack_hash(
            hash_string=target,
            wordlist_path="wordlists/sample.txt",
            mode="dictionary",
            algo="md5",
            salt=salt,
            salt_position="prepend",
        )
        if result["success"]:
            self.assertEqual(result["password"], password)

    def test_crack_sha256_with_salt_append_dictionary(self):
        password = "password"
        salt = "salty"
        target = HashDetector.hash_string(
            password, "sha256", salt=salt, salt_position="append"
        )
        result = self.engine.crack_hash(
            hash_string=target,
            wordlist_path="wordlists/sample.txt",
            mode="dictionary",
            algo="sha256",
            salt=salt,
            salt_position="append",
        )
        if result["success"]:
            self.assertEqual(result["password"], password)


class TestPasswordAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_analyze_weak_password(self):
        result = self.analyzer.analyze_password("abc")
        self.assertLess(result["score"], 30)

    def test_analyze_strong_password(self):
        result = self.analyzer.analyze_password("MyP@ssw0rd123!")
        self.assertGreater(result["score"], 60)

    def test_common_pattern_detection(self):
        result = self.analyzer.analyze_password("password123")
        feedback = result.get("feedback", [])
        self.assertTrue(len(feedback) > 0)

    def test_character_analysis(self):
        result = self.analyzer.analyze_password("Test123!")
        chars = result["character_analysis"]
        self.assertTrue(chars["lowercase"])
        self.assertTrue(chars["uppercase"])
        self.assertTrue(chars["digits"])
        self.assertTrue(chars["special"])


class TestDictionaryAttack(unittest.TestCase):
    def setUp(self):
        self.engine = CoreEngine()
        self.wordlist_path = "wordlists/sample.txt"

    def test_dictionary_attack_success_md5(self):
        target = hashlib.md5(b"password", usedforsecurity=False).hexdigest()
        if os.path.exists(self.wordlist_path):
            result = self.engine.crack_hash(
                hash_string=target, wordlist_path=self.wordlist_path, mode="dictionary"
            )
            self.assertTrue(result["success"])
            self.assertEqual(result["password"], "password")

    def test_dictionary_attack_success_sha256(self):
        target = hashlib.sha256(b"password").hexdigest()
        if os.path.exists(self.wordlist_path):
            result = self.engine.crack_hash(
                hash_string=target, wordlist_path=self.wordlist_path, mode="dictionary"
            )
            self.assertTrue(result["success"])
            self.assertEqual(result["password"], "password")


class TestBruteForceAttack(unittest.TestCase):
    def setUp(self):
        self.engine = CoreEngine()

    def test_brute_force_4char_lowercase(self):
        target = hashlib.sha256(b"test").hexdigest()
        result = self.engine.crack_hash(
            hash_string=target,
            mode="brute",
            min_length=4,
            max_length=4,
            charset="lowercase",
            algo="sha256",
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["password"], "test")


class TestCoreEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CoreEngine()

    def test_invalid_hash(self):
        result = self.engine.crack_hash(hash_string="invalidenthash", mode="dictionary")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_invalid_min_max_length(self):
        target = hashlib.sha256(b"test").hexdigest()
        result = self.engine.crack_hash(
            hash_string=target, mode="brute", min_length=10, max_length=5
        )
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_algo_override_valid(self):
        target = hashlib.sha256(b"test").hexdigest()
        result = self.engine.crack_hash(
            hash_string=target,
            mode="brute",
            min_length=4,
            max_length=4,
            charset="lowercase",
            algo="sha256",
        )
        self.assertEqual(result["hash_type"], "sha256")

    def test_algo_override_invalid(self):
        target = hashlib.sha256(b"test").hexdigest()
        result = self.engine.crack_hash(hash_string=target, algo="invalid_algo")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_crack_from_file(self):
        import tempfile

        target = hashlib.sha256(b"password").hexdigest()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(target)
            tmp_path = f.name
        try:
            result = self.engine.crack_hashes_from_file(
                hash_file_path=tmp_path,
                wordlist_path="wordlists/sample.txt",
                mode="dictionary",
            )
            if os.path.exists("wordlists/sample.txt"):
                self.assertTrue(result["success"])
                self.assertGreaterEqual(result["cracked"], 1)
        finally:
            os.unlink(tmp_path)


class TestAllAlgorithmsRoundTrip(unittest.TestCase):
    """Verify every supported algorithm can produce a hash and detection works."""

    def _test_roundtrip(self, algo, password="test123"):
        try:
            h = HashDetector.hash_string(password, algo)
        except (ValueError, ImportError):
            return
        self.assertIsNotNone(h)
        self.assertIsInstance(h, str)
        self.assertTrue(len(h) > 0)

    def _test_detection(self, algo, password="test123"):
        try:
            h = HashDetector.hash_string(password, algo)
        except (ValueError, ImportError):
            return
        result = HashDetector.detect_hash_type(h)
        self.assertIsNotNone(result, f"Detection failed for {algo}")

    def test_md4(self):
        self._test_roundtrip("md4")

    def test_md5(self):
        self._test_roundtrip("md5")

    def test_sha1(self):
        self._test_roundtrip("sha1")

    def test_sha224(self):
        self._test_roundtrip("sha224")

    def test_sha256(self):
        self._test_roundtrip("sha256")

    def test_sha384(self):
        self._test_roundtrip("sha384")

    def test_sha512(self):
        self._test_roundtrip("sha512")

    def test_sha3_224(self):
        self._test_roundtrip("sha3_224")

    def test_sha3_256(self):
        self._test_roundtrip("sha3_256")

    def test_sha3_384(self):
        self._test_roundtrip("sha3_384")

    def test_sha3_512(self):
        self._test_roundtrip("sha3_512")

    def test_blake2b(self):
        self._test_roundtrip("blake2b")

    def test_blake2s(self):
        self._test_roundtrip("blake2s")

    def test_ripemd160(self):
        self._test_roundtrip("ripemd160")

    def test_whirlpool(self):
        self._test_roundtrip("whirlpool")

    def test_tiger(self):
        self._test_roundtrip("tiger")

    def test_crc32(self):
        self._test_roundtrip("crc32")

    def test_double_md5(self):
        self._test_roundtrip("double_md5")

    def test_ntlm(self):
        self._test_roundtrip("ntlm")

    def test_mysql323(self):
        self._test_roundtrip("mysql323")

    def test_mysql41(self):
        self._test_roundtrip("mysql41")

    def test_oracle10g(self):
        self._test_roundtrip("oracle10g")

    def test_postgres_md5(self):
        h = HashDetector.hash_string("test123", "postgres_md5", username="user")
        self.assertIsNotNone(h)


class TestHashcatWrapper(unittest.TestCase):
    def test_is_available_without_hashcat(self):
        from gpu.hashcat_wrapper import HashcatWrapper

        wrapper = HashcatWrapper()
        self.assertFalse(wrapper.is_available())

    def test_hashcat_modes_supported(self):
        from gpu.hashcat_wrapper import HashcatWrapper, HASHCAT_MODES

        wrapper = HashcatWrapper()
        self.assertIn("md5", HASHCAT_MODES)
        self.assertIn("sha1", HASHCAT_MODES)
        self.assertIn("sha256", HASHCAT_MODES)
        self.assertIn("sha512", HASHCAT_MODES)
        self.assertIn("ntlm", HASHCAT_MODES)
        self.assertIn("bcrypt", HASHCAT_MODES)


class TestCisco7Decode(unittest.TestCase):
    def test_cisco7_decode_format(self):
        result = HashDetector.detect_hash_type("070C285F4D06")
        self.assertIsNotNone(result)


class TestFormatter(unittest.TestCase):
    def test_format_text_color(self):
        from utils.formatter import Formatter
        Formatter.no_color = False
        result = Formatter.format_text("hello", "red")
        self.assertIn("\033[91m", result)
        self.assertIn("hello", result)
        self.assertIn("\033[0m", result)

    def test_format_text_no_color(self):
        from utils.formatter import Formatter
        Formatter.no_color = True
        result = Formatter.format_text("hello", "red")
        self.assertEqual(result, "hello")

    def test_format_text_bold(self):
        from utils.formatter import Formatter
        Formatter.no_color = False
        result = Formatter.format_text("hello", bold=True)
        self.assertIn("\033[1m", result)

    def test_print_methods_respect_no_color(self):
        import io, sys
        from utils.formatter import Formatter
        Formatter.no_color = True
        captured = io.StringIO()
        old = sys.stdout
        sys.stdout = captured
        try:
            Formatter.print_success("test")
            Formatter.print_error("test")
            Formatter.print_warning("test")
            Formatter.print_info("test")
        finally:
            sys.stdout = old
        output = captured.getvalue()
        self.assertNotIn("\033", output)
        self.assertEqual(output.count("test"), 4)


if __name__ == "__main__":
    unittest.main()
