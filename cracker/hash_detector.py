import re
import hashlib
import unicodedata
import struct
import zlib

HAS_PASSLIB = False
HAS_BCRYPT = False
HAS_ARGON2 = False
HAS_MD4 = False

try:
    hashlib.new("md4", b"test", usedforsecurity=False)
    HAS_MD4 = True
except Exception:
    HAS_MD4 = False
try:
    import passlib.hash

    HAS_PASSLIB = True
except ImportError:
    pass
try:
    import bcrypt

    HAS_BCRYPT = True
except ImportError:
    pass
try:
    from argon2 import PasswordHasher as Argon2Hasher
    import argon2.exceptions

    HAS_ARGON2 = True
except ImportError:
    pass


class HashDetector:
    ALGO_META = {
        # (algo_key, display_name, typical_length_hex, hashcat_mode, is_slow, category, note)
        "md4": (
            "md4",
            "MD4",
            32,
            900,
            False,
            "generic",
            "Unsalted, extremely fast — broken",
        ),
        "md5": (
            "md5",
            "MD5",
            32,
            0,
            False,
            "generic",
            "Unsalted — widely used, very fast",
        ),
        "sha1": (
            "sha1",
            "SHA1",
            40,
            100,
            False,
            "generic",
            "Unsalted — deprecated for crypto",
        ),
        "sha224": ("sha224", "SHA224", 56, 1300, False, "generic", ""),
        "sha256": (
            "sha256",
            "SHA256",
            64,
            1400,
            False,
            "generic",
            "Default for many modern systems",
        ),
        "sha384": ("sha384", "SHA384", 96, 10800, False, "generic", ""),
        "sha512": ("sha512", "SHA512", 128, 1700, False, "generic", ""),
        "sha3_224": ("sha3_224", "SHA3-224", 56, 17400, False, "generic", ""),
        "sha3_256": ("sha3_256", "SHA3-256", 64, 17500, False, "generic", ""),
        "sha3_384": ("sha3_384", "SHA3-384", 96, 17600, False, "generic", ""),
        "sha3_512": ("sha3_512", "SHA3-512", 128, 17700, False, "generic", ""),
        "blake2b": (
            "blake2b",
            "BLAKE2b",
            128,
            None,
            False,
            "generic",
            "512-bit output by default",
        ),
        "blake2s": (
            "blake2s",
            "BLAKE2s",
            64,
            None,
            False,
            "generic",
            "256-bit output by default",
        ),
        "ripemd160": ("ripemd160", "RIPEMD-160", 40, 6000, False, "generic", ""),
        "whirlpool": ("whirlpool", "Whirlpool", 128, 6100, False, "generic", ""),
        "tiger": ("tiger", "Tiger", 48, 12500, False, "generic", "192-bit output"),
        "crc32": (
            "crc32",
            "CRC32",
            8,
            11500,
            False,
            "generic",
            "NOT a password hash — checksum only",
        ),
        "double_md5": (
            "double_md5",
            "Double MD5",
            32,
            2600,
            False,
            "iterated",
            "md5(md5(x))",
        ),
        "md5_md5_salt": (
            "md5_md5_salt",
            "MD5(MD5+salt)",
            32,
            3810,
            False,
            "iterated",
            "md5(md5(password).salt)",
        ),
        "hmac_md5": ("hmac_md5", "HMAC-MD5", 32, 50, False, "iterated", ""),
        "hmac_sha1": ("hmac_sha1", "HMAC-SHA1", 40, 150, False, "iterated", ""),
        "hmac_sha256": ("hmac_sha256", "HMAC-SHA256", 64, 1450, False, "iterated", ""),
        "bcrypt": (
            "bcrypt",
            "bcrypt",
            None,
            3200,
            True,
            "slow_kdf",
            "Self-describing $2a$/$2b$/$2y$",
        ),
        "scrypt": (
            "scrypt",
            "scrypt",
            None,
            8900,
            True,
            "slow_kdf",
            "Self-describing format",
        ),
        "argon2i": (
            "argon2i",
            "Argon2i",
            None,
            9200,
            True,
            "slow_kdf",
            "Self-describing $argon2i$",
        ),
        "argon2d": (
            "argon2d",
            "Argon2d",
            None,
            9300,
            True,
            "slow_kdf",
            "Self-describing $argon2d$",
        ),
        "argon2id": (
            "argon2id",
            "Argon2id",
            None,
            9400,
            True,
            "slow_kdf",
            "Self-describing $argon2id$",
        ),
        "pbkdf2_sha1": (
            "pbkdf2_sha1",
            "PBKDF2-SHA1",
            40,
            12001,
            True,
            "slow_kdf",
            "Iteration count embedded in format",
        ),
        "pbkdf2_sha256": (
            "pbkdf2_sha256",
            "PBKDF2-SHA256",
            64,
            10900,
            True,
            "slow_kdf",
            "",
        ),
        "pbkdf2_sha512": (
            "pbkdf2_sha512",
            "PBKDF2-SHA512",
            128,
            12100,
            True,
            "slow_kdf",
            "",
        ),
        "descrypt": (
            "descrypt",
            "DES crypt",
            None,
            1500,
            False,
            "unix_crypt",
            "13-char legacy, no $ prefix",
        ),
        "md5_crypt": (
            "md5_crypt",
            "MD5-crypt",
            None,
            500,
            False,
            "unix_crypt",
            "$1$salt$hash",
        ),
        "sha256_crypt": (
            "sha256_crypt",
            "SHA256-crypt",
            None,
            7400,
            False,
            "unix_crypt",
            "$5$salt$hash",
        ),
        "sha512_crypt": (
            "sha512_crypt",
            "SHA512-crypt",
            None,
            1800,
            False,
            "unix_crypt",
            "$6$salt$hash – Linux shadow default",
        ),
        "yescrypt": (
            "yescrypt",
            "yescrypt",
            None,
            25600,
            True,
            "unix_crypt",
            "$y$/$7$ prefix",
        ),
        "lm": (
            "lm",
            "LM hash",
            32,
            3000,
            False,
            "windows",
            "Unsalted, 7-char split, extremely weak",
        ),
        "ntlm": (
            "ntlm",
            "NTLM",
            32,
            1000,
            False,
            "windows",
            "MD4 of UTF-16LE, unsalted, very fast",
        ),
        "ntlmv2": (
            "ntlmv2",
            "NTLMv2",
            None,
            5600,
            False,
            "windows",
            "Needs challenge-response capture",
        ),
        "mysql323": (
            "mysql323",
            "MySQL 3.2.3",
            16,
            200,
            False,
            "database",
            "Old MySQL, 16-hex",
        ),
        "mysql41": (
            "mysql41",
            "MySQL 4.1+",
            40,
            300,
            False,
            "database",
            "SHA1(SHA1(pw)) in hex (40) or *40hex",
        ),
        "mssql2000": (
            "mssql2000",
            "MSSQL 2000",
            40,
            131,
            False,
            "database",
            "SHA1-based, unsalted",
        ),
        "mssql2005": (
            "mssql2005",
            "MSSQL 2005",
            40,
            132,
            False,
            "database",
            "SHA1(pw+salt) with salt",
        ),
        "mssql2008": (
            "mssql2008",
            "MSSQL 2008",
            64,
            1731,
            False,
            "database",
            "SHA256-based",
        ),
        "mssql2012": (
            "mssql2012",
            "MSSQL 2012+",
            128,
            1731,
            False,
            "database",
            "SHA512-based with salt",
        ),
        "oracle10g": (
            "oracle10g",
            "Oracle 10g",
            40,
            3100,
            False,
            "database",
            "Unsalted SHA1",
        ),
        "oracle11g": (
            "oracle11g",
            "Oracle 11g/12c",
            60,
            112,
            False,
            "database",
            "SHA1-based with salt, 60-char hex",
        ),
        "postgres_md5": (
            "postgres_md5",
            "PostgreSQL MD5",
            35,
            110,
            False,
            "database",
            '"md5"+md5(pw+username)',
        ),
        "phpass": (
            "phpass",
            "phpass (WP/phpBB) ",
            None,
            400,
            True,
            "web",
            "$P$/$H$ prefix, WordPress/phpBB",
        ),
        "django_pbkdf2": (
            "django_pbkdf2",
            "Django PBKDF2",
            None,
            10000,
            True,
            "web",
            "Django default hash format",
        ),
        "drupal7": (
            "drupal7",
            "Drupal 7",
            None,
            8100,
            True,
            "web",
            "$S$, SHA512-based phpass variant",
        ),
        "joomla": ("joomla", "Joomla", 65, None, False, "web", "Joomla hash format"),
        "ldap_ssha": (
            "ldap_ssha",
            "LDAP {SSHA}",
            None,
            111,
            False,
            "enterprise",
            "Salted SHA1, {SSHA} prefix",
        ),
        "ldap_sha": (
            "ldap_sha",
            "LDAP {SHA}",
            None,
            101,
            False,
            "enterprise",
            "Unsalted SHA1, {SHA} prefix",
        ),
        "ldap_md5": (
            "ldap_md5",
            "LDAP {MD5}",
            32,
            1,
            False,
            "enterprise",
            "Unsalted MD5, {MD5} prefix",
        ),
        "ldap_crypt": (
            "ldap_crypt",
            "LDAP {CRYPT}",
            None,
            1500,
            False,
            "enterprise",
            "Unix crypt in {CRYPT} wrapper",
        ),
        "krb5asrep": (
            "krb5asrep",
            "Kerberos AS-REP",
            None,
            18200,
            False,
            "enterprise",
            "krb5asrep$ prefix, needs ticket",
        ),
        "krb5tgs": (
            "krb5tgs",
            "Kerberos TGS-REP",
            None,
            13100,
            False,
            "enterprise",
            "krb5tgs$ prefix, needs ticket",
        ),
        "cisco5": (
            "cisco5",
            "Cisco IOS type 5",
            None,
            5700,
            False,
            "enterprise",
            "MD5-crypt variant",
        ),
        "cisco7": (
            "cisco7",
            "Cisco IOS type 7",
            None,
            None,
            False,
            "enterprise",
            "Reversible XOR, not a hash — decode",
        ),
        "macos_pbkdf2": (
            "macos_pbkdf2",
            "macOS PBKDF2",
            None,
            7100,
            True,
            "macos",
            "Salted SHA512-PBKDF2",
        ),
    }

    HEX_PATTERNS = {}
    for k, v in ALGO_META.items():
        if v[2] is not None:
            HEX_PATTERNS.setdefault(v[2], []).append(k)

    PREFIX_SIGNATURES = [
        (re.compile(r"^\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{53}"), "bcrypt"),
        (re.compile(r"^\$argon2i\$"), "argon2i"),
        (re.compile(r"^\$argon2d\$"), "argon2d"),
        (re.compile(r"^\$argon2id\$"), "argon2id"),
        (re.compile(r"^\$1\$\S{1,8}\$"), "md5_crypt"),
        (re.compile(r"^\$5\$\S{1,16}\$"), "sha256_crypt"),
        (re.compile(r"^\$6\$\S{1,16}\$"), "sha512_crypt"),
        (re.compile(r"^\$y\$"), "yescrypt"),
        (re.compile(r"^\$7\$"), "yescrypt"),
        (re.compile(r"^\{SSHA\}"), "ldap_ssha"),
        (re.compile(r"^\{SHA\}"), "ldap_sha"),
        (re.compile(r"^\{MD5\}"), "ldap_md5"),
        (re.compile(r"^\{CRYPT\}"), "ldap_crypt"),
        (re.compile(r"^\$P\$"), "phpass"),
        (re.compile(r"^\$H\$"), "phpass"),
        (re.compile(r"^\$S\$"), "drupal7"),
        (re.compile(r"^krb5asrep\$"), "krb5asrep"),
        (re.compile(r"^krb5tgs\$"), "krb5tgs"),
        (re.compile(r"^\*[A-F0-9]{40}$"), "mysql41"),
        (re.compile(r"^md5[0-9a-fA-F]{32}$"), "postgres_md5"),
        (re.compile(r"^\$2[aby]\$\d{2}\$"), "bcrypt"),
    ]

    ALGO_ID_MAP = {
        "1": "md5_crypt",
        "5": "sha256_crypt",
        "6": "sha512_crypt",
        "y": "yescrypt",
        "7": "yescrypt",
        "2a": "bcrypt",
        "2b": "bcrypt",
        "2y": "bcrypt",
        "argon2i": "argon2i",
        "argon2d": "argon2d",
        "argon2id": "argon2id",
    }

    @classmethod
    def detect_hash_type(cls, hash_string):
        if not hash_string:
            return None
        hash_string = hash_string.strip()

        salt = None

        # 1) Try prefix signatures first (unambiguous)
        for pattern, algo_key in cls.PREFIX_SIGNATURES:
            if pattern.match(hash_string):
                meta = cls.ALGO_META[algo_key]
                salt = cls._extract_salt_from_prefix(hash_string, algo_key)
                return {
                    "algo": algo_key,
                    "name": meta[1],
                    "confidence": 1.0,
                    "salt": salt,
                    "candidates": [
                        {"algo": algo_key, "name": meta[1], "confidence": 1.0}
                    ],
                }

        # 2) Cisco type 7 detection (starts with 07 or 04 etc.)
        if re.match(r"^(0[0-9]{2}[A-F0-9]+)$", hash_string) and len(hash_string) >= 6:
            meta = cls.ALGO_META["cisco7"]
            return {
                "algo": "cisco7",
                "name": meta[1],
                "confidence": 1.0,
                "salt": None,
                "candidates": [{"algo": "cisco7", "name": meta[1], "confidence": 1.0}],
            }

        # 3) DES crypt (13 chars, all alphanumeric/./, no $, starts with 2 chars)
        if len(hash_string) == 13 and re.match(r"^[\.\/0-9A-Za-z]{13}$", hash_string):
            meta = cls.ALGO_META["descrypt"]
            return {
                "algo": "descrypt",
                "name": meta[1],
                "confidence": 0.95,
                "salt": hash_string[:2],
                "candidates": [
                    {"algo": "descrypt", "name": meta[1], "confidence": 0.95}
                ],
            }

        # 4) LM hash detection (32 hex, but specific pattern: split into two 16-char halves)
        if len(hash_string) == 32 and re.match(r"^[a-fA-F0-9]{32}$", hash_string):
            upper = hash_string.upper()
            if upper.endswith("AAD3B435B51404EE"):
                return {
                    "algo": "lm",
                    "name": "LM hash",
                    "confidence": 0.99,
                    "salt": None,
                    "candidates": [
                        {"algo": "lm", "name": "LM hash", "confidence": 0.99},
                        {"algo": "ntlm", "name": "NTLM", "confidence": 0.8},
                        {"algo": "md5", "name": "MD5", "confidence": 0.7},
                        {"algo": "md4", "name": "MD4", "confidence": 0.6},
                        {"algo": "mysql41", "name": "MySQL 4.1+", "confidence": 0.3},
                        {"algo": "double_md5", "name": "Double MD5", "confidence": 0.3},
                    ],
                }

        # 5) NTLMv2 specific format (hex prefix with user:domain:...)
        if re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]+:[a-fA-F0-9]+:", hash_string):
            meta = cls.ALGO_META["ntlmv2"]
            return {
                "algo": "ntlmv2",
                "name": meta[1],
                "confidence": 0.95,
                "salt": None,
                "candidates": [{"algo": "ntlmv2", "name": meta[1], "confidence": 0.95}],
            }

        # 6) Joomla hash (32 hex:32 hex)
        if re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{16,32}$", hash_string):
            meta = cls.ALGO_META["joomla"]
            parts = hash_string.split(":")
            return {
                "algo": "joomla",
                "name": meta[1],
                "confidence": 0.95,
                "salt": parts[1],
                "candidates": [{"algo": "joomla", "name": meta[1], "confidence": 0.95}],
            }

        # 7) Hex length-based detection (may be ambiguous)
        hex_match = re.match(r"^[a-fA-F0-9]+$", hash_string)
        if hex_match:
            length = len(hash_string)
            candidates = []
            if length in cls.HEX_PATTERNS:
                keys = cls.HEX_PATTERNS[length]
                for k in keys:
                    meta = cls.ALGO_META[k]
                    confidence = cls._confidence_for_hex(k, length, hash_string)
                    candidates.append(
                        {"algo": k, "name": meta[1], "confidence": confidence}
                    )
                candidates.sort(key=lambda x: x["confidence"], reverse=True)
                if candidates:
                    best = candidates[0]
                    return {
                        "algo": best["algo"],
                        "name": best["name"],
                        "confidence": best["confidence"],
                        "salt": None,
                        "candidates": candidates,
                    }

        # 8) Combined hash:salt format (colon-delimited)
        if ":" in hash_string and not hash_string.startswith("krb5"):
            parts = hash_string.split(":")
            if len(parts) == 2:
                h, s = parts
                if re.match(r"^[a-fA-F0-9]+$", h):
                    result = cls.detect_hash_type(h)
                    if result:
                        result["salt"] = s
                        if result.get("algo"):
                            result["name"] = (
                                cls.ALGO_META[result["algo"]][1] + " (salted)"
                            )
                        return result
                if re.match(r"^[a-fA-F0-9]+$", s):
                    result = cls.detect_hash_type(s)
                    if result:
                        result["salt"] = h
                        if result.get("algo"):
                            result["name"] = (
                                cls.ALGO_META[result["algo"]][1] + " (salt:hash)"
                            )
                        return result

        return None

    @classmethod
    def _confidence_for_hex(cls, algo_key, length, hash_string):
        base = 0.5
        meta = cls.ALGO_META.get(algo_key)
        if not meta:
            return 0.1
        if length == 32:
            if algo_key in ("md5",):
                base = 0.9
            elif algo_key in ("ntlm",):
                if any(c.isalpha() for c in hash_string):
                    base = 0.6
                else:
                    base = 0.5
            elif algo_key in ("md4",):
                base = 0.5
            elif algo_key in ("double_md5",):
                base = 0.5
            elif algo_key in ("mysql41",):
                base = 0.2
            elif algo_key in ("lm",):
                base = 0.1
            else:
                base = 0.3
        elif length == 40:
            if algo_key in ("sha1",):
                base = 0.9
            elif algo_key in ("ripemd160",):
                base = 0.4
            elif algo_key in ("mysql41",):
                if hash_string.isupper():
                    base = 0.7
                else:
                    base = 0.2
            elif algo_key in ("mssql2000", "mssql2005"):
                base = 0.3
            elif algo_key in ("oracle10g",):
                base = 0.4
            elif algo_key in ("hmac_sha1",):
                base = 0.2
            else:
                base = 0.3
        elif length == 64:
            if algo_key in ("sha256",):
                base = 0.9
            elif algo_key in ("sha3_256",):
                base = 0.5
            elif algo_key in ("blake2s",):
                base = 0.3
            elif algo_key in ("hmac_sha256",):
                base = 0.2
            elif algo_key in ("mssql2008",):
                base = 0.3
            else:
                base = 0.3
        elif length == 128:
            if algo_key in ("sha512",):
                base = 0.8
            elif algo_key in ("whirlpool",):
                base = 0.5
            elif algo_key in ("blake2b",):
                base = 0.4
            elif algo_key in ("sha3_512",):
                base = 0.5
            else:
                base = 0.3
        elif length == 56:
            if algo_key in ("sha224", "sha3_224"):
                base = 0.7
        elif length == 96:
            if algo_key in ("sha384", "sha3_384"):
                base = 0.7
        elif length == 48:
            if algo_key in ("tiger",):
                base = 0.9
        elif length == 16:
            if algo_key in ("mysql323",):
                base = 0.9
        elif length == 8:
            if algo_key in ("crc32",):
                base = 0.9
        elif length == 35:
            if algo_key in ("postgres_md5",):
                base = 0.9
        elif length == 60:
            if algo_key in ("oracle11g",):
                base = 0.9
        elif length == 65:
            if algo_key in ("joomla",):
                base = 0.7

        if meta[4]:
            base -= 0.1
        return max(0.05, min(0.99, base))

    @classmethod
    def _extract_salt_from_prefix(cls, hash_string, algo_key):
        if algo_key == "bcrypt":
            m = re.match(r"^\$2[aby]\$\d{2}\$([.\/A-Za-z0-9]{22})", hash_string)
            return m.group(1) if m else None
        if algo_key in ("md5_crypt",):
            m = re.match(r"^\$1\$([^\$]{1,8})\$", hash_string)
            return m.group(1) if m else None
        if algo_key in ("sha256_crypt",):
            m = re.match(r"^\$5\$([^\$]{1,16})\$", hash_string)
            return m.group(1) if m else None
        if algo_key in ("sha512_crypt",):
            m = re.match(r"^\$6\$([^\$]{1,16})\$", hash_string)
            return m.group(1) if m else None
        if algo_key in ("yescrypt",):
            m = re.match(r"^\$[y7]\$[^\$]*\$([^\$]+)\$", hash_string)
            return m.group(1) if m else None
        if algo_key in ("ldap_ssha",):
            raw = hash_string[6:]
            try:
                decoded = raw.encode() if isinstance(raw, str) else raw
                import base64

                dec = base64.b64decode(decoded)
                return dec[20:].hex() if len(dec) > 20 else None
            except Exception:
                return None
        if algo_key in ("phpass", "drupal7"):
            return hash_string[:12]
        if algo_key in ("django_pbkdf2",):
            parts = hash_string.split("$")
            return parts[2] if len(parts) >= 4 else None
        if algo_key in ("pbkdf2_sha1", "pbkdf2_sha256", "pbkdf2_sha512"):
            parts = hash_string.split("$")
            return parts[2] if len(parts) >= 4 else None
        if algo_key in ("macos_pbkdf2",):
            parts = hash_string.split("$")
            return parts[2] if len(parts) >= 4 else None
        if algo_key in ("mssql2005",):
            parts = hash_string.split(":")
            return parts[1] if len(parts) > 1 else None
        if algo_key in ("mssql2012",):
            parts = hash_string.split(":")
            return parts[1] if len(parts) > 1 else None
        if algo_key in ("oracle11g",):
            if ":" in hash_string:
                parts = hash_string.split(":")
                return parts[1] if len(parts) > 1 else None
            return hash_string[40:]
        if algo_key in ("cisco5",):
            return hash_string[:4]
        return None

    @classmethod
    def parse_crypt_hash(cls, hash_string):
        if not hash_string or not hash_string.startswith("$"):
            return None
        hash_string = hash_string.strip()
        if hash_string.startswith("$2"):
            m = re.match(
                r"^\$2[aby]\$(\d{2})\$([.\/A-Za-z0-9]{22})([.\/A-Za-z0-9]{31})?",
                hash_string,
            )
            if m:
                return {
                    "algo": "bcrypt",
                    "salt": m.group(2),
                    "hash": m.group(3) or "",
                    "rounds": int(m.group(1)),
                }
        if hash_string.startswith("$argon2"):
            parts = hash_string.split("$")
            if len(parts) >= 5:
                algo = parts[1]
                params = parts[2] if len(parts) > 2 else ""
                salt = parts[3] if len(parts) > 3 else ""
                h = parts[4] if len(parts) > 4 else ""
                return {"algo": algo, "salt": salt, "hash": h, "params": params}
        if hash_string.startswith("$1$"):
            m = re.match(r"^\$1\$([^\$]{1,8})\$([a-fA-F0-9]{22})", hash_string)
            if m:
                return {"algo": "md5_crypt", "salt": m.group(1), "hash": m.group(2)}
        if hash_string.startswith("$5$"):
            m = re.match(r"^\$5\$([^\$]{1,16})\$([a-fA-F0-9]{43,86})", hash_string)
            if m:
                return {"algo": "sha256_crypt", "salt": m.group(1), "hash": m.group(2)}
        if hash_string.startswith("$6$"):
            m = re.match(r"^\$6\$([^\$]{1,16})\$([a-fA-F0-9]{86})", hash_string)
            if m:
                return {"algo": "sha512_crypt", "salt": m.group(1), "hash": m.group(2)}
        if hash_string.startswith("$y$") or hash_string.startswith("$7$"):
            parts = hash_string.split("$")
            if len(parts) >= 5:
                return {
                    "algo": "yescrypt",
                    "salt": parts[3] if len(parts) > 3 else parts[2],
                    "hash": parts[-1],
                    "params": parts[2] if len(parts) > 3 else "",
                }
        return None

    @classmethod
    def get_hash_name(cls, algo_key):
        meta = cls.ALGO_META.get(algo_key)
        return meta[1] if meta else "Unknown"

    @classmethod
    def is_valid_hash(cls, hash_string):
        return cls.detect_hash_type(hash_string) is not None

    @classmethod
    def is_valid_hash_for_type(cls, hash_string, algo_key):
        result = cls.detect_hash_type(hash_string)
        if not result:
            return False
        if result.get("algo") == algo_key:
            return True
        if result.get("candidates"):
            for c in result["candidates"]:
                if c["algo"] == algo_key:
                    return True
        return False

    @classmethod
    def hash_string(cls, text, algorithm, salt=None, salt_position="append", **kwargs):
        normalized = unicodedata.normalize("NFC", text)
        encoded = normalized.encode("utf-8", errors="surrogatepass")

        def apply_salt(data):
            if salt is None:
                return data
            salt_enc = salt.encode("utf-8") if isinstance(salt, str) else salt
            if salt_position == "prepend":
                return salt_enc + data
            elif salt_position == "append":
                return data + salt_enc
            elif salt_position == "hmac":
                import hmac

                return hmac.new(salt_enc, data, hashlib.sha256).digest()
            else:
                return data + salt_enc

        algo_lower = algorithm.lower().replace("-", "_").replace(".", "")

        # md5
        if algo_lower == "md5":
            return hashlib.md5(apply_salt(encoded), usedforsecurity=False).hexdigest()
        # md4
        if algo_lower == "md4":
            if HAS_MD4:
                return hashlib.new(
                    "md4", apply_salt(encoded), usedforsecurity=False
                ).hexdigest()
            raise ValueError(
                "MD4 not available in this Python build. "
                "Use hashcat mode 900 for MD4 cracking."
            )
        # sha1
        if algo_lower == "sha1":
            return hashlib.sha1(apply_salt(encoded), usedforsecurity=False).hexdigest()
        # sha224
        if algo_lower == "sha224":
            return hashlib.sha224(
                apply_salt(encoded), usedforsecurity=False
            ).hexdigest()
        # sha256
        if algo_lower == "sha256":
            return hashlib.sha256(
                apply_salt(encoded), usedforsecurity=False
            ).hexdigest()
        # sha384
        if algo_lower == "sha384":
            return hashlib.sha384(
                apply_salt(encoded), usedforsecurity=False
            ).hexdigest()
        # sha512
        if algo_lower == "sha512":
            return hashlib.sha512(
                apply_salt(encoded), usedforsecurity=False
            ).hexdigest()
        # sha3 variants
        if algo_lower in ("sha3_224", "sha3-224"):
            return hashlib.sha3_224(apply_salt(encoded)).hexdigest()
        if algo_lower in ("sha3_256", "sha3-256"):
            return hashlib.sha3_256(apply_salt(encoded)).hexdigest()
        if algo_lower in ("sha3_384", "sha3-384"):
            return hashlib.sha3_384(apply_salt(encoded)).hexdigest()
        if algo_lower in ("sha3_512", "sha3-512"):
            return hashlib.sha3_512(apply_salt(encoded)).hexdigest()
        # blake2b (512-bit)
        if algo_lower in ("blake2b",):
            return hashlib.blake2b(apply_salt(encoded), digest_size=64).hexdigest()
        # blake2s (256-bit)
        if algo_lower in ("blake2s",):
            return hashlib.blake2s(apply_salt(encoded), digest_size=32).hexdigest()
        # ripemd160
        if algo_lower in ("ripemd160", "ripemd-160"):
            return hashlib.new("ripemd160", apply_salt(encoded)).hexdigest()
        # whirlpool
        if algo_lower == "whirlpool":
            return hashlib.new("whirlpool", apply_salt(encoded)).hexdigest()
        # tiger
        if algo_lower == "tiger":
            return hashlib.new(
                "tiger", apply_salt(encoded), usedforsecurity=False
            ).hexdigest()
        # crc32
        if algo_lower == "crc32":
            crc = zlib.crc32(apply_salt(encoded)) & 0xFFFFFFFF
            return format(crc, "08x")
        # double_md5: md5(md5(x))
        if algo_lower == "double_md5":
            inner = hashlib.md5(encoded, usedforsecurity=False).hexdigest()
            return hashlib.md5(inner.encode(), usedforsecurity=False).hexdigest()
        # md5_md5_salt: md5(md5(password).salt) or md5(md5(password)+salt)
        if algo_lower == "md5_md5_salt":
            inner = hashlib.md5(encoded, usedforsecurity=False).hexdigest()
            combined = (inner + salt) if salt else inner
            return hashlib.md5(combined.encode(), usedforsecurity=False).hexdigest()
        # hmac variants
        if algo_lower == "hmac_md5":
            import hmac

            key = salt.encode() if salt else b""
            return hmac.new(key, encoded, hashlib.md5).hexdigest()
        if algo_lower == "hmac_sha1":
            import hmac

            key = salt.encode() if salt else b""
            return hmac.new(key, encoded, hashlib.sha1).hexdigest()
        if algo_lower == "hmac_sha256":
            import hmac

            key = salt.encode() if salt else b""
            return hmac.new(key, encoded, hashlib.sha256).hexdigest()
        # lm hash
        if algo_lower == "lm":
            return cls._lm_hash(text)
        # ntlm
        if algo_lower == "ntlm":
            return cls._ntlm_hash(text)
        # mysql323
        if algo_lower == "mysql323":
            return cls._mysql323_hash(text)
        # mysql41
        if algo_lower == "mysql41":
            return cls._mysql41_hash(text)
        # postgres_md5 (needs username in kwargs)
        if algo_lower == "postgres_md5":
            username = kwargs.get("username", "")
            return cls._postgres_md5_hash(text, username)
        # oracle10g
        if algo_lower == "oracle10g":
            return cls._oracle10g_hash(text)
        # oracle11g (needs salt in kwargs or salt param)
        if algo_lower == "oracle11g":
            s = salt or kwargs.get("salt", "")
            return cls._oracle11g_hash(text, s)
        # mssql2000
        if algo_lower == "mssql2000":
            return cls._mssql2000_hash(text)
        # mssql2005 (needs salt)
        if algo_lower == "mssql2005":
            s = salt or kwargs.get("salt", "")
            return cls._mssql2005_hash(text, s)
        # mssql2008
        if algo_lower == "mssql2008":
            s = salt or kwargs.get("salt", "")
            return cls._mssql2008_hash(text, s)
        # mssql2012
        if algo_lower == "mssql2012":
            s = salt or kwargs.get("salt", "")
            return cls._mssql2012_hash(text, s)
        # cisco7
        if algo_lower == "cisco7":
            return cls._cisco7_decode(text)

        # Passlib-required algorithms
        if algo_lower in (
            "bcrypt",
            "sha256_crypt",
            "sha512_crypt",
            "md5_crypt",
            "descrypt",
            "yescrypt",
            "pbkdf2_sha1",
            "pbkdf2_sha256",
            "pbkdf2_sha512",
            "phpass",
            "django_pbkdf2",
            "drupal7",
            "ldap_ssha",
            "ldap_sha",
            "ldap_md5",
            "ldap_crypt",
            "macos_pbkdf2",
            "cisco5",
            "scrypt",
            "argon2i",
            "argon2d",
            "argon2id",
        ):
            raise ValueError(
                f"Algorithm '{algorithm}' requires passlib/bcrypt/argon2. "
                "Use verify_hash() instead, or install passlib and bcrypt."
            )

        raise ValueError(f"Unsupported algorithm: {algorithm}")

    @classmethod
    def verify_hash(
        cls,
        password,
        hash_string,
        algo_key=None,
        salt=None,
        salt_position="append",
        **kwargs,
    ):
        if algo_key is None:
            result = cls.detect_hash_type(hash_string)
            if result:
                algo_key = result.get("algo")
                salt = salt or result.get("salt")
        if algo_key is None:
            return False, {"error": "Unable to detect hash type"}

        try:
            normalized = unicodedata.normalize("NFC", password)
            encoded = normalized.encode("utf-8", errors="surrogatepass")
        except Exception:
            return False, {"error": "Encoding error"}

        algo = algo_key.lower().replace("-", "_")

        # Passlib-based verification
        if algo in (
            "bcrypt",
            "sha256_crypt",
            "sha512_crypt",
            "md5_crypt",
            "descrypt",
            "yescrypt",
            "pbkdf2_sha1",
            "pbkdf2_sha256",
            "pbkdf2_sha512",
            "phpass",
            "django_pbkdf2",
            "drupal7",
            "ldap_ssha",
            "ldap_sha",
            "ldap_md5",
            "ldap_crypt",
            "macos_pbkdf2",
            "cisco5",
            "scrypt",
        ):
            if HAS_PASSLIB:
                try:
                    schemes = {
                        "bcrypt": passlib.hash.bcrypt,
                        "sha256_crypt": passlib.hash.sha256_crypt,
                        "sha512_crypt": passlib.hash.sha512_crypt,
                        "md5_crypt": passlib.hash.md5_crypt,
                        "descrypt": passlib.hash.des_crypt,
                        "yescrypt": None,
                        "pbkdf2_sha1": passlib.hash.pbkdf2_sha1,
                        "pbkdf2_sha256": passlib.hash.pbkdf2_sha256,
                        "pbkdf2_sha512": passlib.hash.pbkdf2_sha512,
                        "phpass": passlib.hash.phpass,
                        "django_pbkdf2": None,
                        "drupal7": None,
                        "ldap_ssha": None,
                        "ldap_sha": None,
                        "ldap_md5": None,
                        "ldap_crypt": None,
                        "macos_pbkdf2": None,
                        "cisco5": None,
                        "scrypt": passlib.hash.scrypt,
                    }
                    scheme = schemes.get(algo)
                    if scheme:
                        valid = scheme.verify(password, hash_string)
                        return valid, {} if valid else {"error": "Password mismatch"}
                except Exception:
                    pass
        # bcrypt direct
        if algo == "bcrypt" and HAS_BCRYPT and not HAS_PASSLIB:
            try:
                if isinstance(hash_string, str):
                    hash_string = hash_string.encode()
                if isinstance(password, str):
                    password = password.encode()
                valid = bcrypt.checkpw(password, hash_string)
                return valid, {} if valid else {"error": "Password mismatch"}
            except Exception as e:
                return False, {"error": f"bcrypt error: {e}"}
        # Argon2 direct
        if algo in ("argon2i", "argon2d", "argon2id") and HAS_ARGON2:
            try:
                ph = Argon2Hasher()
                valid = ph.verify(hash_string, password)
                return valid, {} if valid else {"error": "Password mismatch"}
            except argon2.exceptions.VerificationError:
                return False, {"error": "Argon2 mismatch"}
            except Exception as e:
                return False, {"error": f"Argon2 error: {e}"}

        # Passlib for django
        if algo == "django_pbkdf2" and HAS_PASSLIB:
            try:
                valid = passlib.hash.django_pbkdf2_sha256.verify(password, hash_string)
                return valid, {} if valid else {"error": "Password mismatch"}
            except Exception:
                try:
                    valid = passlib.hash.django_pbkdf2_sha1.verify(
                        password, hash_string
                    )
                    return valid, {} if valid else {"error": "Password mismatch"}
                except Exception:
                    pass

        # Fallback: standard hash_string comparison
        if algo in cls.ALGO_META:
            meta = cls.ALGO_META[algo]
            if meta[2] is not None:
                try:
                    computed = cls.hash_string(
                        password, algo, salt=salt, salt_position=salt_position, **kwargs
                    )
                    return computed == hash_string, {} if computed == hash_string else {
                        "error": "Password mismatch"
                    }
                except ValueError as e:
                    return False, {"error": str(e)}

        return False, {"error": f"Unsupported algorithm: {algo_key}"}

    @classmethod
    def crack_with_passlib(cls, password, hash_string):
        try:
            if HAS_PASSLIB:
                from passlib.apps import custom_app_context

                try:
                    valid = custom_app_context.verify(password, hash_string)
                    if valid:
                        return True
                except Exception:
                    pass
                for scheme_name in dir(passlib.hash):
                    scheme = getattr(passlib.hash, scheme_name)
                    if callable(getattr(scheme, "verify", None)):
                        try:
                            if scheme.verify(password, hash_string):
                                return True
                        except Exception:
                            continue
        except Exception:
            pass
        if HAS_BCRYPT:
            try:
                return bcrypt.checkpw(
                    password.encode(),
                    hash_string.encode()
                    if isinstance(hash_string, str)
                    else hash_string,
                )
            except Exception:
                pass
        return False

    @classmethod
    def _lm_hash(cls, password):
        raise ValueError(
            "LM hash computation requires pycryptodome (pip install pycryptodome). "
            "Use hashcat mode 3000 for LM cracking. Detection is still supported."
        )

    @classmethod
    def _ntlm_hash(cls, password):
        try:
            encoded = password.encode("utf-16le")
        except Exception:
            encoded = password.encode("utf-16-le", errors="replace")
        if HAS_MD4:
            return hashlib.new("md4", encoded, usedforsecurity=False).hexdigest()
        raise ValueError(
            "MD4 (needed for NTLM) not available in this Python build. "
            "Use hashcat mode 1000 for NTLM cracking."
        )

    @classmethod
    def _mysql323_hash(cls, password):
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        for c in password if isinstance(password, str) else password.decode("latin-1"):
            if c == " " or c == "\t":
                continue
            c_val = ord(c)
            nr ^= (((nr & 63) + add) * c_val) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            add += c_val
        nr &= 0x7FFFFFFF
        nr2 &= 0x7FFFFFFF
        return format(nr, "08x") + format(nr2, "08x")

    @classmethod
    def _mysql41_hash(cls, password):
        step1 = hashlib.sha1(password.encode()).digest()
        step2 = hashlib.sha1(step1).hexdigest().upper()
        return "*" + step2

    @classmethod
    def _postgres_md5_hash(cls, password, username=""):
        inner = hashlib.md5((password + username).encode()).hexdigest()
        return "md5" + inner

    @classmethod
    def _oracle10g_hash(cls, password):
        s = password.upper().encode("utf-8")
        return hashlib.sha1(s).hexdigest().lower()

    @classmethod
    def _oracle11g_hash(cls, password, salt_hex):
        s = password.upper().encode("utf-8")
        s += bytes.fromhex(salt_hex)
        h = hashlib.sha1(s).hexdigest().lower()
        return h.upper() + salt_hex.upper()

    @classmethod
    def _mssql2000_hash(cls, password):
        pw_up = password.upper().encode("utf-16le")
        return hashlib.sha1(pw_up).hexdigest()

    @classmethod
    def _mssql2005_hash(cls, password, salt_hex):
        pw_up = password.upper().encode("utf-16le")
        pw_up += bytes.fromhex(salt_hex)
        return hashlib.sha1(pw_up).hexdigest()

    @classmethod
    def _mssql2008_hash(cls, password, salt_hex):
        pw_up = password.upper().encode("utf-16le")
        h = hashlib.sha256(pw_up).hexdigest()
        if salt_hex:
            h += salt_hex
        return h

    @classmethod
    def _mssql2012_hash(cls, password, salt_hex):
        import hmac

        salt_bytes = bytes.fromhex(salt_hex) if salt_hex else b""
        h = (
            hmac.new(salt_bytes, password.upper().encode("utf-16le"), hashlib.sha512)
            .hexdigest()
            .upper()
        )
        return h

    @classmethod
    def _cisco7_decode(cls, encoded):
        try:
            key = [
                0x64,
                0x73,
                0x66,
                0x64,
                0x3B,
                0x6B,
                0x66,
                0x6F,
                0x41,
                0x2C,
                0x2E,
                0x69,
                0x79,
                0x65,
                0x77,
                0x72,
                0x6B,
                0x6C,
                0x64,
                0x4A,
                0x4B,
                0x44,
                0x48,
                0x53,
                0x55,
                0x42,
            ]
            if len(encoded) < 4:
                return encoded
            offset = int(encoded[:2])
            enc_data = encoded[2:]
            result = []
            for i, c in enumerate(enc_data):
                if i % 2 == 0:
                    byte_pair = enc_data[i : i + 2]
                    if len(byte_pair) < 2:
                        break
                    val = int(byte_pair, 16) ^ key[(offset + i // 2) % len(key)]
                    result.append(chr(val))
            return "".join(result)
        except (ValueError, IndexError):
            return encoded
