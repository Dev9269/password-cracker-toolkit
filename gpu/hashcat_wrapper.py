import subprocess
import os
import tempfile

from cracker.hash_detector import HashDetector


HASHCAT_MODES = {
    "md4": 900,
    "md5": 0,
    "sha1": 100,
    "sha224": 1300,
    "sha256": 1400,
    "sha384": 10800,
    "sha512": 1700,
    "sha3_224": 17400,
    "sha3_256": 17500,
    "sha3_384": 17600,
    "sha3_512": 17700,
    "ripemd160": 6000,
    "whirlpool": 6100,
    "tiger": 12500,
    "crc32": 11500,
    "double_md5": 2600,
    "md5_md5_salt": 3810,
    "hmac_md5": 50,
    "hmac_sha1": 150,
    "hmac_sha256": 1450,
    "bcrypt": 3200,
    "scrypt": 8900,
    "argon2i": 9200,
    "argon2d": 9300,
    "argon2id": 9400,
    "pbkdf2_sha1": 12001,
    "pbkdf2_sha256": 10900,
    "pbkdf2_sha512": 12100,
    "descrypt": 1500,
    "md5_crypt": 500,
    "sha256_crypt": 7400,
    "sha512_crypt": 1800,
    "yescrypt": 25600,
    "lm": 3000,
    "ntlm": 1000,
    "ntlmv2": 5600,
    "mysql323": 200,
    "mysql41": 300,
    "mssql2000": 131,
    "mssql2005": 132,
    "mssql2008": 1731,
    "mssql2012": 1731,
    "oracle10g": 3100,
    "oracle11g": 112,
    "postgres_md5": 110,
    "phpass": 400,
    "django_pbkdf2": 10000,
    "drupal7": 8100,
    "ldap_ssha": 111,
    "ldap_sha": 101,
    "ldap_md5": 1,
    "ldap_crypt": 1500,
    "krb5asrep": 18200,
    "krb5tgs": 13100,
    "cisco5": 5700,
    "macos_pbkdf2": 7100,
}

HC_MASK_ATTACK_MAP = {
    0: "dictionary",
    3: "brute",
    6: "hybrid",
    7: "hybrid",
}


class HashcatWrapper:
    def __init__(self):
        self.hash_detector = HashDetector()
        self.hashcat_path = self._find_hashcat()

    def _find_hashcat(self):
        hashcat_names = [
            "hashcat",
            "hashcat.bin",
            "hashcat64.bin",
            "hashcat64.exe",
            "hashcat32.exe",
        ]
        for name in hashcat_names:
            cmd = ["where", name] if os.name == "nt" else ["which", name]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, shell=False
                )
                if result.returncode == 0:
                    return result.stdout.strip().split("\n")[0]
            except (FileNotFoundError, OSError):
                pass
        return None

    def is_available(self):
        return self.hashcat_path is not None

    def _build_cmd(
        self,
        hashcat_mode,
        hash_file_path,
        output_file_path,
        mode,
        wordlist_path=None,
        min_length=1,
        max_length=8,
        charset=None,
        mask=None,
        rules_file=None,
        username=False,
    ):
        cmd = [self.hashcat_path, "-m", str(hashcat_mode), hash_file_path]

        if username:
            cmd.append("--username")

        if mode == "mask":
            hc_charset = (
                self._convert_charset_to_hashcat(charset) if charset else "?l?u?d?s"
            )
            cmd[1:1] = ["-a", "3"]
            if mask:
                cmd.extend(["-1", hc_charset, mask])
            else:
                cmd.extend(
                    [
                        "-1",
                        hc_charset,
                        "--increment",
                        "--increment-min",
                        str(min_length),
                        "--increment-max",
                        str(max_length),
                        "?" * max_length,
                    ]
                )

        elif mode == "brute" or (mode == "auto" and not wordlist_path and not mask):
            hc_charset = (
                self._convert_charset_to_hashcat(charset) if charset else "?l?u?d?s"
            )
            cmd[1:1] = ["-a", "3"]
            cmd.extend(
                [
                    "-1",
                    hc_charset,
                    "--increment",
                    "--increment-min",
                    str(min_length),
                    "--increment-max",
                    str(max_length),
                    "?" * max_length,
                ]
            )

        elif mode == "dictionary":
            if not wordlist_path:
                return {
                    "success": False,
                    "error": "Wordlist path required for dictionary attack",
                }
            cmd.extend(["-a", "0", wordlist_path])

        elif mode == "hybrid":
            if not wordlist_path:
                return {
                    "success": False,
                    "error": "Wordlist path required for hybrid attack",
                }
            hc_charset = (
                self._convert_charset_to_hashcat(charset) if charset else "?l?u?d?s"
            )
            cmd.extend(["-a", "6", wordlist_path, "-1", hc_charset, "?1" * max_length])

        elif mode == "rule":
            if not wordlist_path:
                return {
                    "success": False,
                    "error": "Wordlist path required for rule attack",
                }
            cmd.extend(["-a", "0", wordlist_path])

        elif mode == "combinator":
            return {
                "success": False,
                "error": "Hashcat combinator mode (-a 1) requires two wordlists; use --wordlist1 and --wordlist2",
            }

        else:
            if not wordlist_path:
                return {
                    "success": False,
                    "error": f"Unknown mode '{mode}' or missing wordlist",
                }

        if rules_file:
            cmd.extend(["--rules-file", rules_file])

        cmd.extend(["--outfile", output_file_path, "--outfile-format", "2"])
        return cmd

    def _parse_output_file(self, output_file_path, hash_string, stdout, stderr):
        if not os.path.exists(output_file_path):
            return {"success": False, "error": "Hashcat did not recover the password"}
        with open(output_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        recovered_hash, password = parts
                        if recovered_hash == hash_string:
                            attempts = self._parse_attempts_from_output(
                                stdout + "\n" + stderr
                            )
                            return {
                                "success": True,
                                "password": password,
                                "attempts": attempts,
                            }
        return {"success": False, "error": "Hashcat did not recover the password"}

    def _cleanup(self, *paths):
        for path in paths:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except (FileNotFoundError, OSError):
                pass

    def crack_hash(
        self,
        hash_string,
        hash_type,
        wordlist_path=None,
        mode="auto",
        min_length=1,
        max_length=8,
        charset=None,
        salt=None,
        mask=None,
        rules_file=None,
        wordlist1=None,
        wordlist2=None,
        username=False,
    ):
        if not self.is_available():
            return {
                "success": False,
                "error": "Hashcat not found. Please install hashcat and ensure it is in your PATH.",
            }

        if mode == "combinator" and wordlist1 and wordlist2:
            return self._run_combinator(hash_string, hash_type, wordlist1, wordlist2)

        hashcat_mode = HASHCAT_MODES.get(hash_type)
        if hashcat_mode is None:
            return {
                "success": False,
                "error": f"No hashcat mode mapping for: {hash_type}",
            }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as hash_file:
            if salt and ":" not in hash_string:
                hash_file.write(f"{hash_string}:{salt}")
            else:
                hash_file.write(hash_string)
            hash_file_path = hash_file.name
        output_file_path = hash_file_path + ".out"

        try:
            cmd = self._build_cmd(
                hashcat_mode,
                hash_file_path,
                output_file_path,
                mode,
                wordlist_path=wordlist_path,
                min_length=min_length,
                max_length=max_length,
                charset=charset,
                mask=mask,
                rules_file=rules_file,
                username=username,
            )
            if isinstance(cmd, dict):
                return cmd
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            return self._parse_output_file(
                output_file_path, hash_string, result.stdout, result.stderr
            )
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Hashcat timed out after 1 hour"}
        except (OSError, ValueError) as e:
            return {"success": False, "error": f"Error running hashcat: {str(e)}"}
        finally:
            self._cleanup(hash_file_path, output_file_path)

    def _run_combinator(self, hash_string, hash_type, wordlist1, wordlist2):
        hashcat_mode = HASHCAT_MODES.get(hash_type)
        if hashcat_mode is None:
            return {
                "success": False,
                "error": f"No hashcat mode mapping for: {hash_type}",
            }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as hash_file:
            hash_file.write(hash_string)
            hash_file_path = hash_file.name
        output_file_path = hash_file_path + ".out"

        try:
            cmd = [
                self.hashcat_path,
                "-m",
                str(hashcat_mode),
                hash_file_path,
                "-a",
                "1",
                wordlist1,
                wordlist2,
            ]
            cmd.extend(["--outfile", output_file_path, "--outfile-format", "2"])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            return self._parse_output_file(
                output_file_path, hash_string, result.stdout, result.stderr
            )
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Hashcat timed out after 1 hour"}
        except (OSError, ValueError) as e:
            return {"success": False, "error": f"Error running hashcat: {str(e)}"}
        finally:
            self._cleanup(hash_file_path, output_file_path)

    def _convert_charset_to_hashcat(self, charset):
        has_lower = any(c.islower() for c in charset)
        has_upper = any(c.isupper() for c in charset)
        has_digit = any(c.isdigit() for c in charset)
        has_special = any(not c.isalnum() for c in charset)
        hc_charset = ""
        if has_lower:
            hc_charset += "?l"
        if has_upper:
            hc_charset += "?u"
        if has_digit:
            hc_charset += "?d"
        if has_special:
            hc_charset += "?s"
        if not hc_charset:
            hc_charset = "?l?u?d?s"
        return hc_charset

    def _parse_attempts_from_output(self, text):
        import re

        attempts = 0
        for line in text.splitlines():
            if "Restored" in line and "(" in line:
                m = re.search(r"(\d+)/", line)
                if m:
                    attempts = max(attempts, int(m.group(1)))
            m = re.search(
                r"(?i)(?:Recovered|Progress|Candidates|Excavated|Guesses|Attempts)[:\s]*(\d+)",
                line,
            )
            if m:
                try:
                    attempts = max(attempts, int(m.group(1)))
                except ValueError:
                    pass
        return attempts
