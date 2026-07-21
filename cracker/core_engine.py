import json
import os
import time
import math
import multiprocessing as mp
from functools import partial

from cracker.hash_detector import HashDetector
from attacks.dictionary import DictionaryAttack
from attacks.brute_force import BruteForceAttack
from attacks.hybrid import HybridAttack
from attacks.rule_based import RuleBasedAttack
from attacks.mask import MaskAttack, parse_mask, mask_keyspace_size
from attacks.combinator import CombinatorAttack
from attacks.rule_engine import (
    load_rules,
    generate_rule_pipeline,
    get_default_rules,
    ensure_default_rules_file,
)
from gpu.hashcat_wrapper import HashcatWrapper
from cracker.analyzer import PasswordAnalyzer
from cracker.logger import PasswordLogger
from cracker.session import SessionManager
from cracker.reporting import write_report


def _worker_brute_chunk(args):
    (
        hash_target,
        hash_type,
        chars,
        length,
        start_offset,
        chunk_size,
        salt,
        salt_position,
        extra,
    ) = args
    detector = HashDetector()
    import itertools

    count = 0
    for combo in itertools.product(chars, repeat=length):
        if count < start_offset:
            count += 1
            continue
        if count >= start_offset + chunk_size:
            break
        password = "".join(combo)
        count += 1
        if salt is not None:
            hashed = detector.hash_string(
                password, hash_type, salt=salt, salt_position=salt_position, **extra
            )
        else:
            hashed = detector.hash_string(password, hash_type)
        if hashed == hash_target:
            return {
                "success": True,
                "password": password,
                "attempts": count - start_offset,
            }
    return {"success": False, "attempts": chunk_size}


def _worker_mask_chunk(args):
    (
        hash_target,
        hash_type,
        mask_str,
        start_offset,
        chunk_size,
        salt,
        salt_position,
        custom_cs,
        extra,
    ) = args
    detector = HashDetector()
    charsets = parse_mask(mask_str, custom_cs)
    import itertools

    count = 0
    produced = 0
    for combo in itertools.product(*charsets):
        if count < start_offset:
            count += 1
            continue
        password = "".join(combo)
        count += 1
        produced += 1
        if salt is not None:
            hashed = detector.hash_string(
                password, hash_type, salt=salt, salt_position=salt_position, **extra
            )
        else:
            hashed = detector.hash_string(password, hash_type)
        if hashed == hash_target:
            return {"success": True, "password": password, "attempts": produced}
        if produced >= chunk_size:
            break
    return {"success": False, "attempts": produced}


class CoreEngine:
    def __init__(self):
        self.hash_detector = HashDetector()
        self.dictionary_attack = DictionaryAttack()
        self.brute_force_attack = BruteForceAttack()
        self.hybrid_attack = HybridAttack()
        self.rule_based_attack = RuleBasedAttack()
        self.mask_attack = MaskAttack()
        self.combinator_attack = CombinatorAttack()
        self.hashcat_wrapper = HashcatWrapper()
        self.analyzer = PasswordAnalyzer()
        self.logger = PasswordLogger()
        self.session = None
        self.start_time = 0.0
        self.attempts = 0
        self.found = False
        self.cracked_password = None

    def crack_hash(
        self,
        hash_string,
        wordlist_path=None,
        mode="auto",
        min_length=1,
        max_length=8,
        charset=None,
        use_gpu=False,
        algo=None,
        salt=None,
        salt_position="append",
        mask=None,
        wordlist1=None,
        wordlist2=None,
        rules_file=None,
        session_name=None,
        threads=1,
        custom_charset1=None,
        custom_charset2=None,
        **kwargs,
    ):
        raw_hash = hash_string
        salt = salt or kwargs.get("salt")

        parsed = self._parse_combined_hash(raw_hash, algo)
        if parsed:
            raw_hash = parsed["hash"]
            if parsed.get("salt") and salt is None:
                salt = parsed["salt"]
            if parsed.get("algo") and algo is None:
                algo = parsed["algo"]

        if algo:
            algo_lower = algo.lower().replace("-", "_")
            meta = self.hash_detector.ALGO_META.get(algo_lower)
            if not meta:
                return {
                    "success": False,
                    "error": f"Invalid algorithm override: {algo}",
                }
            hash_type = algo_lower
        else:
            result = self.hash_detector.detect_hash_type(raw_hash)
            if not result:
                return {"success": False, "error": "Invalid or unsupported hash format"}
            hash_type = result.get("algo")
            if result.get("salt") and salt is None:
                salt = result["salt"]

        if hash_type is None:
            candidates = self.hash_detector.detect_hash_type(raw_hash)
            if candidates and candidates.get("candidates"):
                names = [
                    f"{c['name']} ({c['algo']})" for c in candidates["candidates"][:5]
                ]
                return {
                    "success": False,
                    "error": f"Ambiguous hash. Use --algo to specify one of: {', '.join(names)}",
                }
            return {"success": False, "error": "Unable to determine hash type"}

        if min_length < 1 or max_length < min_length:
            return {"success": False, "error": "Invalid min/max length parameters"}
        self.start_time = time.time()
        self.attempts = 0
        self.found = False
        self.cracked_password = None

        display_hash = raw_hash[:32] + "..." if len(raw_hash) > 32 else raw_hash
        self.logger.log_attempt_start(display_hash, hash_type, mode, use_gpu)

        meta = self.hash_detector.ALGO_META.get(
            hash_type, (None, None, None, None, True)
        )
        is_slow_kdf = meta[4] or hash_type in (
            "bcrypt",
            "scrypt",
            "argon2i",
            "argon2d",
            "argon2id",
            "pbkdf2_sha1",
            "pbkdf2_sha256",
            "pbkdf2_sha512",
            "phpass",
            "django_pbkdf2",
            "drupal7",
            "macos_pbkdf2",
            "yescrypt",
        )

        if session_name:
            self.session = SessionManager(session_name)
            self.session.set("hash_type", hash_type)
            self.session.set("hash_target", raw_hash)
            self.session.set("mode", mode)
            self.session.set("threads", threads)
            self.session.save()

        if use_gpu:
            result = self._run_gpu(
                raw_hash,
                hash_type,
                mode,
                wordlist_path,
                mask,
                min_length,
                max_length,
                charset,
                rules_file,
                salt,
            )
            result["used_gpu"] = True
            self.attempts = result.get("attempts", 0)
            if result["success"]:
                self.found = True
                self.cracked_password = result["password"]
            elapsed_time = time.time() - self.start_time
            attempts_per_second = (
                self.attempts / elapsed_time if elapsed_time > 0 else 0
            )
            self.logger.log_result(
                self.found, self.cracked_password, elapsed_time, self.attempts
            )
            analysis = (
                self.analyzer.analyze_password(self.cracked_password)
                if self.found
                else None
            )
            result.update(
                {
                    "hash_type": hash_type,
                    "time_elapsed": elapsed_time,
                    "attempts_per_second": attempts_per_second,
                    "analysis": analysis,
                }
            )
            if self.session and self.found:
                self.session.set("cracked", True)
                self.session.set("password", self.cracked_password)
                self.session.save()
            return result

        if is_slow_kdf:
            return self._crack_slow_kdf(
                raw_hash,
                hash_type,
                wordlist_path,
                mode,
                min_length,
                max_length,
                charset,
                salt,
                salt_position,
                **kwargs,
            )

        custom_cs = {}
        if custom_charset1:
            custom_cs["?1"] = custom_charset1
        if custom_charset2:
            custom_cs["?2"] = custom_charset2

        attack_kwargs = {
            "salt": salt,
            "salt_position": salt_position,
            "custom_charsets": custom_cs,
        }
        attack_kwargs.update(kwargs)

        if mode == "auto":
            for attack_mode in ["dictionary", "hybrid", "brute"]:
                result = self._run_attack(
                    attack_mode,
                    raw_hash,
                    hash_type,
                    wordlist_path,
                    min_length,
                    max_length,
                    charset,
                    attack_kwargs,
                    None,
                    1,
                )
                if result["success"]:
                    self.found = True
                    self.cracked_password = result["password"]
                    break
        elif mode == "mask":
            result = self._run_mask(
                raw_hash,
                hash_type,
                mask,
                attack_kwargs,
                threads,
                rules_file,
                wordlist_path,
            )
            if result["success"]:
                self.found = True
                self.cracked_password = result["password"]
        elif mode == "combinator":
            result = self._run_combinator(
                raw_hash, hash_type, wordlist1, wordlist2, attack_kwargs
            )
            if result["success"]:
                self.found = True
                self.cracked_password = result["password"]
        else:
            result = self._run_attack(
                mode,
                raw_hash,
                hash_type,
                wordlist_path,
                min_length,
                max_length,
                charset,
                attack_kwargs,
                rules_file,
                threads,
            )
            if result["success"]:
                self.found = True
                self.cracked_password = result["password"]

        elapsed_time = time.time() - self.start_time
        attempts_per_second = self.attempts / elapsed_time if elapsed_time > 0 else 0
        self.logger.log_result(
            self.found, self.cracked_password, elapsed_time, self.attempts
        )
        analysis = (
            self.analyzer.analyze_password(self.cracked_password)
            if self.found
            else None
        )

        final = {
            "success": self.found,
            "password": self.cracked_password,
            "hash_type": hash_type,
            "attempts": self.attempts,
            "time_elapsed": elapsed_time,
            "attempts_per_second": attempts_per_second,
            "analysis": analysis,
        }
        if self.session:
            self.session.set("cracked", self.found)
            if self.found:
                self.session.set("password", self.cracked_password)
            self.session.set("attempts", self.attempts)
            self.session.save()
        return final

    def _parse_combined_hash(self, hash_string, algo_override=None):
        if not hash_string:
            return None
        crypt_parsed = self.hash_detector.parse_crypt_hash(hash_string)
        if crypt_parsed:
            return {
                "hash": hash_string,
                "salt": crypt_parsed.get("salt"),
                "algo": crypt_parsed.get("algo"),
            }
        if ":" in hash_string and not hash_string.startswith("krb5"):
            parts = hash_string.split(":")
            if len(parts) == 2:
                import re

                h, s = parts
                if re.match(r"^[a-fA-F0-9]+$", h):
                    return {"hash": h, "salt": s, "algo": None}
                if re.match(r"^[a-fA-F0-9]+$", s):
                    return {"hash": s, "salt": h, "algo": None}
        return None

    def _run_gpu(
        self,
        hash_string,
        hash_type,
        mode,
        wordlist_path,
        mask,
        min_length,
        max_length,
        charset,
        rules_file,
        salt,
    ):
        rules_arg = rules_file
        return self.hashcat_wrapper.crack_hash(
            hash_string,
            hash_type,
            wordlist_path=wordlist_path,
            mode=mode,
            min_length=min_length,
            max_length=max_length,
            charset=charset,
            salt=salt,
            mask=mask,
            rules_file=rules_arg,
        )

    def _run_mask(
        self,
        hash_string,
        hash_type,
        mask,
        extra_kwargs,
        threads,
        rules_file=None,
        wordlist_path=None,
    ):
        from utils.formatter import Formatter

        if not mask:
            return {
                "success": False,
                "error": "Mask pattern required for mask mode (e.g. ?u?l?l?l?d?d)",
            }
        if rules_file and wordlist_path:
            return self._run_mask_with_rules(
                hash_string, hash_type, mask, extra_kwargs, rules_file, wordlist_path
            )
        total_size = mask_keyspace_size(mask, extra_kwargs.get("custom_charsets"))
        Formatter.print_info(f"Mask keyspace: {total_size:,} candidates")
        if threads > 1 and total_size > 100000:
            return self._run_parallel_mask(
                hash_string, hash_type, mask, extra_kwargs, threads, total_size
            )
        return self.mask_attack.attack(
            hash_string, hash_type, mask, self._increment_attempts, **extra_kwargs
        )

    def _run_mask_with_rules(
        self, hash_string, hash_type, mask, extra_kwargs, rules_file, wordlist_path
    ):
        from utils.formatter import Formatter
        import re as _re

        rules = load_rules(rules_file)
        Formatter.print_info(f"Loaded {len(rules)} rules from {rules_file}")
        if not os.path.exists(wordlist_path):
            return {"success": False, "error": f"Wordlist not found: {wordlist_path}"}

        charsets = parse_mask(mask, extra_kwargs.get("custom_charsets"))
        from attacks.mask import mask_candidates

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            base_words = [line.strip() for line in f if line.strip()]
        if base_words:
            Formatter.print_info(
                f"Hybrid mask+rule: {len(base_words)} base words x {len(rules)} rules"
            )
        for base in base_words:
            for rule_str in rules:
                from attacks.rule_engine import parse_rule, apply_rule

                commands = parse_rule(rule_str)
                candidate = apply_rule(base, commands)
                if not candidate:
                    continue
                self._increment_attempts(1)
                if extra_kwargs.get("salt") is not None:
                    hashed = self.hash_detector.hash_string(
                        candidate,
                        hash_type,
                        salt=extra_kwargs["salt"],
                        salt_position=extra_kwargs.get("salt_position", "append"),
                        **extra_kwargs,
                    )
                else:
                    hashed = self.hash_detector.hash_string(candidate, hash_type)
                if hashed == hash_string:
                    return {"success": True, "password": candidate, "attempts": 0}
        return {"success": False, "error": "Mask+rule exhausted"}

    def _run_parallel_mask(
        self, hash_string, hash_type, mask_str, extra_kwargs, threads, total_size
    ):
        from utils.formatter import Formatter

        chunk_size = math.ceil(total_size / threads)
        charsets = parse_mask(mask_str, extra_kwargs.get("custom_charsets"))
        Formatter.print_info(
            f"Spawning {threads} workers, ~{chunk_size:,} candidates each"
        )

        worker_args = []
        for i in range(threads):
            start = i * chunk_size
            sz = min(chunk_size, total_size - start)
            if sz <= 0:
                break
            worker_args.append(
                (
                    hash_string,
                    hash_type,
                    mask_str,
                    start,
                    sz,
                    extra_kwargs.get("salt"),
                    extra_kwargs.get("salt_position"),
                    extra_kwargs.get("custom_charsets"),
                    {},
                )
            )

        with mp.Pool(threads) as pool:
            results = pool.map(_worker_mask_chunk, worker_args)

        total_attempts = 0
        for r in results:
            total_attempts += r.get("attempts", 0)
            self._increment_attempts(r.get("attempts", 0))
            if r.get("success"):
                return {
                    "success": True,
                    "password": r["password"],
                    "attempts": total_attempts,
                }
        return {"success": False, "attempts": total_attempts}

    def _run_combinator(
        self, hash_string, hash_type, wordlist1, wordlist2, extra_kwargs
    ):
        if not wordlist1 or not wordlist2:
            return {
                "success": False,
                "error": "--wordlist1 and --wordlist2 required for combinator mode",
            }
        return self.combinator_attack.attack(
            hash_string,
            hash_type,
            wordlist1,
            wordlist2,
            self._increment_attempts,
            **extra_kwargs,
        )

    def _crack_slow_kdf(
        self,
        hash_string,
        hash_type,
        wordlist_path,
        mode,
        min_length,
        max_length,
        charset,
        salt,
        salt_position,
        **kwargs,
    ):
        from utils.formatter import Formatter

        Formatter.print_info(
            f"Using slow-KDF verifier for {self.hash_detector.get_hash_name(hash_type)}"
        )
        if mode in ("dictionary", "hybrid", "rule", "auto") and wordlist_path:
            if not os.path.exists(wordlist_path):
                return {
                    "success": False,
                    "error": f"Wordlist not found: {wordlist_path}",
                }
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
            for word in words:
                self.attempts += 1
                valid, info = self.hash_detector.verify_hash(
                    word,
                    hash_string,
                    hash_type,
                    salt=salt,
                    salt_position=salt_position,
                    **kwargs,
                )
                if valid:
                    elapsed_time = time.time() - self.start_time
                    self.found = True
                    self.cracked_password = word
                    return {
                        "success": True,
                        "password": word,
                        "hash_type": hash_type,
                        "attempts": self.attempts,
                        "time_elapsed": elapsed_time,
                        "attempts_per_second": self.attempts / elapsed_time
                        if elapsed_time > 0
                        else 0,
                        "analysis": self.analyzer.analyze_password(word),
                    }
                if self.attempts >= 1000:
                    avg_speed = (
                        self.attempts / (time.time() - self.start_time)
                        if (time.time() - self.start_time) > 0
                        else 0
                    )
                    Formatter.print_info(
                        f"  Slow-KDF progress: {self.attempts} attempts, ~{avg_speed:.1f}/s"
                    )
                    self.attempts = 0
                    self.start_time = time.time()
        elapsed_time = time.time() - self.start_time
        return {
            "success": False,
            "password": None,
            "hash_type": hash_type,
            "attempts": self.attempts,
            "time_elapsed": elapsed_time,
            "attempts_per_second": self.attempts / elapsed_time
            if elapsed_time > 0
            else 0,
            "analysis": None,
        }

    def _run_attack(
        self,
        mode,
        hash_string,
        hash_type,
        wordlist_path,
        min_length,
        max_length,
        charset,
        extra_kwargs=None,
        rules_file=None,
        threads=1,
    ):
        extra_kwargs = extra_kwargs or {}
        if mode == "dictionary":
            return self.dictionary_attack.attack(
                hash_string,
                hash_type,
                wordlist_path,
                self._increment_attempts,
                **extra_kwargs,
            )
        elif mode == "brute":
            if threads and threads > 1:
                from utils.formatter import Formatter

                if charset and charset in self.brute_force_attack.CHARSETS:
                    chars = self.brute_force_attack.CHARSETS[charset]
                elif charset:
                    chars = charset
                else:
                    chars = (
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    )
                total_size = sum(
                    len(chars) ** l for l in range(min_length, max_length + 1)
                )
                Formatter.print_info(
                    f"Brute-force keyspace: ~{total_size:,} candidates, {threads} threads"
                )
                return self._run_parallel_brute(
                    hash_string,
                    hash_type,
                    chars,
                    min_length,
                    max_length,
                    extra_kwargs,
                    threads,
                )
            return self.brute_force_attack.attack(
                hash_string,
                hash_type,
                min_length,
                max_length,
                charset,
                self._increment_attempts,
                **extra_kwargs,
            )
        elif mode == "hybrid":
            return self.hybrid_attack.attack(
                hash_string,
                hash_type,
                wordlist_path,
                self._increment_attempts,
                **extra_kwargs,
            )
        elif mode == "rule":
            if rules_file:
                return self._run_rule_with_file(
                    hash_string, hash_type, wordlist_path, rules_file, extra_kwargs
                )
            return self.rule_based_attack.attack(
                hash_string,
                hash_type,
                wordlist_path,
                self._increment_attempts,
                **extra_kwargs,
            )
        else:
            return {"success": False, "error": f"Unknown attack mode: {mode}"}

    def _run_rule_with_file(
        self, hash_string, hash_type, wordlist_path, rules_file, extra_kwargs
    ):
        from utils.formatter import Formatter

        rules = load_rules(rules_file)
        Formatter.print_info(f"Loaded {len(rules)} rules from {rules_file}")
        if not os.path.exists(wordlist_path):
            return {"success": False, "error": f"Wordlist not found: {wordlist_path}"}
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        for word in words:
            for variant in generate_rule_pipeline(word, rules):
                if not variant:
                    continue
                self._increment_attempts(1)
                salt = extra_kwargs.get("salt")
                if salt is not None:
                    hashed = self.hash_detector.hash_string(
                        variant,
                        hash_type,
                        salt=salt,
                        salt_position=extra_kwargs.get("salt_position", "append"),
                        **extra_kwargs,
                    )
                else:
                    hashed = self.hash_detector.hash_string(variant, hash_type)
                if hashed == hash_string:
                    return {"success": True, "password": variant, "attempts": 0}
        return {
            "success": False,
            "error": "Password not found with rule-based transformations",
        }

    def _run_parallel_brute(
        self,
        hash_string,
        hash_type,
        chars,
        min_length,
        max_length,
        extra_kwargs,
        threads,
    ):
        from utils.formatter import Formatter

        total_attempts = 0
        for length in range(min_length, max_length + 1):
            total_for_len = len(chars) ** length
            chunk_size = math.ceil(total_for_len / threads)
            worker_args = []
            for i in range(threads):
                start = i * chunk_size
                sz = min(chunk_size, total_for_len - start)
                if sz <= 0:
                    break
                worker_args.append(
                    (
                        hash_string,
                        hash_type,
                        chars,
                        length,
                        start,
                        sz,
                        extra_kwargs.get("salt"),
                        extra_kwargs.get("salt_position"),
                        {},
                    )
                )
            with mp.Pool(threads) as pool:
                results = pool.map(_worker_brute_chunk, worker_args)
            for r in results:
                total_attempts += r.get("attempts", 0)
                self._increment_attempts(r.get("attempts", 0))
                if r.get("success"):
                    return {
                        "success": True,
                        "password": r["password"],
                        "attempts": total_attempts,
                    }
        return {"success": False, "attempts": total_attempts}

    def crack_hashes_from_file(
        self,
        hash_file_path,
        wordlist_path=None,
        mode="auto",
        min_length=1,
        max_length=8,
        charset=None,
        use_gpu=False,
        algo=None,
        salt=None,
        salt_position="append",
        mask=None,
        wordlist1=None,
        wordlist2=None,
        rules_file=None,
        session_name=None,
        threads=1,
        **kwargs,
    ):
        if not os.path.exists(hash_file_path):
            return {"success": False, "error": f"Hash file not found: {hash_file_path}"}
        results = []
        total_start = time.time()
        cracked_count = 0
        failed_count = 0
        with open(hash_file_path, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
        total = len(hashes)
        from utils.formatter import Formatter

        Formatter.print_info(f"Loaded {total} hashes from {hash_file_path}")
        for i, hs in enumerate(hashes, 1):
            Formatter.print_info(f"[{i}/{total}] Attempting: {hs}")
            result = self.crack_hash(
                hash_string=hs,
                wordlist_path=wordlist_path,
                mode=mode,
                min_length=min_length,
                max_length=max_length,
                charset=charset,
                use_gpu=use_gpu,
                algo=algo,
                salt=salt,
                salt_position=salt_position,
                mask=mask,
                wordlist1=wordlist1,
                wordlist2=wordlist2,
                rules_file=rules_file,
                session_name=session_name,
                threads=threads,
                **kwargs,
            )
            results.append({"hash": hs, "result": result})
            if result["success"]:
                cracked_count += 1
                Formatter.print_success(f"  -> Cracked: {result['password']}")
            else:
                failed_count += 1
                Formatter.print_error(
                    f"  -> Failed: {result.get('error', 'Not found')}"
                )
            print()
        total_elapsed = time.time() - total_start
        Formatter.print_info("=" * 50)
        Formatter.print_info("BATCH CRACK SUMMARY")
        Formatter.print_info("=" * 50)
        Formatter.print_success(
            f"Total: {total} | Cracked: {cracked_count} | Failed: {failed_count}"
        )
        Formatter.print_info(f"Time: {total_elapsed:.2f}s")
        print()
        return {
            "success": cracked_count > 0,
            "total": total,
            "cracked": cracked_count,
            "failed": failed_count,
            "time_elapsed": total_elapsed,
            "results": results,
        }

    def export_results(self, results, output_path, format="json"):
        from utils.formatter import Formatter

        if format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            Formatter.print_success(f"Results exported to {output_path}")
        elif format == "csv":
            import csv

            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Hash", "Status", "Password", "Hash Type", "Time (s)", "Attempts"]
                )
                for entry in results.get("results", []):
                    r = entry["result"]
                    writer.writerow(
                        [
                            entry["hash"],
                            "Cracked" if r["success"] else "Failed",
                            r.get("password", ""),
                            r.get("hash_type", ""),
                            f"{r.get('time_elapsed', 0):.2f}",
                            r.get("attempts", 0),
                        ]
                    )
            Formatter.print_success(f"Results exported to {output_path}")
        else:
            Formatter.print_error(f"Unsupported export format: {format}")

    def _increment_attempts(self, count=1):
        self.attempts += count
