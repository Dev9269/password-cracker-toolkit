import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from cracker.hash_detector import HashDetector
from cracker.session import SessionManager
from cracker.reporting import write_report, append_to_report
from cracker.wordlist_utils import (
    merge_wordlists,
    dedupe_wordlist,
    apply_rules_to_wordlist,
    wordlist_stats,
)
from attacks.mask import MaskAttack, parse_mask, mask_candidates, mask_keyspace_size
from attacks.rule_engine import (
    parse_rule,
    apply_rule,
    load_rules,
    get_default_rules,
    ensure_default_rules_file,
)
from attacks.combinator import CombinatorAttack


class TestMaskAttack:
    def setup_method(self):
        self.mask = MaskAttack()
        self.detector = HashDetector()

    def test_parse_mask_simple(self):
        result = parse_mask("?l?l?l")
        assert len(result) == 3
        for cs in result:
            assert cs == "abcdefghijklmnopqrstuvwxyz"

    def test_parse_mask_mixed(self):
        result = parse_mask("?u?l?d")
        assert result[0] == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        assert result[1] == "abcdefghijklmnopqrstuvwxyz"
        assert all(c.isdigit() for c in result[2])

    def test_parse_mask_custom_charset(self):
        custom = {"?1": "abc", "?2": "123"}
        result = parse_mask("?1?2?1", custom)
        assert result[0] == "abc"
        assert result[1] == "123"
        assert result[2] == "abc"

    def test_mask_keyspace_size(self):
        size = mask_keyspace_size("?l?l")
        assert size == 26 * 26

    def test_mask_keyspace_size_custom(self):
        custom = {"?1": "abcd"}
        size = mask_keyspace_size("?1?d?1", custom)
        assert size == 4 * 10 * 4

    def test_mask_candidates_generator(self):
        gen = mask_candidates("?d?d")
        first = next(gen)
        assert first == "00"
        second = next(gen)
        assert second == "01"

    def test_mask_attack_cracks_correctly(self):
        detector = HashDetector()
        target = detector.hash_string("cat", "md5")
        count = [0]

        def inc(n=1):
            count[0] += n

        result = self.mask.attack(target, "md5", "?l?l?l", inc)
        assert result["success"] is True
        assert result["password"] == "cat"

    def test_mask_attack_fails_with_wrong_mask(self):
        detector = HashDetector()
        target = detector.hash_string("xyz", "md5")
        count = [0]

        def inc(n=1):
            count[0] += n

        result = self.mask.attack(target, "md5", "?d?d?d", inc)
        assert result["success"] is False


class TestRuleEngine:
    def test_parse_rule_toggle(self):
        cmds = parse_rule("T3")
        assert len(cmds) == 1
        assert cmds[0] == ("T", 3)

    def test_parse_rule_substitute(self):
        cmds = parse_rule("sa0")
        assert cmds[0] == ("s", ("a", "0"))

    def test_apply_rule_toggle(self):
        cmds = parse_rule("T0")
        result = apply_rule("hello", cmds)
        assert result == "Hello"

    def test_apply_rule_uppercase(self):
        cmds = parse_rule("u")
        result = apply_rule("hello", cmds)
        assert result == "HELLO"

    def test_apply_rule_lowercase(self):
        cmds = parse_rule("l")
        result = apply_rule("HELLO", cmds)
        assert result == "hello"

    def test_apply_rule_capitalize(self):
        cmds = parse_rule("c")
        result = apply_rule("hello", cmds)
        assert result == "Hello"

    def test_apply_rule_reverse(self):
        cmds = parse_rule("r")
        result = apply_rule("abc", cmds)
        assert result == "cba"

    def test_apply_rule_duplicate(self):
        cmds = parse_rule("d")
        result = apply_rule("abc", cmds)
        assert result == "abcabc"

    def test_apply_rule_reflect(self):
        cmds = parse_rule("f")
        result = apply_rule("abc", cmds)
        assert result == "abccba"

    def test_apply_rule_append_char(self):
        cmds = parse_rule("$X")
        result = apply_rule("hello", cmds)
        assert result == "helloX"

    def test_apply_rule_prepend_char(self):
        cmds = parse_rule("^X")
        result = apply_rule("hello", cmds)
        assert result == "Xhello"

    def test_apply_rule_substitute(self):
        cmds = parse_rule("sl0")
        result = apply_rule("hello", cmds)
        assert result == "he0lo"

    def test_apply_rule_multi_command(self):
        cmds = parse_rule("u $1")
        result = apply_rule("hello", cmds)
        assert result == "HELLO1"

    def test_get_default_rules(self):
        rules = get_default_rules()
        assert len(rules) > 0
        assert any("$" in r or "^" in r for r in rules)

    def test_ensure_default_rules_file(self):
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
        if os.path.exists(rules_dir):
            import shutil

            shutil.rmtree(rules_dir)
        ensure_default_rules_file()
        assert os.path.exists(os.path.join(rules_dir, "best64.rule"))
        with open(os.path.join(rules_dir, "best64.rule")) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) > 0


class TestCombinatorAttack:
    def setup_method(self):
        self.combinator = CombinatorAttack()
        self.detector = HashDetector()

    def test_combinator_cracks_correctly(self):
        target = self.detector.hash_string("adminpass", "md5")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f1:
            f1.write("admin\n")
            p1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f2:
            f2.write("pass\n")
            p2 = f2.name
        try:
            count = [0]

            def inc(n=1):
                count[0] += n

            result = self.combinator.attack(target, "md5", p1, p2, inc)
            assert result["success"] is True
            assert result["password"] == "adminpass"
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_combinator_fails_with_wrong_words(self):
        target = self.detector.hash_string("nope", "md5")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f1:
            f1.write("aaa\n")
            p1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f2:
            f2.write("bbb\n")
            p2 = f2.name
        try:
            count = [0]

            def inc(n=1):
                count[0] += n

            result = self.combinator.attack(target, "md5", p1, p2, inc)
            assert result["success"] is False
        finally:
            os.unlink(p1)
            os.unlink(p2)


class TestSession:
    def setup_method(self):
        self.session_dir = os.path.join(os.path.dirname(__file__), "..", "sessions")
        self.test_name = "_test_session_cleanup"

    def teardown_method(self):
        sm = SessionManager(self.test_name)
        sm.delete()
        if os.path.exists(self.session_dir):
            remaining = os.listdir(self.session_dir)
            if not remaining:
                os.rmdir(self.session_dir)

    def test_session_save_and_load(self):
        sm = SessionManager(self.test_name)
        sm.set("hash_type", "md5")
        sm.set("hash_target", "abc123")
        sm.set("mode", "dictionary")
        sm.set("attempts", 42)
        sm.save()

        sm2 = SessionManager(self.test_name)
        data = sm2.load()
        assert data is not None
        assert data["hash_type"] == "md5"
        assert data["hash_target"] == "abc123"
        assert data["mode"] == "dictionary"
        assert data["attempts"] == 42

    def test_session_delete(self):
        sm = SessionManager(self.test_name)
        sm.set("test", "value")
        sm.save()
        assert sm.load() is not None
        sm.delete()
        assert sm.load() is None

    def test_session_list(self):
        sm = SessionManager(self.test_name)
        sm.set("x", "y")
        sm.save()
        sessions = SessionManager.list_sessions()
        names = [s["name"] for s in sessions]
        assert self.test_name in names

    def test_session_not_found(self):
        sm = SessionManager("_nonexistent_session_xyz")
        assert sm.load() is None


class TestReporting:
    def test_write_report_json(self):
        results = [
            {
                "hash": "abc",
                "result": {
                    "success": True,
                    "password": "pass",
                    "hash_type": "md5",
                    "time_elapsed": 0.1,
                    "attempts": 10,
                    "attempts_per_second": 100,
                },
            },
            {
                "hash": "def",
                "result": {
                    "success": False,
                    "password": "",
                    "hash_type": "sha1",
                    "time_elapsed": 0.2,
                    "attempts": 5,
                    "attempts_per_second": 25,
                },
            },
        ]
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            path = f.name
        try:
            write_report(results, path, "json")
            with open(path) as f:
                data = json.load(f)
            assert len(data) == 2
            assert data[0]["hash"] == "abc"
        finally:
            os.unlink(path)

    def test_write_report_csv(self):
        results = [
            {
                "hash": "abc",
                "result": {
                    "success": True,
                    "password": "pass",
                    "hash_type": "md5",
                    "time_elapsed": 0.1,
                    "attempts": 10,
                    "attempts_per_second": 100,
                },
            },
        ]
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            path = f.name
        try:
            write_report(results, path, "csv")
            with open(path) as f:
                content = f.read()
            assert "abc" in content
            assert "pass" in content
        finally:
            os.unlink(path)

    def test_append_to_report(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            path = f.name
        try:
            append_to_report(
                {"hash": "abc", "result": {"success": True, "password": "pass"}}, path
            )
            append_to_report({"hash": "def", "result": {"success": False}}, path)
            with open(path) as f:
                data = json.load(f)
            assert len(data["results"]) == 2
        finally:
            os.unlink(path)


class TestWordlistUtils:
    def test_merge_wordlists(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f1:
            f1.write("apple\nbanana\n")
            p1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f2:
            f2.write("banana\ncherry\n")
            p2 = f2.name
        out = p1 + ".merged"
        try:
            count = merge_wordlists([p1, p2], out)
            assert count == 3
            with open(out) as f:
                words = {line.strip() for line in f if line.strip()}
            assert words == {"apple", "banana", "cherry"}
        finally:
            os.unlink(p1)
            os.unlink(p2)
            if os.path.exists(out):
                os.unlink(out)

    def test_dedupe_wordlist(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("a\nb\na\nc\nb\n")
            inp = f.name
        out = inp + ".deduped"
        try:
            count = dedupe_wordlist(inp, out)
            assert count == 3
            with open(out) as f:
                words = [line.strip() for line in f if line.strip()]
            assert words == ["a", "b", "c"]
        finally:
            os.unlink(inp)
            if os.path.exists(out):
                os.unlink(out)

    def test_apply_rules_to_wordlist(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f_wl:
            f_wl.write("hello\n")
            wl_path = f_wl.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".rule") as f_r:
            f_r.write("u\n$1\n")
            rule_path = f_r.name
        out = wl_path + ".mutated"
        try:
            count = apply_rules_to_wordlist(wl_path, rule_path, out)
            assert count == 2
            with open(out) as f:
                words = {line.strip() for line in f if line.strip()}
            assert "HELLO" in words
            assert "hello1" in words
        finally:
            os.unlink(wl_path)
            os.unlink(rule_path)
            if os.path.exists(out):
                os.unlink(out)

    def test_wordlist_stats(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("a\nab\nabc\n")
            path = f.name
        try:
            stats = wordlist_stats(path)
            assert stats["words"] == 3
            assert stats["min_len"] == 1
            assert stats["max_len"] == 3
            assert stats["avg_len"] == 2.0
        finally:
            os.unlink(path)


class TestCoreEngineNewModes:
    def test_mask_mode_via_engine(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        detector = HashDetector()
        target = detector.hash_string("dog", "md5")
        result = engine.crack_hash(target, mode="mask", mask="?l?l?l")
        assert result["success"] is True
        assert result["password"] == "dog"

    def test_combinator_mode_via_engine(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        detector = HashDetector()
        target = detector.hash_string("foobar", "md5")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f1:
            f1.write("foo\n")
            p1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f2:
            f2.write("bar\n")
            p2 = f2.name
        try:
            result = engine.crack_hash(
                target, mode="combinator", wordlist1=p1, wordlist2=p2
            )
            assert result["success"] is True
            assert result["password"] == "foobar"
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_rule_mode_with_default_rules(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        detector = HashDetector()
        target = detector.hash_string("HELLO1", "md5")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("hello\n")
            wl_path = f.name
        try:
            ensure_default_rules_file()
            rules_path = os.path.join(
                os.path.dirname(__file__), "..", "rules", "best64.rule"
            )
            result = engine.crack_hash(
                target, wordlist_path=wl_path, mode="rule", rules_file=rules_path
            )
            assert result["success"] is True
        finally:
            os.unlink(wl_path)

    def test_session_persistence(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        detector = HashDetector()
        target = detector.hash_string("testpass", "md5")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("testpass\n")
            wl_path = f.name
        try:
            result = engine.crack_hash(
                target,
                wordlist_path=wl_path,
                mode="dictionary",
                session_name="_test_session_crack",
            )
            assert result["success"] is True
            sm = SessionManager("_test_session_crack")
            data = sm.load()
            assert data is not None
            assert data["cracked"] is True
            assert data["password"] == "testpass"
            sm.delete()
        finally:
            os.unlink(wl_path)

    def test_batch_crack_from_file(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        detector = HashDetector()
        h1 = detector.hash_string("alpha", "md5")
        h2 = detector.hash_string("beta", "sha1")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f_h:
            f_h.write(h1 + "\n" + h2 + "\n")
            hash_path = f_h.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f_w:
            f_w.write("alpha\nbeta\n")
            wl_path = f_w.name
        try:
            results = engine.crack_hashes_from_file(
                hash_path, wordlist_path=wl_path, mode="dictionary"
            )
            assert results["total"] == 2
            assert results["cracked"] == 2
            assert results["failed"] == 0
        finally:
            os.unlink(hash_path)
            os.unlink(wl_path)

    def test_threads_default(self):
        from cracker.core_engine import CoreEngine

        engine = CoreEngine()
        assert engine.crack_hash("invalid", mode="brute", threads=1) is not None
