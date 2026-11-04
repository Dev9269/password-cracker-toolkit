#!/usr/bin/env python3
import argparse
import logging
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from cracker.core_engine import CoreEngine
from cracker.hash_detector import HashDetector
from cracker.session import SessionManager
from cracker.reporting import write_report
from cracker.wordlist_utils import (
    merge_wordlists,
    dedupe_wordlist,
    apply_rules_to_wordlist,
)
from attacks.rule_engine import ensure_default_rules_file
from utils.formatter import Formatter


ALGO_CHOICES = sorted(HashDetector.ALGO_META.keys())
ALGO_CHOICES_LOWER = [a.lower() for a in ALGO_CHOICES]


def create_sample_wordlist():
    wordlist_dir = "wordlists"
    if not os.path.exists(wordlist_dir):
        os.makedirs(wordlist_dir)
    wordlist_path = os.path.join(wordlist_dir, "sample.txt")
    if not os.path.exists(wordlist_path):
        sample_words = [
            "password",
            "123456",
            "admin",
            "letmein",
            "monkey",
            "dragon",
            "baseball",
            "iloveyou",
            "trustno1",
            "sunshine",
            "master",
            "hello",
            "freedom",
            "whatever",
            "qazwsx",
            "password123",
            "admin123",
            "user",
            "login",
            "welcome",
            "test",
            "demo",
            "guest",
            "root",
            "coffee",
        ]
        with open(wordlist_path, "w") as f:
            for word in sample_words:
                f.write(word + "\n")
        Formatter.print_info(f"Created sample wordlist at: {wordlist_path}")


VERSION = "2.1.0"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Advanced Password Cracking & Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Dictionary attack
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode dictionary

  # Mask attack
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode mask --mask '?u?l?l?l?d?d?d'

  # Combinator attack (two wordlists concatenated)
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode combinator --wordlist1 w1.txt --wordlist2 w2.txt

  # Rule-based attack with custom rules
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode rule --rules-file rules/best64.rule

  # Multi-threaded brute force
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode brute --threads 4

  # Session persistence
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode brute --session myattack

  # Resume a saved session
  python main.py --resume myattack

  # Batch mode with report
  python main.py --hash-file hashes.txt --mode dictionary --report results.json

  # Wordlist utilities
  python main.py --merge w1.txt w2.txt -o merged.txt
  python main.py --dedupe input.txt -o clean.txt
  python main.py --apply-rules-export input.txt rules.rule -o mutated.txt

  # List supported algorithms
  python main.py --list-aliases
        """,
    )

    parser.add_argument("--hash", type=str, help="The hash to crack")
    parser.add_argument("--wordlist", type=str, help="Path to wordlist file")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["auto", "dictionary", "brute", "hybrid", "rule", "mask", "combinator"],
        default="auto",
        help="Attack mode (default: auto)",
    )
    parser.add_argument(
        "--min-length", type=int, default=1, help="Minimum password length (default: 1)"
    )
    parser.add_argument(
        "--max-length", type=int, default=8, help="Maximum password length (default: 8)"
    )
    parser.add_argument(
        "--charset",
        type=str,
        choices=[
            "lowercase",
            "uppercase",
            "digits",
            "symbols",
            "lowerupper",
            "alnum",
            "all",
        ],
        default="all",
        help="Character set for brute force mode (default: all)",
    )
    parser.add_argument(
        "--algo",
        type=str,
        choices=ALGO_CHOICES_LOWER,
        help=f"Manually specify hash algorithm (choices: {', '.join(ALGO_CHOICES_LOWER)})",
    )
    parser.add_argument(
        "--gpu", action="store_true", help="Enable GPU acceleration via hashcat"
    )
    parser.add_argument(
        "--hash-file",
        type=str,
        help="Path to file containing hashes (one per line) for batch cracking",
    )
    parser.add_argument(
        "--output", type=str, help="Export results to file (.json or .csv)"
    )
    parser.add_argument(
        "--create-sample-wordlist", action="store_true", help="Create a sample wordlist"
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version information"
    )
    parser.add_argument("--salt", type=str, help="Salt value for salted hash modes")
    parser.add_argument(
        "--salt-position",
        type=str,
        choices=["prepend", "append", "hmac"],
        default="append",
        help="Salt position: prepend, append, or hmac (default: append)",
    )
    parser.add_argument(
        "--username",
        type=str,
        help="Username (required for PostgreSQL MD5 and some enterprise hashes)",
    )
    parser.add_argument(
        "--list-aliases", action="store_true", help="List all supported hash algorithms"
    )

    parser.add_argument(
        "--mask", type=str, help="Mask pattern for mask mode (e.g. ?u?l?l?l?d?d?d)"
    )
    parser.add_argument(
        "--custom-charset1", type=str, help="Custom charset for ?1 in mask mode"
    )
    parser.add_argument(
        "--custom-charset2", type=str, help="Custom charset for ?2 in mask mode"
    )
    parser.add_argument(
        "--wordlist1", type=str, help="First wordlist for combinator mode"
    )
    parser.add_argument(
        "--wordlist2", type=str, help="Second wordlist for combinator mode"
    )
    parser.add_argument(
        "--rules-file", type=str, help="Path to hashcat-format rule file"
    )
    parser.add_argument("--session", type=str, help="Session name for save/resume")
    parser.add_argument("--resume", type=str, help="Resume a saved session by name")
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of threads for parallel attacks (default: 1)",
    )
    parser.add_argument(
        "--report", type=str, help="Path to report output file (.json or .csv)"
    )

    parser.add_argument(
        "--merge",
        nargs=2,
        metavar=("FILE1", "FILE2"),
        help="Merge two wordlists (use with -o)",
    )
    parser.add_argument(
        "--dedupe",
        type=str,
        metavar="FILE",
        help="Deduplicate a wordlist (use with -o)",
    )
    parser.add_argument(
        "--apply-rules-export",
        nargs=2,
        metavar=("WORDLIST", "RULES"),
        help="Apply rules to a wordlist and export (use with -o)",
    )
    parser.add_argument(
        "-o", "--output-file", type=str, help="Output file for wordlist utilities"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    return parser


def handle_wordlist_utils(args):
    if args.merge:
        if not args.output_file:
            Formatter.print_error("--output-file (-o) required for --merge")
            sys.exit(1)
        merge_wordlists([args.merge[0], args.merge[1]], args.output_file)
        Formatter.print_success(f"Merged wordlists saved to {args.output_file}")
        return True

    if args.dedupe:
        if not args.output_file:
            Formatter.print_error("--output-file (-o) required for --dedupe")
            sys.exit(1)
        dedupe_wordlist(args.dedupe, args.output_file)
        Formatter.print_success(f"Deduplicated wordlist saved to {args.output_file}")
        return True

    if args.apply_rules_export:
        if not args.output_file:
            Formatter.print_error(
                "--output-file (-o) required for --apply-rules-export"
            )
            sys.exit(1)
        wordlist_path, rules_path = args.apply_rules_export
        apply_rules_to_wordlist(wordlist_path, rules_path, args.output_file)
        Formatter.print_success(f"Rule-applied wordlist saved to {args.output_file}")
        return True

    return False


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        Formatter.no_color = True

    if args.version:
        print(f"Password Cracking & Analysis Toolkit v{VERSION}")
        print("For educational and authorized security testing only.")
        print(f"Supports {len(ALGO_CHOICES)} hash algorithms.")
        return

    if args.list_aliases:
        print(f"Supported hash algorithms ({len(ALGO_CHOICES)} total):")
        print("=" * 70)
        categories = {}
        for k, v in HashDetector.ALGO_META.items():
            cat = v[5]
            categories.setdefault(cat, []).append((k, v[1], v[3], v[6]))
        for cat, items in sorted(categories.items()):
            print(f"\n  [{cat.upper()}]")
            for key, name, hc_mode, note in items:
                hc_str = f" (hashcat -m {hc_mode})" if hc_mode else ""
                note_str = f" — {note}" if note else ""
                print(f"    {key:22s}  {name}{hc_str}{note_str}")
        print()
        return

    if args.create_sample_wordlist:
        create_sample_wordlist()
        return

    if args.resume:
        session = SessionManager(args.resume)
        data = session.load()
        if not data:
            Formatter.print_error(f"Session not found: {args.resume}")
            sys.exit(1)
        Formatter.print_info(f"Resuming session: {args.resume}")
        engine = CoreEngine()
        engine.start_time = 0.0
        engine.attempts = data.get("attempts", 0)
        engine.session = session
        result = engine.crack_hash(
            hash_string=data.get("hash", ""),
            wordlist_path=data.get("wordlist"),
            mode=data.get("mode", "auto"),
            min_length=data.get("min_length", 1),
            max_length=data.get("max_length", 8),
            charset=data.get("charset", "all"),
            use_gpu=data.get("gpu", False),
            algo=data.get("hash_type"),
            salt=data.get("salt"),
            salt_position=data.get("salt_position", "append"),
            mask=data.get("mask"),
            wordlist1=data.get("wordlist1"),
            wordlist2=data.get("wordlist2"),
            rules_file=data.get("rules_file"),
            session_name=args.resume,
            threads=data.get("threads", 1),
            resume_offset=data.get("attempts", 0),
        )
        if result["success"]:
            Formatter.print_success(f"Resumed and cracked: {result['password']}")
        else:
            Formatter.print_info("Session resumed but password not yet found.")
        return

    if handle_wordlist_utils(args):
        return

    if args.hash_file:
        engine = CoreEngine()
        Formatter.print_info("=" * 60)
        Formatter.print_info("Password Cracking & Analysis Toolkit - Batch Mode")
        Formatter.print_info("For educational and authorized security testing only")
        Formatter.print_info("=" * 60)
        print()
        results = engine.crack_hashes_from_file(
            hash_file_path=args.hash_file,
            wordlist_path=args.wordlist,
            mode=args.mode,
            min_length=args.min_length,
            max_length=args.max_length,
            charset=args.charset,
            use_gpu=args.gpu,
            algo=args.algo,
            salt=args.salt,
            salt_position=args.salt_position,
            mask=args.mask,
            wordlist1=args.wordlist1,
            wordlist2=args.wordlist2,
            rules_file=args.rules_file,
            session_name=args.session,
            threads=args.threads,
            username=args.username,
        )
        if args.report:
            write_report(results.get("results", []), args.report)
        if args.output:
            output_format = "csv" if args.output.endswith(".csv") else "json"
            engine.export_results(results, args.output, format=output_format)
        return

    if args.hash is None:
        Formatter.print_error(
            "--hash is required unless --hash-file, --create-sample-wordlist, --list-aliases, --resume, or wordlist utilities are used"
        )
        sys.exit(1)

    dict_mode = args.mode in ("dictionary", "hybrid", "rule", "combinator", "mask")
    needs_wordlist = args.mode in ("dictionary", "hybrid", "rule")
    combinator_needs = args.mode == "combinator"
    mask_needs_wordlist = args.mode == "mask" and args.rules_file and not args.wordlist

    if needs_wordlist and not args.wordlist:
        Formatter.print_error(f"--wordlist is required for {args.mode} mode")
        sys.exit(1)

    if combinator_needs and (not args.wordlist1 or not args.wordlist2):
        Formatter.print_error(
            "--wordlist1 and --wordlist2 are required for combinator mode"
        )
        sys.exit(1)

    if args.mode == "mask" and not args.mask:
        Formatter.print_error(
            "--mask is required for mask mode (e.g. --mask '?u?l?l?l?d?d?d')"
        )
        sys.exit(1)

    if args.mode == "mask" and args.rules_file and not args.wordlist:
        Formatter.print_error(
            "--wordlist is required when using --rules-file with mask mode"
        )
        sys.exit(1)

    if args.wordlist and not os.path.exists(args.wordlist):
        Formatter.print_error(f"Wordlist file not found: {args.wordlist}")
        sys.exit(1)

    if args.wordlist1 and not os.path.exists(args.wordlist1):
        Formatter.print_error(f"Wordlist1 not found: {args.wordlist1}")
        sys.exit(1)

    if args.wordlist2 and not os.path.exists(args.wordlist2):
        Formatter.print_error(f"Wordlist2 not found: {args.wordlist2}")
        sys.exit(1)

    if args.rules_file and not os.path.exists(args.rules_file):
        Formatter.print_error(f"Rules file not found: {args.rules_file}")
        sys.exit(1)

    if args.mode == "rule" and not args.rules_file:
        ensure_default_rules_file()
        default_rules = os.path.join("rules", "best64.rule")
        if os.path.exists(default_rules):
            args.rules_file = default_rules
            Formatter.print_info(f"Using default rules: {default_rules}")

    engine = CoreEngine()

    Formatter.print_info("=" * 60)
    Formatter.print_info("Password Cracking & Analysis Toolkit")
    Formatter.print_info("For educational and authorized security testing only")
    Formatter.print_info("=" * 60)

    result = engine.crack_hash(
        hash_string=args.hash,
        wordlist_path=args.wordlist,
        mode=args.mode,
        min_length=args.min_length,
        max_length=args.max_length,
        charset=args.charset,
        use_gpu=args.gpu,
        algo=args.algo,
        salt=args.salt,
        salt_position=args.salt_position,
        mask=args.mask,
        wordlist1=args.wordlist1,
        wordlist2=args.wordlist2,
        rules_file=args.rules_file,
        session_name=args.session,
        threads=args.threads,
        custom_charset1=args.custom_charset1,
        custom_charset2=args.custom_charset2,
        username=args.username,
    )

    print()

    if result["success"]:
        Formatter.print_success("SUCCESS: Password cracked!")
        logging.getLogger(__name__).info(
            "Cracked - algo: %s, attempts: %s, elapsed: %.2fs, speed: %.2f/s",
            result["hash_type"],
            result["attempts"],
            result["time_elapsed"],
            result["attempts_per_second"],
        )
        print(
            f"Password: {Formatter.format_text(result['password'], 'green', bold=True)}"
        )

        if result["analysis"]:
            print()
            Formatter.print_info("Password Analysis:")
            strength_color = (
                "green"
                if result["analysis"]["strength"] == "Strong"
                else "yellow"
                if result["analysis"]["strength"] == "Medium"
                else "red"
            )
            print(
                f"Strength: {Formatter.format_text(result['analysis']['strength'], strength_color)}"
            )
            print(
                f"Score: {result['analysis']['score']}/{result['analysis']['max_score']}"
            )
            print(f"Length: {result['analysis']['length']} characters")
            chars = result["analysis"]["character_analysis"]
            char_str = []
            if chars["lowercase"]:
                char_str.append("lowercase")
            if chars["uppercase"]:
                char_str.append("uppercase")
            if chars["digits"]:
                char_str.append("digits")
            if chars["special"]:
                char_str.append("special chars")
            print(f"Character types: {', '.join(char_str) if char_str else 'none'}")
            if result["analysis"]["feedback"]:
                print()
                Formatter.print_info("Feedback:")
                for fb in result["analysis"]["feedback"]:
                    print(f"  {fb}")
            if result["analysis"]["suggestions"]:
                print()
                Formatter.print_info("Suggestions for improvement:")
                for s in result["analysis"]["suggestions"]:
                    print(f"  {Formatter.SYMBOLS['info']} {s}")
    else:
        Formatter.print_error("FAILED: Password not found")
        logging.getLogger(__name__).info(
            "Failed attempt - algo: %s, attempts: %s, elapsed: %.2fs",
            result.get("hash_type", "Unknown"),
            result.get("attempts", 0),
            result.get("time_elapsed", 0),
        )
        if "error" in result:
            logging.getLogger(__name__).error(result["error"])
            print("An error occurred during cracking. Check the log for details.")

    print()
    Formatter.print_info(
        "Remember: Use this tool only for authorized security testing!"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        Formatter.print_warning("Operation cancelled by user")
        sys.exit(0)
    except Exception:
        logging.getLogger(__name__).exception("Unexpected error")
        Formatter.print_error(
            "An unexpected error occurred. Check the log for details."
        )
        sys.exit(1)
