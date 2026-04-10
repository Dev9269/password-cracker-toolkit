#!/usr/bin/env python3
"""
Password Cracking & Analysis Toolkit
A comprehensive tool for educational and authorized security testing purposes.

WARNING: This tool is intended for educational and authorized security testing only.
Unauthorized use is strictly prohibited and may violate laws and regulations.
"""

import argparse
import logging
import sys
import os

# Fix Windows terminal encoding (supports Windows, ChromeOS, Kali Linux)
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from cracker.core_engine import CoreEngine
from utils.formatter import Formatter

def create_sample_wordlist():
    """Create a sample wordlist for demonstration purposes."""
    wordlist_dir = "wordlists"
    if not os.path.exists(wordlist_dir):
        os.makedirs(wordlist_dir)
    
    wordlist_path = os.path.join(wordlist_dir, "sample.txt")
    if not os.path.exists(wordlist_path):
        sample_words = [
            "password", "123456", "admin", "letmein", "monkey",
            "dragon", "baseball", "iloveyou", "trustno1", "sunshine",
            "master", "hello", "freedom", "whatever", "qazwsx",
            "password123", "admin123", "user", "login", "welcome"
        ]
        
        with open(wordlist_path, 'w') as f:
            for word in sample_words:
                f.write(word + '\n')
        
        Formatter.print_info(f"Created sample wordlist at: {wordlist_path}")

def main():
    """Main entry point for the password cracker toolkit."""
    parser = argparse.ArgumentParser(
        description="Advanced Password Cracking & Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dictionary attack with wordlist
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode dictionary
  
  # Brute force attack with length constraints
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode brute --min-length 4 --max-length 6
  
  # Hybrid attack
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode hybrid
  
  # Rule-based attack
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode rule
  
  # Automatic mode (tries dictionary, hybrid, then brute force)
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode auto
  
  # GPU-accelerated cracking (requires hashcat)
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode dictionary --gpu
        """
    )
    
    parser.add_argument(
        '--hash',
        type=str,
        required=False,
        help='The hash to crack (MD5, SHA1, or SHA256)'
    )
    
    parser.add_argument(
        '--wordlist',
        type=str,
        help='Path to wordlist file (required for dictionary, hybrid, and rule modes)'
    )
    
    parser.add_argument(
        '--mode',
        type=str,
        choices=['auto', 'dictionary', 'brute', 'hybrid', 'rule'],
        default='auto',
        help='Attack mode to use (default: auto)'
    )
    
    parser.add_argument(
        '--min-length',
        type=int,
        default=1,
        help='Minimum password length for brute force mode (default: 1)'
    )
    
    parser.add_argument(
        '--max-length',
        type=int,
        default=8,
        help='Maximum password length for brute force mode (default: 8)'
    )
    
    parser.add_argument(
        '--charset',
        type=str,
        choices=['lowercase', 'uppercase', 'digits', 'symbols', 'lowerupper', 'alnum', 'all'],
        default='all',
        help='Character set for brute force mode (default: all)'
    )
    
    parser.add_argument(
        '--algo',
        type=str,
        choices=['md5', 'sha1', 'sha256'],
        help='Manually specify hash algorithm (optional override)'
    )
    
    parser.add_argument(
        '--gpu',
        action='store_true',
        help='Enable GPU acceleration via hashcat (requires hashcat installation)'
    )
    
    parser.add_argument(
        '--create-sample-wordlist',
        action='store_true',
        help='Create a sample wordlist for demonstration purposes'
    )
    
    args = parser.parse_args()
    
    # Create sample wordlist if requested
    if args.create_sample_wordlist:
        create_sample_wordlist()
        return
    
    # Validate arguments
    if args.hash is None:
        Formatter.print_error("--hash is required unless --create-sample-wordlist is used")
        sys.exit(1)

    if args.mode in ['dictionary', 'hybrid', 'rule'] and not args.wordlist:
        Formatter.print_error(f"--wordlist is required for {args.mode} mode")
        sys.exit(1)
    
    if args.wordlist and not os.path.exists(args.wordlist):
        Formatter.print_error(f"Wordlist file not found: {args.wordlist}")
        sys.exit(1)
    
    # Initialize the core engine
    engine = CoreEngine()
    
    # Display banner
    Formatter.print_info("=" * 60)
    Formatter.print_info("Password Cracking & Analysis Toolkit")
    Formatter.print_info("For educational and authorized security testing only")
    Formatter.print_info("=" * 60)
    
    # Perform the cracking attempt
    result = engine.crack_hash(
        hash_string=args.hash,
        wordlist_path=args.wordlist,
        mode=args.mode,
        min_length=args.min_length,
        max_length=args.max_length,
        charset=args.charset,
        use_gpu=args.gpu,
        algo=args.algo
    )
    
    # Display results
    print()  # Empty line for readability
    
    if result['success']:
        Formatter.print_success("SUCCESS: Password cracked!")
        logging.getLogger(__name__).info(
            "Cracked - algo: %s, attempts: %s, elapsed: %.2fs, speed: %.2f/s",
            result['hash_type'],
            result['attempts'],
            result['time_elapsed'],
            result['attempts_per_second']
        )
        print(f"Password: {Formatter.format_text(result['password'], 'green', bold=True)}")
        
        # Display password analysis
        if result['analysis']:
            print()  # Empty line
            Formatter.print_info("Password Analysis:")
            print(f"Strength: {Formatter.format_text(result['analysis']['strength'], 
                                          'green' if result['analysis']['strength'] == 'Strong' else 
                                                   'yellow' if result['analysis']['strength'] == 'Medium' else 'red')}")
            print(f"Score: {result['analysis']['score']}/{result['analysis']['max_score']}")
            print(f"Length: {result['analysis']['length']} characters")
            
            # Character analysis
            chars = result['analysis']['character_analysis']
            char_str = []
            if chars['lowercase']: char_str.append("lowercase")
            if chars['uppercase']: char_str.append("uppercase")
            if chars['digits']: char_str.append("digits")
            if chars['special']: char_str.append("special chars")
            print(f"Character types: {', '.join(char_str) if char_str else 'none'}")
            
            # Feedback
            if result['analysis']['feedback']:
                print()  # Empty line
                Formatter.print_info("Feedback:")
                for feedback in result['analysis']['feedback']:
                    print(f"  {feedback}")
            
            # Suggestions
            if result['analysis']['suggestions']:
                print()  # Empty line
                Formatter.print_info("Suggestions for improvement:")
                for suggestion in result['analysis']['suggestions']:
                    print(f"  {Formatter.SYMBOLS['info']} {suggestion}")
    else:
        Formatter.print_error("FAILED: Password not found")
        logging.getLogger(__name__).info(
            "Failed attempt - algo: %s, attempts: %s, elapsed: %.2fs",
            result.get('hash_type', 'Unknown'),
            result.get('attempts', 0),
            result.get('time_elapsed', 0)
        )
        if 'error' in result:
            logging.getLogger(__name__).error(result['error'])
            print("An error occurred during cracking. Check the log for details.")
    
    print()  # Empty line
    Formatter.print_info("Remember: Use this tool only for authorized security testing!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()  # Empty line
        Formatter.print_warning("Operation cancelled by user")
        sys.exit(0)
    except Exception:
        logging.getLogger(__name__).exception("Unexpected error")
        Formatter.print_error("An unexpected error occurred. Check the log for details.")
        sys.exit(1)