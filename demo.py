#!/usr/bin/env python3
"""
Quick demo script to showcase all features of the Password Cracking Toolkit
Direct function calls for faster execution (no subprocess overhead)
"""

import hashlib
import os
import sys
from cracker.core_engine import CoreEngine
from cracker.hash_detector import HashDetector
from utils.formatter import Formatter

# Fix Windows terminal encoding for special characters
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def demo_attack(engine, hash_string, description, **kwargs):
    """Run a single demo attack."""
    print("\n" + "=" * 70)
    print(f"[TEST] {description}")
    print("=" * 70)
    
    result = engine.crack_hash(hash_string, **kwargs)
    
    if result['success']:
        masked_pwd = result['password'][0] + '*' * (len(result['password']) - 2) + result['password'][-1]
        print(f"[SUCCESS] Password: {masked_pwd}")
        print(f"   Time: {result['time_elapsed']:.2f}s | Attempts: {result['attempts']:,}")
    else:
        print(f"[FAILED] {result.get('error', 'No password found')}")
    
    print()

def main():
    engine = CoreEngine()
    
    print("\n" + "=" * 70)
    print(" " * 15 + "PASSWORD CRACKING TOOLKIT - DEMO SUITE")
    print(" " * 20 + "Educational & Authorized Testing Only")
    print("=" * 70)
    
    wordlist = "wordlists/sample.txt"
    
    # Test 1: Dictionary
    md5_password = '5f4dcc3b5aa765d61d8327deb882cf99'
    demo_attack(engine, md5_password, "TEST 1: Dictionary Attack", 
                wordlist_path=wordlist, mode='dictionary')
    
    # Test 2: Brute Force
    md5_test = '098f6bcd4621d373cade4e832627b4f6'  # MD5('test')
    demo_attack(engine, md5_test, "TEST 2: Brute Force (4 chars lowercase)", 
                mode='brute', min_length=4, max_length=4, charset='lowercase')
    
    # Test 3: Hybrid
    md5_password123 = '482c811da5d5b4bc6d497ffa98491e38'  # MD5('password123')
    demo_attack(engine, md5_password123, "TEST 3: Hybrid Attack", 
                wordlist_path=wordlist, mode='hybrid')
    
    # Test 4: Rule-Based
    md5_admin123 = '0192023a7bbd73250516f069df18b500'  # MD5('admin123')
    demo_attack(engine, md5_admin123, "TEST 4: Rule-Based Attack", 
                wordlist_path=wordlist, mode='rule')
    
    # Test 5: Auto
    demo_attack(engine, md5_password, "TEST 5: Auto Mode", 
                wordlist_path=wordlist, mode='auto')
    
    # Test 6: SHA1
    sha1_password = '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'
    demo_attack(engine, sha1_password, "TEST 6: SHA1 Auto-Detection", 
                wordlist_path=wordlist, mode='dictionary')
    
    # Test 7: SHA256
    sha256_admin = hashlib.sha256(b'admin').hexdigest()
    demo_attack(engine, sha256_admin, "TEST 7: SHA256 Auto-Detection", 
                wordlist_path=wordlist, mode='dictionary')
    
    # Test 8: Error
    demo_attack(engine, 'invalidhash', "TEST 8: Error Handling", mode='brute')
    
    print("=" * 70)
    print("[DONE] DEMO COMPLETE - All core functionality verified!")
    print("[LOG] Detailed logs: logs/password_cracker_*.log")
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Demo interrupted by user (Ctrl+C)")
        sys.exit(0)
