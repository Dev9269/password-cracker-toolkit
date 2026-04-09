# 🔐 Password Toolkit — Advanced Hash Cracking & Analysis Engine

> A powerful, modular password security toolkit built in Python — designed for ethical security research, penetration testing, and educational purposes.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Fully%20Operational-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-28%20Passed-success?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

---

## 📖 About

Password Toolkit is a feature-rich command-line tool that combines multiple attack strategies to analyze and crack password hashes. Whether you're a security researcher, CTF player, or ethical hacker, this toolkit gives you the power to test password strength and understand real-world attack vectors.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **Auto Hash Detection** | Automatically identifies MD5, SHA1, SHA256 and more |
| 📖 **Dictionary Attack** | Leverage custom wordlists for fast lookups |
| 💪 **Brute Force Attack** | Exhaustive search with configurable length and charset |
| 🔀 **Hybrid Attack** | Combines dictionary + mutation for smarter cracking |
| 📏 **Rule-Based Attack** | Apply transformation rules (leet speak, capitalization) to wordlist entries |
| ⚡ **GPU Acceleration** | Hashcat integration for blazing-fast cracking |
| 🔍 **Password Analyzer** | Evaluates strength and patterns of cracked passwords |
| 📋 **Detailed Logging** | Tracks every attempt with timestamps and stats |

---

## 📁 Project Structure

```text
password-toolkit/
│
├── cracker/
│   ├── core_engine.py          # Main cracking orchestrator
│   ├── hash_detector.py        # Hash type identification
│   ├── analyzer.py             # Password strength analysis
│   └── logger.py               # Logging system
│
├── attacks/
│   ├── dictionary.py           # Dictionary-based attacks
│   ├── brute_force.py          # Brute force combination generation
│   ├── hybrid.py               # Wordlist + pattern attacks
│   └── rule_based.py           # Transformation-based attacks
│
├── gpu/
│   └── hashcat_wrapper.py      # Hashcat GPU integration
│
├── utils/
│   ├── timer.py                # Timing utilities
│   └── formatter.py            # Colored terminal output
│
├── wordlists/
│   └── sample.txt              # Example wordlist
│
├── tests/                      # Unit & integration tests
├── logs/                       # Auto-generated log files
├── main.py                     # CLI entry point
├── demo.py                     # Full demo runner
└── requirements.txt
```

---

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- [Hashcat](https://hashcat.net/hashcat/) *(optional, for GPU acceleration)*

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Dev9269/password-cracker-toolkit.git
cd password-toolkit

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Generate a sample wordlist
python main.py --create-sample-wordlist
```

---

## 💻 Usage

### Auto Mode *(Recommended)*
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode auto
```

### Dictionary Attack
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode dictionary
```

### Brute Force Attack
```bash
python main.py --hash <hash> --mode brute --min-length 4 --max-length 6 --charset lowercase
```

### Hybrid Attack
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode hybrid
```

### Rule-Based Attack
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode rule
```

### GPU-Accelerated Cracking
```bash
python main.py --hash <hash> --mode dictionary --gpu
```

### Manual Algorithm Override
```bash
python main.py --hash <hash> --algo sha256 --mode dictionary
```

---

## 📊 Attack Mode Comparison

| Mode | Speed | Best For | Avg Attempts |
|------|-------|----------|--------------|
| **Dictionary** | ⚡⚡⚡⚡⚡ Fastest | Common words | 1 – 100 |
| **Hybrid** | ⚡⚡⚡⚡ Very Fast | Word + number patterns | 100 – 1K |
| **Rule-Based** | ⚡⚡⚡ Fast | Transformations | 1K – 100K |
| **Brute Force** | ⚡⚡ Moderate | Unknown passwords | 100K – 1M+ |

---

## 🔤 Charset Options *(for Brute Force)*

```bash
--charset lowercase      # abcdefghijklmnopqrstuvwxyz
--charset uppercase      # ABCDEFGHIJKLMNOPQRSTUVWXYZ
--charset digits         # 0123456789
--charset symbols        # !@#$%^&*()_+-=[]{}|;:,.<>?
--charset lowerupper     # Mixed case letters
--charset alnum          # Letters + numbers
--charset all            # Everything combined (default, slowest)
```

---

## 📈 Performance Benchmarks

```
Attack Type          Attempts      Time       Speed
─────────────────────────────────────────────────────
Dictionary (hit)            1      0.00s      596/s
Hybrid (hit)              124      0.00s      86K/s
Rule-Based (hit)          27K      0.03s     1.0M/s
Brute Force 4-char       337K      0.27s     1.2M/s
```

---

## 📊 Sample Output

```
============================================================
  Password Cracking & Analysis Toolkit
  For educational and authorized security testing only
============================================================

✅ SUCCESS: Password cracked!
   Algorithm  : MD5
   Password   : <cracked_value>
   Attempts   : 1,245
   Time       : 0.23 seconds
   Speed      : 5,413 attempts/sec

🔍 Password Analysis:
   Strength   : Medium (55/100)
   Length     : 11 characters
   Char Types : lowercase, digits

💡 Suggestions:
   → Add uppercase letters
   → Add special characters (!@#$%^&*)
   → Avoid common words and patterns
```

---

## 🛠️ CLI Arguments Reference

```
--hash                  Hash string to crack (required)
--wordlist              Path to wordlist file
--mode                  auto | dictionary | brute | hybrid | rule
--min-length            Minimum password length (brute force)
--max-length            Maximum password length (brute force)
--charset               Character set for brute force
--algo                  Manual override: md5 | sha1 | sha256
--gpu                   Enable GPU acceleration via hashcat
--create-sample-wordlist  Generate a sample wordlist file
```

---

## ✅ Test Results

```
✅ 20 Unit Tests         (100% pass rate)
✅ 8  Integration Tests  (100% pass rate)
✅ 4  Attack Modes       (All functional)
✅ 3  Hash Algorithms    (MD5, SHA1, SHA256)
✅ ~90% Code Coverage
✅ Full Error Handling
```

Run tests yourself:
```bash
python -m unittest discover -s tests -v
python demo.py
```

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Commit your changes: `git commit -m 'Add YourFeature'`
4. Push to the branch: `git push origin feature/YourFeature`
5. Open a Pull Request

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

> This tool is intended strictly for **ethical use** — authorized penetration testing, security research, and educational purposes only.
> Unauthorized use against systems you do not own is **illegal**.
> The developers assume **no liability** for misuse of this toolkit.

---

## 🙏 Acknowledgments

- Inspired by real-world password security research
- Built with Python's powerful standard library
- Hashcat developers for GPU-accelerated cracking technology
- The open-source security community

---

<p align="center">
  <b>🏆 Status: FULLY OPERATIONAL — Ready for GitHub Portfolio!</b><br/>
  <i>With great power comes great responsibility. Use ethically. 🔐</i>
</p>
