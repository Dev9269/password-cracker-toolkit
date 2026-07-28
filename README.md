<div align="center">

# 🔐 Password Cracker Toolkit

[![Stars](https://img.shields.io/github/stars/Dev9269/password-cracker-toolkit?style=flat-square&logo=github&color=gold)](https://github.com/Dev9269/password-cracker-toolkit)
[![Forks](https://img.shields.io/github/forks/Dev9269/password-cracker-toolkit?style=flat-square&logo=github&color=blue)](https://github.com/Dev9269/password-cracker-toolkit/forks)
[![Last Commit](https://img.shields.io/github/last-commit/Dev9269/password-cracker-toolkit?style=flat-square&color=blueviolet)](https://github.com/Dev9269/password-cracker-toolkit/commits/main)
[![License](https://img.shields.io/github/license/Dev9269/password-cracker-toolkit?style=flat-square&color=brightgreen)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square)](https://github.com/Dev9269/password-cracker-toolkit/pulls)

A modular, multi-algorithm password hash auditing toolkit for ethical security research, penetration testing, CTFs, and educational purposes.

**Created by** [Jainam Maru](https://github.com/Dev9269)

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Mode Comparison](#-attack-mode-comparison)
- [CLI Arguments Reference](#-cli-arguments-reference)
- [Docker Deployment](#-docker-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📖 About

Password Cracker Toolkit is a feature-rich command-line tool that combines dictionary, brute-force, hybrid, rule-based, and GPU-accelerated attack strategies to audit password hashes. It supports **50+ hash algorithms** across generic digests, slow KDFs, Unix/Linux crypt(3) formats, Windows hashes, database-specific hashes, web framework hashes, and enterprise directory hashes.

---

## ✨ Features

| Feature | Description |
|---|---|---|
| 🧠 **Auto Hash Detection** | Multi-candidate scoring (prefix signatures + length heuristics + confidence ranking) |
| 🧂 **Salting Support** | `--salt` flag with `prepend` / `append` / `hmac` modes; auto-extracts salt from `hash:salt`, `$id$salt$hash`, and `{SSHA}` formats |
| 🔑 **50+ Hash Algorithms** | All algorithms listed below — generic, iterated, slow KDFs, Unix crypt, Windows, database, web framework, enterprise |
| 📖 **Dictionary Attack** | Wordlist-based lookup with salt support |
| 💪 **Brute Force Attack** | Exhaustive search with configurable length, charset, and salt |
| 🔀 **Hybrid Attack** | Wordlist + numeric/year/symbol mutations |
| 📏 **Rule-Based Attack** | Leet speak, capitalization, prefix/suffix transformations |
| 🎭 **Mask Attack** | Hashcat-compatible `?l?u?d?s?a?b` masks with custom `?1..?9` charsets |
| 🔗 **Combinator Attack** | Concatenates every word from two wordlists |
| 📐 **Rule Engine** | Hashcat `.rule` parser + best64 default rules; apply single or pipelined rules |
| 💾 **Session Persistence** | `--session` save/resume with JSON checkpoint files in `sessions/` |
| 🧵 **Multiprocessing** | `--threads` for parallel brute-force and mask attacks |
| ⚡ **GPU Acceleration** | Hashcat integration (mode mapping for 40+ hash types) |
| 🔍 **Password Analyzer** | Strength scoring (0–100), character analysis, improvement suggestions |
| 📋 **Logging & Export** | Structured logging + JSON/CSV batch export + per-session reports |
| 🔍 **Slow-KDF Verifier** | Uses passlib/bcrypt/argon2-cffi for bcrypt, Argon2, scrypt, PBKDF2, phpass, and others |
| 📝 **Wordlist Utilities** | `--merge`, `--dedupe`, `--apply-rules-export` for wordlist management |

---

## 📁 Project Structure

```text
password-toolkit/
│
├── cracker/
│   ├── core_engine.py          # Orchestrator (salt, slow-KDF, sessions, multiprocessing)
│   ├── hash_detector.py        # Multi-candidate hash identification (50+ types)
│   ├── analyzer.py             # Password strength analysis
│   ├── logger.py               # Logging system
│   ├── session.py              # Session save/resume with JSON checkpoints
│   ├── reporting.py            # JSON/CSV report output
│   └── wordlist_utils.py       # Merge, dedupe, apply-rules-to-wordlist
│
├── attacks/
│   ├── dictionary.py           # Dictionary-based attacks (salt-aware)
│   ├── brute_force.py          # Brute force combination generation (salt-aware)
│   ├── hybrid.py               # Wordlist + pattern attacks (salt-aware)
│   ├── rule_based.py           # Transformation-based attacks (salt-aware)
│   ├── mask.py                 # Hashcat-compatible mask attack
│   ├── rule_engine.py          # Hashcat .rule parser + best64 default rules
│   └── combinator.py           # Two-wordlist concatenation attack
│
├── gpu/
│   └── hashcat_wrapper.py      # Hashcat integration (40+ mode mappings, mask/rule passthrough)
│
├── utils/
│   ├── timer.py                # Timing utilities
│   └── formatter.py            # Colored terminal output
│
├── wordlists/
│   └── sample.txt              # Example wordlist
│
├── rules/
│   └── best64.rule             # Default rule file (auto-generated)
│
├── sessions/                   # Session checkpoint files
│
├── tests/                      # 120+ unit & integration tests
├── logs/                       # Auto-generated log files
├── main.py                     # CLI entry point (v2.1.0)
├── demo.py                     # Full demo runner
└── requirements.txt            # Dependencies
```

---

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)
- Git (for cloning)
- [Hashcat](https://hashcat.net/hashcat/) *(optional, for GPU acceleration)*

### Setup
```bash
git clone https://github.com/Dev9269/password-cracker-toolkit.git
cd password-toolkit

# (Recommended) Create and activate a virtual environment
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate

pip install -r requirements.txt
python main.py --create-sample-wordlist
```

---

## 💻 Usage

### Dictionary Attack
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode dictionary
```

### Dictionary Attack with Salt
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --salt "mysalt" --salt-position append
```

### Salt-Prepend Mode
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --salt "mysalt" --salt-position prepend
```

### HMAC-SHA256 Mode (salt as key)
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --salt "mykey" --salt-position hmac --algo hmac_sha256
```

### Combined Hash:Salt Format (auto-extracts salt)
```bash
python main.py --hash "5f4dcc3b5aa765d61d8327deb882cf99:salt123" --wordlist wordlists/sample.txt --mode dictionary
```

### Unix Crypt-Style Hash (auto-detects algorithm + salt)
```bash
python main.py --hash '$6$salt$hashvalue' --wordlist wordlists/sample.txt
```

### Brute Force Attack
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode brute --min-length 4 --max-length 6 --charset lowercase
```

### Manual Algorithm Override
```bash
python main.py --hash <hash> --algo ntlm --mode dictionary --wordlist wordlists/sample.txt
```

### Auto Mode (tries dictionary → hybrid → brute force)
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode auto
```

### Mask Attack (hashcat-compatible masks)
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode mask --mask '?u?l?l?l?d?d?d'
```
Mask placeholders: `?l` (lower), `?u` (upper), `?d` (digit), `?s` (special), `?a` (all), `?b` (byte).
Custom charsets via `--custom-charset1` / `--custom-charset2` (maps to `?1` / `?2`).

### Combinator Attack (two wordlists)
```bash
python main.py --hash <hash> --mode combinator --wordlist1 words.txt --wordlist2 suffixes.txt
```

### Rule-Based Attack with Custom Rules
```bash
python main.py --hash <hash> --wordlist wordlists/sample.txt --mode rule --rules-file rules/best64.rule
```

### Multi-Threaded Brute Force
```bash
python main.py --hash <hash> --mode brute --threads 4 --min-length 4 --max-length 6
```

### Session Persistence
```bash
python main.py --hash <hash> --mode brute --session myattack
python main.py --resume myattack
```

### Wordlist Utilities
```bash
python main.py --merge w1.txt w2.txt -o merged.txt
python main.py --dedupe input.txt -o clean.txt
python main.py --apply-rules-export input.txt rules/my.rule -o mutated.txt
```

### GPU-Accelerated Cracking
```bash
python main.py --hash <hash> --mode dictionary --gpu
```

### List All Supported Algorithms
```bash
python main.py --list-aliases
```

---

## 📊 Attack Mode Comparison

| Mode | Speed | Best For | Avg Attempts |
|------|-------|----------|--------------|
| **Dictionary** | ⚡⚡⚡⚡⚡ Fastest | Common/pwned passwords | 1 – 100 |
| **Hybrid** | ⚡⚡⚡⚡ Very Fast | Word + number/year patterns | 100 – 1K |
| **Rule-Based** | ⚡⚡⚡ Fast | Leet/capitalization transformations | 1K – 100K |
| **Mask** | ⚡⚡⚡ Fast | Pattern-based (KnownChar1+KnownChar2...) | 1K – 10M |
| **Combinator** | ⚡⚡⚡ Fast | Compound passwords (word+word) | 1K – 1M |
| **Brute Force** | ⚡⚡ Moderate | Short unknown passwords | 100K – 1M+ |

---

## 🔤 Charset Options (Brute Force)

```
--charset lowercase      abcdefghijklmnopqrstuvwxyz
--charset uppercase      ABCDEFGHIJKLMNOPQRSTUVWXYZ
--charset digits         0123456789
--charset symbols        !@#$%^&*()_+-=[]{}|;:,.<>?
--charset lowerupper     Mixed case letters
--charset alnum          Letters + numbers
--charset all            Everything combined (default, slowest)
```

---

## 🛠️ CLI Arguments Reference

```
--hash                    Hash string to crack (also accepts hash:salt, $id$salt$hash, {SSHA}...)
--wordlist                Path to wordlist file
--mode                    auto | dictionary | brute | hybrid | rule | mask | combinator
--min-length              Minimum password length (brute force)
--max-length              Maximum password length (brute force)
--charset                 Character set for brute force
--algo                    Manual algorithm override (50+ choices, see --list-aliases)
--salt                    Salt value for salted hash modes
--salt-position           prepend | append | hmac (default: append)
--gpu                     Enable GPU acceleration via hashcat
--username                Username (required for Postgres MD5 and some enterprise hashes)
--hash-file               Path to file containing hashes (one per line) for batch cracking
--output                  Export results to file (.json or .csv)

--mask                    Mask pattern (e.g. ?u?l?l?l?d?d?d)
--custom-charset1         Custom charset for ?1 in mask mode
--custom-charset2         Custom charset for ?2 in mask mode
--wordlist1               First wordlist for combinator mode
--wordlist2               Second wordlist for combinator mode
--rules-file              Path to hashcat-format rule file
--session                 Session name for save/resume
--resume                  Resume a saved session by name
--threads                 Number of threads for parallel attacks (default: 1)
--report                  Path to report output file (.json or .csv)

--merge FILE1 FILE2       Merge two wordlists (use with -o)
--dedupe FILE             Deduplicate a wordlist (use with -o)
--apply-rules-export WL RULES  Apply rules to wordlist and export (use with -o)
-o, --output-file         Output file for wordlist utilities

--create-sample-wordlist  Generate a sample wordlist file
--list-aliases            List all 50+ supported hash algorithms and exit
--version                 Show version information and exit
```

---

## 🔐 Algorithm Reference

### Generic Digests (hashlib, unsalted or manually salted)

| Algorithm | Hex Length | Hashcat Mode | Crack Speed | Notes |
|-----------|-----------|-------------|-------------|-------|
| MD4 | 32 | 900 | ⚡ Extremely Fast | Broken, unsalted |
| MD5 | 32 | 0 | ⚡ Extremely Fast | Widely used, vulnerable to collision |
| SHA1 | 40 | 100 | ⚡ Extremely Fast | Deprecated for crypto |
| SHA224 | 56 | 1300 | ⚡ Fast | |
| SHA256 | 64 | 1400 | ⚡ Fast | Default for modern systems |
| SHA384 | 96 | 10800 | ⚡ Fast | |
| SHA512 | 128 | 1700 | ⚡ Fast | |
| SHA3-224 | 56 | 17400 | ⚡ Fast | |
| SHA3-256 | 64 | 17500 | ⚡ Fast | |
| SHA3-384 | 96 | 17600 | ⚡ Fast | |
| SHA3-512 | 128 | 17700 | ⚡ Fast | |
| BLAKE2b | 128 | — | ⚡ Fast | 512-bit output |
| BLAKE2s | 64 | — | ⚡ Fast | 256-bit output |
| RIPEMD-160 | 40 | 6000 | ⚡ Fast | |
| Whirlpool | 128 | 6100 | ⚡ Fast | |
| Tiger | 48 | 12500 | ⚡ Fast | 192-bit |
| CRC32 | 8 | 11500 | ⚡ Fastest | **Not a password hash** — checksum only |

### Iterated / Composite

| Algorithm | Hex Length | Hashcat Mode | Crack Speed | Notes |
|-----------|-----------|-------------|-------------|-------|
| Double MD5 | 32 | 2600 | ⚡ Fast | md5(md5(x)) |
| MD5(MD5+salt) | 32 | 3810 | ⚡ Fast | md5(md5(pw).salt) |
| HMAC-MD5 | 32 | 50 | ⚡ Fast | salt as key |
| HMAC-SHA1 | 40 | 150 | ⚡ Fast | salt as key |
| HMAC-SHA256 | 64 | 1450 | ⚡ Fast | salt as key |

### Slow KDFs (deliberately slow — 1000× slower than MD5)

| Algorithm | Hashcat Mode | Crack Speed | Why Slow | Notes |
|-----------|-------------|-------------|----------|-------|
| bcrypt | 3200 | 🐢 Very Slow | Configurable cost factor (2^rounds) | $2a$/$2b$/$2y$, self-describing |
| scrypt | 8900 | 🐢 Very Slow | Memory-hard + CPU-hard | |
| Argon2i | 9200 | 🐢 Very Slow | Memory-hard, side-channel resistant | $argon2i$ prefix |
| Argon2d | 9300 | 🐢 Very Slow | Memory-hard, GPU-resistant | $argon2d$ prefix |
| Argon2id | 9400 | 🐢 Very Slow | Hybrid of Argon2i + Argon2d | $argon2id$ prefix |
| PBKDF2-SHA1 | 12001 | 🐢 Slow | Iteration count configurable | |
| PBKDF2-SHA256 | 10900 | 🐢 Slow | Iteration count configurable | |
| PBKDF2-SHA512 | 12100 | 🐢 Slow | Iteration count configurable | |

**Why slow?** — These algorithms use work factors (iteration count, memory hardness, parallelization) to make each hash evaluation computationally expensive. A single MD5 hash takes ~0.5μs, while a single bcrypt(12) takes ~80ms — that's 160,000× slower. This is intentional: it makes brute-force and dictionary attacks impractical even with strong hardware.

### Unix/Linux crypt(3) Formats

| Algorithm | Prefix | Hashcat Mode | Crack Speed | Notes |
|-----------|--------|-------------|-------------|-------|
| DES crypt | (no $, 13 chars) | 1500 | ⚡ Fast | Legacy, 56-bit key, extremely weak |
| MD5-crypt | $1$ | 500 | ⚡ Fast | 1000 MD5 iterations |
| SHA256-crypt | $5$ | 7400 | ⚡ Fast | 5000 SHA256 iterations |
| SHA512-crypt | $6$ | 1800 | 🐢 Moderate | 5000 SHA512 iterations — modern Linux default |
| yescrypt | $y$/$7$ | 25600 | 🐢 Slow | Modern replacement for sha512-crypt |

### Windows

| Algorithm | Hex Length | Hashcat Mode | Crack Speed | Notes |
|-----------|-----------|-------------|-------------|-------|
| LM hash | 32 | 3000 | ⚡ Fastest | 7-char split, no salt, case-insensitive, extremely weak |
| NTLM | 32 | 1000 | ⚡ Extremely Fast | MD4 of UTF-16LE, unsalted — Windows default since NT4 |
| NTLMv2 | (complex) | 5600 | 🐢 Slow | Challenge-response, needs captured challenge |

### Database-Specific

| Algorithm | Hex Length | Hashcat Mode | Crack Speed | Notes |
|-----------|-----------|-------------|-------------|-------|
| MySQL 3.2.3 | 16 | 200 | ⚡ Fastest | Old MySQL, extremely weak |
| MySQL 4.1+ | 41 (*40hex) | 300 | ⚡ Fast | SHA1(SHA1(pw)) |
| MSSQL 2000 | 40 | 131 | ⚡ Fast | Unsalted SHA1 of uppercase UTF-16LE |
| MSSQL 2005 | 40 | 132 | ⚡ Fast | SHA1 of UTF-16LE + salt |
| MSSQL 2008 | 64 | 1731 | ⚡ Fast | SHA256 + salt |
| MSSQL 2012+ | 128 | 1731 | 🐢 Moderate | HMAC-SHA512 with salt |
| Oracle 10g | 40 | 3100 | ⚡ Fast | Unsalted SHA1 of uppercase |
| Oracle 11g/12c | 60 | 112 | ⚡ Fast | SHA1-based with salt |
| PostgreSQL MD5 | 35 | 110 | ⚡ Fast | "md5" + md5(pw+username) |

### Web Application Frameworks

| Algorithm | Prefix | Hashcat Mode | Crack Speed | Notes |
|-----------|--------|-------------|-------------|-------|
| phpass (WP/phpBB) | $P$/$H$ | 400 | 🐢 Slow | 8192 iterations of MD5 |
| Django PBKDF2 | (complex) | 10000 | 🐢 Slow | PBKDF2-SHA256 default |
| Drupal 7 | $S$ | 8100 | 🐢 Slow | SHA512-based phpass variant |
| Joomla | hash:salt | — | ⚡ Fast | MD5 + salt |

### Enterprise / Directory

| Algorithm | Prefix | Hashcat Mode | Crack Speed | Notes |
|-----------|--------|-------------|-------------|-------|
| LDAP {SSHA} | {SSHA} | 111 | 🐢 Moderate | Salted SHA1, base64-encoded |
| LDAP {SHA} | {SHA} | 101 | ⚡ Fast | Unsalted SHA1 |
| LDAP {MD5} | {MD5} | 1 | ⚡ Fast | Unsalted MD5 |
| LDAP {CRYPT} | {CRYPT} | 1500 | varies | Wraps Unix crypt formats |
| Kerberos AS-REP | krb5asrep$ | 18200 | 🐢 Slow | Needs captured ticket |
| Kerberos TGS-REP | krb5tgs$ | 13100 | 🐢 Slow | Needs captured ticket |
| Cisco IOS type 5 | (complex) | 5700 | 🐢 Moderate | MD5-crypt variant |
| Cisco IOS type 7 | 07XXXX | — | ⚡ Decode | Reversible XOR (decode, not crack) |

### macOS

| Algorithm | Hashcat Mode | Crack Speed | Notes |
|-----------|-------------|-------------|-------|
| macOS salted PBKDF2 | 7100 | 🐢 Slow | SHA512-PBKDF2 with 40k+ iterations |

---

## 📈 Performance Benchmarks

```
Attack Type          Attempts      Time       Speed       Hash Type
───────────────────────────────────────────────────────────────────
Dictionary (hit)            1      0.00s      596/s        MD5
Hybrid (hit)              124      0.00s       86K/s       MD5
Rule-Based (hit)         27K       0.03s      1.0M/s       MD5
Brute Force 4-char       337K      0.27s      1.2M/s       MD5
Brute Force 5-char         12M      9.5s      1.3M/s       MD5
Brute Force 6-char (lwr)  300M    240.0s      1.2M/s       MD5
Dictionary with salt      66       0.01s      6.6K/s       MD5+salt
```

> ⚠️ Slow KDFs (bcrypt, Argon2, scrypt, PBKDF2) will be **100x–1000x slower** than the above rates. This is by design — they're intentionally hard to crack.

---

## ✅ Test Results

```
✅ 122+ Unit Tests        (100% pass rate, 3 skipped — MD4/NTLM on Python 3.14)
✅ 50+ Hash Algorithm Round-trips  (MD5, SHA1, SHA256, SHA512, NTLM, MD4, MySQL, Oracle, ...)
✅ Salt Tests              (prepend, append, HMAC, hash:salt parsing)
✅ Detection Tests         (prefix-based + hex-based multi-candidate scoring)
✅ Attack Modes            (Dictionary, Brute Force, Hybrid, Rule-Based, Mask, Combinator)
✅ Mask Attack             (?l?u?d?s + custom charsets, keyspace calc, iterators)
✅ Rule Engine             (parse, apply, pipeline, best64 default rules)
✅ Session Persistence     (save, load, delete, list, resume)
✅ Reporting               (JSON/CSV per-session reports)
✅ Wordlist Utilities      (merge, dedupe, apply-rules-export, stats)
✅ Slow-KDF Passthrough    (bcrypt/Argon2/scrypt/pbkdf2 via passlib)
✅ Full Error Handling
```

Run tests yourself:
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
python demo.py
```

---

## 🐳 Docker Deployment

```bash
docker build -t password-toolkit .
docker run -it --rm password-toolkit --help
docker run -it --rm -v $(pwd)/wordlists:/app/wordlists password-toolkit \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/sample.txt --mode dictionary
```

---

## 🤝 Contributing

Contributions are welcome! This project follows PEP 8, uses type hints and docstrings. See [CONTRIBUTING.md](CONTRIBUTING.md).

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
- [passlib](https://passlib.readthedocs.io/) for comprehensive password hash library support
- [Hashcat](https://hashcat.net/hashcat/) developers for GPU-accelerated cracking technology
- The open-source security community

---

<p align="center">
  <b>🏆 Status: v2.1.0 — Mask Attack | Rule Engine | Combinator | Sessions | Multiprocessing</b><br/>
  <i>With great power comes great responsibility. Use ethically. 🔐</i>
</p>
