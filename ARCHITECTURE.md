# Architecture

## High-Level Design

Password Cracker Toolkit follows a modular architecture with clear separation of concerns. Each attack mode is an independent module, and the core engine orchestrates execution based on CLI input.

## System Overview

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  CLI (main) │────▶│  Core Engine     │────▶│  Attack      │
│  argparse   │     │  (orchestrator)  │     │  Modules     │
└─────────────┘     └───────┬──────────┘     └──────────────┘
                            │                          │
                            ▼                          ▼
                     ┌──────────────┐          ┌──────────────┐
                     │  Hash        │          │  Dictionary  │
                     │  Detector    │          │  Brute Force │
                     └──────────────┘          │  Hybrid      │
                                                │  Rule-Based  │
                     ┌──────────────┐          │  Mask        │
                     │  Session     │          │  Combinator  │
                     │  Manager     │          └──────────────┘
                     └──────────────┘                 │
                                                      ▼
                     ┌──────────────┐          ┌──────────────┐
                     │  GPU Wrapper │          │  Rule Engine │
                     │  (hashcat)   │          │  (.rule)     │
                     └──────────────┘          └──────────────┘
```

## Module Descriptions

### CLI Entry Point (`main.py`)
Parses command-line arguments and dispatches to the appropriate attack mode. Handles wordlist utilities, session management, and reporting flags.

### Core Engine (`cracker/core_engine.py`)
The central orchestrator. Coordinates hash detection, salt handling, slow-KDF verification, session save/resume, multiprocessing, and attack module invocation.

### Hash Detector (`cracker/hash_detector.py`)
Identifies hash type using multi-candidate scoring: prefix signatures, length heuristics, and confidence ranking. Supports 50+ hash algorithms.

### Attack Modules (`attacks/`)
Six independent attack strategies, each implementing a standard interface:
- **Dictionary** — Wordlist lookup with salt support
- **Brute Force** — Exhaustive character combination generation
- **Hybrid** — Wordlist + numeric/year/symbol mutations
- **Rule-Based** — Transformation rules (leet, capitalization, prefix/suffix)
- **Mask** — Hashcat-compatible `?l?u?d?s?a?b` mask patterns
- **Combinator** — Concatenates every word from two wordlists

### Rule Engine (`attacks/rule_engine.py`)
Parses and applies hashcat `.rule` files. Includes best64 default rules and supports rule pipelining.

### Session Manager (`cracker/session.py`)
Saves and resumes attack state via JSON checkpoints in `sessions/`. Enables long-running attacks to survive interruptions.

### GPU Wrapper (`gpu/hashcat_wrapper.py`)
Integrates with Hashcat for GPU-accelerated cracking. Maps 40+ hash types to Hashcat mode IDs and passes through mask/rule arguments.

### Utilities
- **Analyzer** (`cracker/analyzer.py`) — Password strength scoring (0–100)
- **Logger** (`cracker/logger.py`) — Structured logging
- **Reporting** (`cracker/reporting.py`) — JSON/CSV export
- **Timer** (`utils/timer.py`) — Performance timing
- **Formatter** (`utils/formatter.py`) — Colored terminal output

## Data Flow

1. User invokes CLI with `--hash <hash> --mode <mode> [options]`
2. `main.py` parses arguments and calls `CoreEngine.crack()`
3. Core Engine detects hash algorithm via `HashDetector`
4. If salt is detected (hash:salt, $id$salt$, --salt flag), it's extracted
5. The appropriate Attack Module is instantiated and executed
6. Results are streamed to output, logged, and optionally exported

## Key Design Decisions

- **Salt-first architecture**: Salt extraction happens before any attack begins
- **Session checkpoints**: JSON-based save/resume for long-running attacks
- **Multiprocessing**: Brute-force and mask attacks parallelize across CPU cores
- **Plugin-style attacks**: Adding a new attack mode requires only implementing a standard interface
