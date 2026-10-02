# Password Strength Analyzer & Security Suggestion Tool

[![Defensive Cybersecurity](https://img.shields.io/badge/Security-Defensive%20Engineering-blue?style=for-the-badge&logo=shield)](https://github.com/)
[![Zero-Persistence](https://img.shields.io/badge/Privacy-Zero--Knowledge%20In--Memory-emerald?style=for-the-badge&logo=lock)](https://github.com/)
[![Tests](https://img.shields.io/badge/Tests-36%2F36%20Passed-brightgreen?style=for-the-badge&logo=pytest)](https://github.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)

> **CyberGuard** is an industry-oriented, privacy-preserving defensive cybersecurity application engineered to evaluate password strength using length, predictability, common-password lists, pattern analysis, and entropy concepts. It provides actionable security guidance, NIST SP 800-63B policy checking, cryptographically secure password generation, and an educational hashing laboratory.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Cybersecurity Relevance](#cybersecurity-relevance)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Password Analysis Engine](#password-analysis-engine)
- [Length Analysis](#length-analysis)
- [Pattern Detection](#pattern-detection)
- [Common Password Detection](#common-password-detection)
- [Entropy Estimation](#entropy-estimation)
- [Strength Scoring](#strength-scoring)
- [Security Suggestions](#security-suggestions)
- [Password Generator](#password-generator)
- [Password Policy Checker](#password-policy-checker)
- [Privacy Design](#privacy-design)
- [Installation](#installation)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Security Testing](#security-testing)
- [Results](#results)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Screenshots](#screenshots)
- [Learning Outcomes](#learning-outcomes)
- [Security Disclaimer](#security-disclaimer)
- [Author](#author)

---

## Overview

Most traditional password checkers measure strength purely through character composition: checking if a password contains uppercase, lowercase, numbers, and symbols. Under this naive rubric, a password such as:

```text
Password123!
```

receives a high score because it satisfies all four character classes. However, in real-world security operations, `Password123!` is broken in milliseconds using rule-based dictionary attacks because it follows standard predictable patterns: a dictionary word capitalized at the start, followed by an ascending sequential run and a predictable trailing symbol.

**CyberGuard** establishes a modern, defensible credential evaluation paradigm:
$$\text{Length} + \text{Unpredictability} + \text{Pattern Resistance} + \text{Common-Password Checks} + \text{Context} = \text{Better Password Assessment}$$

---

## Problem Statement

Weak, predictable, and reused passwords remain the single largest initial attack vector leading to enterprise credential stuffing, account takeover (ATO), and data breaches. Users forced to comply with rigid composition mandates frequently default to predictable transformations (e.g. replacing 'a' with '@' or appending '!'). Traditional meters reinforce this dangerous behavior by showing "Strong" indicators for predictable credentials while offering no actionable defensive guidance.

---

## Objectives

1. **Eliminate False Confidence:** Flag predictable structures, keyboard walks, repetitions, and dictionary words even when composition checklists are satisfied.
2. **Effective Entropy Formulation:** Contrast theoretical Shannon entropy with effective entropy adjusted for human predictability.
3. **Strict Zero-Knowledge Privacy:** Guarantee that user credentials are processed transiently in memory with zero plaintext logging or storage.
4. **Actionable Recommendations:** Provide specific defensive guidance recommending passphrases, password managers, and Multi-Factor Authentication (MFA).
5. **NIST SP 800-63B Alignment:** Decouple formal compliance (PASS/FAIL) from mathematical password strength.

---

## Cybersecurity Relevance

Password security controls are foundational to:
- **Authentication & IAM Systems:** Protecting identity boundaries in Azure AD, Okta, and enterprise SSO portals.
- **Banking & E-Commerce:** Defending customer accounts against automated credential stuffing and brute-force botnets.
- **Application Security (AppSec):** Enforcing secure authentication design principles (OWASP ASVS).
- **Security Operations Center (SOC):** Analyzing authentication log telemetry to detect spraying and dictionary spikes.

### Relevant Cybersecurity Career Roles:
- **Application Security Analyst:** Validating authentication workflows, input boundaries, and credential validation logic.
- **Identity & Access Management (IAM) Specialist:** Defining modern password policies aligned with NIST SP 800-63B.
- **Cybersecurity Analyst / SOC Analyst:** Recognizing adversary password-guessing tactics (MITRE ATT&CK T1110).
- **Secure Software Engineer:** Implementing CSPRNGs (`secrets`), salt generation, and slow key-stretching functions.

---

## Features

- ⚡ **Real-Time Reactive Meter:** Debounced evaluation updating score, classification, and metrics as you type.
- 👁️ **Show / Hide Password:** Obfuscated password input by default with secure toggle.
- 📏 **Educational Length Bands:** Evaluates length across four calibrated boundaries (`<8`, `8–11`, `12–15`, `16+`).
- 🔠 **Character Diversity Analysis:** Evaluates character classes, unique character count, and uniqueness ratio.
- 📖 **Common Password & Leetspeak Screening:** Set-based local detection against sanitized common credential lists.
- ⌨️ **Sequence & Keyboard Walk Detection:** Flags ascending/descending numeric/alphabetic runs and QWERTY walks.
- 🔁 **Repetition Detection:** Identifies consecutive identical characters (`aaaa`) and repeating substrings (`abcabc`).
- 📅 **Predictable Grammar & Year Detection:** Detects `TitleCase + Number + Symbol` and calendar years (`2020-2099`).
- 👤 **Voluntary Personal Context Check:** Tests for overlap with name, birth year, or organization in memory.
- 🧮 **Dual Entropy Calculation:** Computes both theoretical Shannon bits and effective bits factoring in pattern discounts.
- 🎯 **5-Tier Calibrated Scoring:** Scores 0–100 mapped to `VERY WEAK`, `WEAK`, `MODERATE`, `STRONG`, and `VERY STRONG`.
- 🛡️ **Actionable Suggestions Engine:** Context-aware defensive guidance without echoing passwords.
- 📋 **NIST SP 800-63B Policy Checker:** Evaluates PASS/FAIL status independently from strength score.
- 🎲 **CSPRNG Generator:** Generates high-entropy random passwords and Diceware-style passphrases using Python's `secrets` module.
- ⏱️ **Cryptographic Hashing Lab:** Real-time benchmark comparing MD5, SHA-256, PBKDF2 (600k rounds), and scrypt.
- 📊 **Privacy-Safe Telemetry Dashboard:** Aggregated metrics and interactive Chart.js charts backed strictly by safe metadata.
- 💡 **10 Password Security Rules:** Curated awareness guidance on password hygiene, passkeys, and MFA.

---

## Architecture

```
User Browser (Client)
         │
         ▼ (JSON over HTTP/HTTPS)
Flask REST API Gateway (api.py)
         │
         ▼ [In-Memory Isolation Boundary]
┌───────────────────────────────────────────────────────────┐
│ Length Analyzer │ Character Pool Analyzer │ Common Checker │
│ Sequence Detector │ Keyboard Walk Detector │ Repetition   │
│ Context Matcher │ Entropy Engine │ NIST Policy Evaluator  │
└───────────────────────────────────────────────────────────┘
         │
         ▼
Scoring & Suggestion Engine (scoring_engine.py & suggestion_engine.py)
         │
         ▼ (Only Non-Reversible Numeric Metadata)
SQLite Telemetry Database (analyses & findings tables)
```

---

## Technology Stack

| Layer | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+ / Flask | Lightweight, modular REST API; ideal for readable, defensible security logic |
| **CSPRNG** | Python `secrets` | Cryptographically secure random source utilizing OS entropy (`CryptGenRandom` / `getrandom`) |
| **Frontend** | HTML5 / CSS3 / Vanilla JS | Zero external framework dependencies; high performance and transparency |
| **Telemetry DB** | SQLite | Serverless, relational database storing exclusively non-reversible numeric metadata |
| **Visualizations** | Chart.js | Dynamic, client-side rendering of distribution and weakness frequency charts |
| **Testing** | `unittest` & `pytest` | 36 automated unit and security tests ensuring engine and privacy integrity |

---

## Password Analysis Engine

The central orchestrator [`analyze_password(password, context, policy)`](backend/services/password_analyzer.py) coordinates all modular analyzers and returns a rich JSON payload:

```json
{
  "score": 75,
  "classification": "STRONG",
  "classification_description": "High level of resistance against standard offline and online attack techniques.",
  "findings": [],
  "suggestions": [
    "Credential Hygiene: Never reuse this password across other accounts or services.",
    "Password Manager: Use a reputable password manager to generate and store 16–24+ character credentials.",
    "Defense-in-Depth: Always enable Multi-Factor Authentication (MFA/2FA)."
  ],
  "metrics": {
    "length": 16,
    "length_band": "Strong Length",
    "character_type_count": 4,
    "unique_character_count": 14,
    "unique_character_ratio": 0.875,
    "has_lowercase": true,
    "has_uppercase": true,
    "has_digits": true,
    "has_symbols": true,
    "has_spaces": false,
    "pattern_count": 0,
    "is_common": false
  },
  "entropy": {
    "theoretical_bits": 105.12,
    "effective_bits": 105.12,
    "search_space_notation": "2^105.1 combinations",
    "strength_tier": "Extremely High Resistance"
  },
  "policy": {
    "status": "PASS",
    "policy_passed": true,
    "violations": []
  }
}
```

---

## Length Analysis

- `< 8 characters:` **Very Short** (Capped at `VERY WEAK`)
- `8–11 characters:` **Short** (Vulnerable to modern hash-rate cracking)
- `12–15 characters:` **Better Length** (Meets enterprise baseline)
- `16+ characters:` **Strong Length** (Substantial search space expansion)

*Length alone does not guarantee security: `aaaaaaaaaaaaaaaa` is 16 characters long, yet collapses due to repetition.*

---

## Pattern Detection

1. **Sequences:** Scans for runs like `1234`, `9876`, `abcd`, `dcba`.
2. **Keyboard Walks:** Scans horizontal rows (`qwerty`, `asdf`) and vertical columns (`1qaz`, `2wsx`).
3. **Repetitions:** Detects 3+ identical consecutive characters (`aaaa`) and multi-character loops (`ababab`).
4. **Predictable Structures:** Identifies `TitleCase + Digits + Symbol` (e.g. `Welcome123!`).
5. **Personal Context:** Optional local check for first name, birth year, or organization.

---

## Common Password Detection

Checks inputs against [data/common_passwords.txt](data/common_passwords.txt) using:
- **Exact Match:** Instant $O(1)$ set lookup.
- **Root Extraction:** Strips trailing numbers/symbols to catch `password123!` or `welcome2026`.
- **Leetspeak Inversion:** Reverses common substitutions (`p@ssw0rd` $\rightarrow$ `password`).

---

## Entropy Estimation

- **Theoretical Shannon Entropy:**
  $$H_{\text{theoretical}} = L \times \log_2(N)$$
- **Effective Entropy:**
  Adjusts theoretical bits downward when dictionary words, repetitions, or keyboard walks are detected.

---

## Strength Scoring

Score range: **0 to 100**
- **0–20:** `VERY WEAK`
- **21–40:** `WEAK`
- **41–60:** `MODERATE`
- **61–80:** `STRONG`
- **81–100:** `VERY STRONG`

Guardrails ensure common passwords and critically short inputs cannot exceed `WEAK`.

---

## Password Policy Checker

Evaluates NIST SP 800-63B modern authentication policies:
- Minimum length (12 or 16 characters).
- Screening against breached/common lists.
- Permitting spaces for passphrases.
- Decouples policy compliance from mathematical strength.

---

## Privacy Design

- **Zero-Knowledge Architecture:** No password column exists in SQLite database schema.
- **In-Memory Volatility:** Passwords are processed transiently and discarded immediately.
- **No Console Logging:** Request body logging is suppressed to prevent leakage in log files.
- **Client-Side Privacy:** No `localStorage` or `sessionStorage` caching.
- **Strict Headers:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Step-by-Step Setup

```powershell
# 1. Clone the repository
git clone https://github.com/<your-username>/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool

# 2. Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the backend application
python backend/app.py
```

### Access Application
Open your web browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## API Documentation

### 1. Analyze Password
- **Endpoint:** `POST /api/analyze`
- **Request Body:**
  ```json
  {
    "password": "SamplePassword123!",
    "context": {
      "first_name": "John",
      "birth_year": "1995",
      "org_name": "Acme"
    },
    "policy": {
      "min_length": 12,
      "reject_common": true,
      "reject_personal": true
    },
    "record_analytics": true
  }
  ```
- **Response:** `200 OK` with analysis breakdown, findings, and suggestions.

### 2. Generate Secure Credential
- **Endpoint:** `POST /api/generate-password`
- **Request Body (Password Mode):**
  ```json
  {
    "mode": "password",
    "length": 20,
    "include_upper": true,
    "include_lower": true,
    "include_digits": true,
    "include_symbols": true
  }
  ```
- **Request Body (Passphrase Mode):**
  ```json
  {
    "mode": "passphrase",
    "word_count": 4,
    "separator": "-"
  }
  ```

### 3. Hashing Lab Benchmark
- **Endpoint:** `POST /api/hashing-demo`
- **Request Body:** `{ "sample": "DemoPassword" }`
- **Response:** Execution timings and attacker disadvantage comparison across MD5, SHA-256, PBKDF2 (600,000 rounds), and scrypt.

### 4. Telemetry Statistics
- **Endpoint:** `GET /api/dashboard/stats`
- **Response:** Aggregate counts, averages, and distribution histograms.

---

## Testing

Run the automated test suite of **35 unit and security tests**:

```powershell
# Run with Python standard unittest
python -m unittest discover -s tests -p "test_*.py"

# Or run with pytest
pytest tests/ -v
```

All 35 tests pass:
```text
tests/test_analyzer.py ..............................                    [ 85%]
tests/test_security_privacy.py .....                                     [100%]
============================== 35 passed in 1.88s ==============================
```

---

## Safe Demonstration Cases

| Synthetic Password | Expected Classification | Key Findings |
| :--- | :--- | :--- |
| `123456` | **VERY WEAK** (Score: 0) | Exact common match, critically short, sequential run |
| `Password123!` | **VERY WEAK** (Score: 0) | Common root word, ascending digits (`123`), predictable grammar |
| `aaaaaaaaaaaaaaaa` | **WEAK** (Score: 23) | Length 16, but collapsed uniqueness ratio and consecutive repetition |
| `qwerty2026!` | **VERY WEAK** (Score: 0) | Horizontal keyboard walk, calendar year pattern (`2026`) |
| `x]=$E_^*Mo5XmKCK%%S>` | **VERY STRONG** (Score: 100) | CSPRNG generated 20 chars, zero detected patterns, high entropy |

---

## Screenshots

Refer to the [screenshots/](screenshots/README.md) directory for captured evidence:
- Real-time strength meter and score animation
- NIST SP 800-63B policy compliance checks
- CSPRNG random credential and Diceware passphrase generator
- Real-time cryptographic hashing benchmark
- Chart.js telemetry charts and vulnerability frequency analytics

---

## Learning Outcomes

1. Deepened understanding of **adversarial authentication attacks** (dictionary, mask, rule-based, and brute-force).
2. Mastered **information entropy theory** and its practical limitations when applied to human psychology.
3. Designed **privacy-preserving architectures** guaranteeing zero credential exposure.
4. Gained practical fluency in **cryptographic APIs** (`secrets`, `hashlib.pbkdf2_hmac`, `hashlib.scrypt`).
5. Implemented modern **NIST SP 800-63B** authentication guidance.

---

## Security Disclaimer

> **Educational & Defensive Tool Only:** This tool is intended for defensive security education, credential resilience evaluation, and secure coding instruction. Passwords entered are processed strictly in-memory. Never enter live, high-privilege production credentials into third-party or untrusted environments. Always use a dedicated password manager and enable Multi-Factor Authentication (MFA).

---

## Author
**Abhishek Basu — Embedded Systems Student GitHub: [DevAbhay2003](https://github.com/DevAbhay2003?tab=repositories) · LinkedIn: [Abhishek Basu](https://www.linkedin.com/in/abhishek-basu-68b1b1342/)**
