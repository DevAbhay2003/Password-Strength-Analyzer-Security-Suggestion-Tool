# Academic & Technical Project Report

**Project Title:** Password Strength Analyzer & Security Suggestion Tool  
**System Designation:** CyberGuard  
**Domain:** Defensive Cybersecurity, Application Security, Identity & Access Management (IAM)  
**Academic Target:** Cybersecurity Engineering Course Capstone / Proof of Work  

---

## 1. Abstract

Authentication remains the primary gatekeeper for digital identities, yet passwords represent the most widely exploited initial access vector in modern cyberattacks. Conventional password composition rules (requiring uppercase letters, digits, and symbols) foster a false sense of security, resulting in predictable substitutions (e.g., `Password123!`) that pass complexity checks but fall victim to dictionary, mask, and hybrid attacks in milliseconds.

This project designs and implements **CyberGuard**, an industry-aligned, privacy-preserving defensive cybersecurity application that provides holistic password strength evaluation and actionable security recommendations. The system evaluates credentials across five critical vectors: **Length, Unpredictability, Pattern Resistance, Common-Password Screening, and Contextual Overlap**. Built with an in-memory execution pipeline, CyberGuard ensures that no plaintext credentials or hashes are logged or stored. In addition, the tool integrates modern NIST SP 800-63B policy compliance checking, a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) credential generator, an educational password hashing laboratory comparing fast vs. memory-hard functions, and an anonymized telemetry dashboard powered by Chart.js.

---

## 2. Introduction

Authentication credentials protect enterprise databases, cloud infrastructure, banking portals, and consumer accounts. Despite decades of security guidelines, user credentials remain susceptible to predictable human patterns. When organizations enforce naive complexity policies without screening for predictability, users systematically adhere to patterns such as capitalizing the initial letter and appending `123!` or current calendar years.

This project addresses these systemic weaknesses by providing users, developers, and security analysts with an open-source, local analysis engine that accurately measures password resistance against real-world adversary workflows.

---

## 3. Problem Statement

Traditional password evaluation systems suffer from three fundamental flaws:
1. **Misleading Composition Rules:** Traditional password meters check binary presence of character classes ($A-Z, a-z, 0-9, \text{symbols}$) without measuring structural predictability.
2. **Inaccurate Theoretical Entropy:** Standard entropy formulas assume characters are selected uniformly at random from a character pool, yielding falsely high bit-entropy ratings for predictable human passwords (e.g. evaluating `Password123!` as ~78 bits).
3. **Privacy Vulnerabilities:** Many online password checkers transmit credentials over public networks or query third-party APIs, creating potential exposure points for sensitive user data.

---

## 4. Objectives

The primary objectives of this project are:
- **Build a Multi-Layered Analysis Engine:** Decompose credentials into length, diversity, dictionary roots, keyboard walks, repetitions, and sequences.
- **Implement Realistic Entropy Estimation:** Formulate an effective entropy calculation that discounts predictable human structures.
- **Provide Actionable Defensive Recommendations:** Deliver context-aware guidance covering passphrases, password managers, and Multi-Factor Authentication (MFA).
- **Ensure Strict Zero-Knowledge Privacy:** Guarantee in-memory transient processing with zero logging or disk persistence of plaintext passwords.
- **Educate on Authentication Fundamentals:** Demonstrate password hashing, salting, key-stretching, and brute-force resistance concepts through interactive benchmarks.

---

## 5. Password Security & Authentication Background

### 5.1 Authentication vs. Authorization
- **Authentication (AuthN):** Verifying the identity claim of an entity ("Who are you?").
- **Authorization (AuthZ):** Granting or denying access to resources based on validated identity permissions ("What are you allowed to do?").

### 5.2 Plaintext Passwords vs. Password Hashes
Under no circumstances should production authentication systems store plaintext passwords. If a database is breached via SQL injection or unauthorized backup access, plaintext credentials expose users immediately across all services where credentials are reused.

A cryptographic hash is a one-way mathematical function that maps arbitrary-length input data to a fixed-length digest:
$$\text{Digest} = H(\text{Password})$$
Hashing is irreversible: an adversary cannot computationally derive the original plaintext from the digest alone.

### 5.3 Modern Password Hashing Functions
General-purpose cryptographic hashes (such as MD5, SHA-1, and SHA-256) were designed for data integrity and speed. On modern consumer GPUs and ASICs, attackers compute billions of SHA-256 hashes per second, making fast hashes completely unsuitable for password storage.

Production systems require **slow, memory-hard key derivation functions**:
- **Argon2id:** Winner of the Password Hashing Competition (PHC). Provides resistance against both GPU-parallel and side-channel cache attacks.
- **bcrypt:** Adaptive hash function based on the Blowfish cipher with configurable work factor.
- **scrypt:** Memory-hard function designed to require large amounts of RAM, neutralizing hardware ASIC advantages.
- **PBKDF2:** NIST-approved key-stretching function applying hundreds of thousands of HMAC iterations.

---

## 6. System Architecture & Component Design

The CyberGuard system follows a modular, defensively decoupled three-tier architecture:

```
[ Frontend: HTML5 / CSS3 / ES6 / Chart.js ]
                    │
                    ▼ (JSON over HTTP/HTTPS)
[ Backend: Flask REST API / Rate Limiter / Security Headers ]
                    │
                    ▼ (In-Memory Pipeline)
┌───────────────────────────────────────────────────────────┐
│ Length Analyzer │ Character Pool Analyzer │ Common Checker │
│ Sequence Detector │ Keyboard Walk Detector │ Repetition   │
│ Context Matcher │ Entropy Engine │ NIST Policy Evaluator  │
└───────────────────────────────────────────────────────────┘
                    │
                    ▼
[ Scoring Engine & Actionable Suggestion Engine ]
                    │
                    ▼ (Safe Anonymized Metadata Only)
[ SQLite Telemetry Database: scores, lengths, finding types ]
```

---

## 7. Password Analysis & Feature Extraction

### 7.1 Length Analysis
Password length is the primary exponent in keyspace sizing. The system categorizes length into four educational tiers:
- `< 8 chars:` Critically short; capped at `VERY WEAK`.
- `8–11 chars:` Short; legacy baseline; vulnerable to modern GPU clusters.
- `12–15 chars:` Better length; modern enterprise standard.
- `16+ chars:` Strong length contribution.

### 7.2 Character Diversity & Uniqueness Ratio
The analyzer evaluates character classes and calculates the uniqueness ratio:
$$\text{Uniqueness Ratio} = \frac{\text{Unique Characters}}{\text{Total Characters}}$$
A password such as `aaaaaaaaaaaaaaaa` (length 16) has a uniqueness ratio of $1/16 = 0.0625$, immediately triggering repetition penalties.

### 7.3 Common Credential & Leetspeak Detection
The analyzer tests input against `data/common_passwords.txt`, checking:
1. Exact match (case-insensitive).
2. Root word match with appended numbers/symbols (`password` + `123!`).
3. Leetspeak mapping (`p@ssw0rd` $\rightarrow$ `password`).

### 7.4 Sequence, Keyboard & Repetition Detection
- **Sequences:** Detects consecutive numerical (`123`, `987`) and alphabetical (`abc`, `cba`) runs.
- **Keyboard Walks:** Scans horizontal rows (`qwerty`, `asdf`) and vertical columns (`1qaz`, `2wsx`).
- **Repetitions:** Detects 3+ identical consecutive characters (`aaaa`) and multi-character loops (`ababab`, `abcabc`).
- **Predictable Grammar:** Flags the ubiquitous `TitleCase + Digits + Symbol` formula.

---

## 8. Entropy Formulation: Theoretical vs. Effective

### 8.1 Theoretical Shannon Entropy
Assuming uniform random selection from an estimated character pool $N$ of length $L$:
$$H_{\text{theoretical}} = L \times \log_2(N)$$

| Character Set Present | Pool Size ($N$) | Bits per Character ($\log_2 N$) |
| :--- | :--- | :--- |
| Lowercase only | 26 | ~4.70 bits |
| Alphanumeric (lower + upper + digits) | 62 | ~5.95 bits |
| Full Printable ASCII (with symbols) | 95 | ~6.57 bits |

### 8.2 Effective Entropy Discounting
Because humans do not select characters uniformly at random, theoretical entropy produces deceptive estimates. CyberGuard calculates **Effective Entropy**:
$$H_{\text{effective}} = \max\left(0, H_{\text{theoretical}} - \sum \text{Pattern Discounts} \times \text{Uniqueness Factor}\right)$$
For example, `Password123!` has $H_{\text{theoretical}} \approx 78.8 \text{ bits}$, but after discounting common word roots and predictable grammar, $H_{\text{effective}}$ drops to under $15 \text{ bits}$.

---

## 9. Scoring Model & Classification Calibration

CyberGuard uses a bounded 0–100 composite scoring algorithm:
$$\text{Score} = \text{clamp}\left(0, 100, \sum \text{Positive Contributions} - \sum \text{Penalties}\right)$$

### 9.1 Point Distribution
- **Length:** up to +35
- **Character Diversity:** up to +15
- **Uniqueness Ratio:** up to +10
- **Pattern Resistance:** up to +20
- **Non-Common List Check:** up to +10
- **Unpredictability Factor:** up to +10

### 9.2 Guardrails
- If a password matches common lists, final score is capped at `35 (WEAK)`.
- If a password has length $< 6$ or $< 8$ with only 1 character class, final score is capped at `18 (VERY WEAK)`.

---

## 10. Privacy & Zero-Knowledge Architecture

CyberGuard enforces privacy at the architectural level:
1. **In-Memory Volatility:** Passwords exist solely in memory during request evaluation.
2. **Server Log Suppression:** Web server access logs filter and suppress request body content.
3. **Zero-Knowledge Telemetry DB:** The SQLite database stores exclusively non-reversible numeric metadata:
   - `analysis_id` (UUID)
   - `score` (Integer)
   - `classification` (String)
   - `password_length` (Integer)
   - `weakness_count` (Integer)
   - `created_at` (Timestamp)
   *No plaintext or hash columns exist in the schema.*
4. **Client-Side Privacy:** Passwords are never saved in `localStorage`, `sessionStorage`, or emitted to `console.log`.

---

## 11. Verification & Test Results

The test suite contains **35 automated unit and security tests** executed via Python's standard `unittest` and `pytest` frameworks.

### Summary of Test Execution:
```
============================= 35 passed in 1.88s ==============================
```

### Key Verification Cases:
- **Common Credential (`123456`):** Classified as `VERY WEAK` (Score: 0).
- **Predictable Grammar (`Password123!`):** Classified as `VERY WEAK` (Score: 0).
- **Repetitive String (`aaaaaaaaaaaaaaaa`):** Classified as `WEAK` (Score: 23).
- **Keyboard Walk (`qwerty2026!`):** Classified as `VERY WEAK` (Score: 0).
- **Random 20-Character CSPRNG:** Classified as `VERY STRONG` (Score: 100).
- **Database Schema Audit:** Verified zero password columns in SQLite tables.
- **API Leakage Audit:** Verified request input is never reflected in API responses.

---

## 12. Limitations & Future Scope

### Limitations:
- The local common password dataset contains a curated educational list rather than multi-gigabyte breach corpora (e.g. RockYou2024).
- Offline cracking resistance metrics represent educational approximations rather than absolute guarantees.

### Future Scope:
- Integration with Privacy-Preserving k-Anonymity API queries (e.g., Have I Been Pwned range queries using SHA-1 prefixes).
- Enterprise IAM Active Directory / Azure AD integration for real-time password filter simulation.
- WebAuthn / FIDO2 Passkey demonstration module.

---

## 13. Conclusion

The CyberGuard Password Strength Analyzer & Security Suggestion Tool demonstrates that effective credential evaluation requires moving beyond rigid composition checklists toward comprehensive predictability and pattern analysis. By combining multi-vector heuristic analysis, realistic effective entropy estimation, NIST SP 800-63B policy checking, and strict zero-knowledge privacy controls, this project delivers an industry-grade defensive cybersecurity capstone ready for academic and professional review.
