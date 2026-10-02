# Proof of Work & Screenshot Verification Checklist

This directory catalogs the visual proof-of-work, test outputs, and architecture captures for the **CyberGuard Password Strength Analyzer & Security Suggestion Tool**.

---

## Screenshot Inventory & Filename Specifications

| # | Screenshot Filename | Description / Viewport Target | Key Evidence Demonstrated |
|---|--------------------|--------------------------------|---------------------------|
| 1 | `01_project_structure.png` | Terminal tree / Explorer view of project structure | Complete modular folder architecture |
| 2 | `02_architecture_diagram.png` | Architecture pipeline diagram from docs | In-memory flow, privacy boundaries, CSPRNG |
| 3 | `03_analyzer_homepage.png` | Full application interface on initial load | Modern dark-mode UI, navigation, zero-state |
| 4 | `04_hidden_password_field.png` | Input field with default masked characters | Obfuscated input, show/hide eye toggle |
| 5 | `05_very_weak_evaluation.png` | Analysis of synthetic password: `123456` | Score 0/100, VERY WEAK badge, common list match |
| 6 | `06_weak_evaluation.png` | Analysis of synthetic password: `Password123!` | Composition checklist met, but penalized to WEAK |
| 7 | `07_moderate_evaluation.png` | Analysis of synthetic password: `BlueSkySummer99` | Score ~55, MODERATE badge, predictable year |
| 8 | `08_strong_evaluation.png` | Analysis of synthetic password: `W8#pL9$zK2!vX5@m` | Score ~75, STRONG badge, 4 character classes |
| 9 | `09_very_strong_passphrase.png` | Passphrase: `cactus-orbit-velvet-frost-zenith` | Score 95+, VERY STRONG badge, high entropy |
| 10 | `10_length_band_analysis.png` | Length breakdown panel showing educational band | Educational message (<8, 8-11, 12-15, 16+) |
| 11 | `11_sequence_detection.png` | Vulnerability card showing `1234` / `9876` | Ascending and descending sequence alerts |
| 12 | `12_keyboard_walk_detection.png`| Vulnerability card showing `qwerty` / `asdf` | Horizontal and vertical keyboard walk alert |
| 13 | `13_repetition_detection.png` | Analysis of `aaaaaaaaaaaaaaaa` | Consecutive repetition and substring alerts |
| 14 | `14_common_password_warning.png` | Common dictionary match banner | Warning against compromised wordlist matches |
| 15 | `15_security_recommendations.png` | Tailored recommendations list | Specific advice (MFA, password managers, passphrases) |
| 16 | `16_entropy_calculation.png` | Theoretical vs Effective entropy card | Shannon bits vs discount for human predictability |
| 17 | `17_password_generator.png` | CSPRNG generator tab with 20-character result | Python secrets CSPRNG, copy & analyze buttons |
| 18 | `18_passphrase_generator.png` | Diceware-style passphrase generator tab | 4-word random phrase with separator selection |
| 19 | `19_policy_checker_pass.png` | NIST SP 800-63B policy pass badge | Compliance status decoupled from raw score |
| 20 | `20_policy_checker_fail.png` | Policy violations list for short credential | Min length violation and common password alert |
| 21 | `21_analytics_dashboard.png` | Telemetry dashboard overview with metrics | Total analyses, average score, average length |
| 22 | `22_classification_chart.png` | Chart.js doughnut chart of strength tiers | Visual breakdown of tested credentials |
| 23 | `23_weakness_chart.png` | Chart.js horizontal bar chart of weaknesses | Frequency of sequences, keyboard walks, repeats |
| 24 | `24_hashing_benchmark.png` | Hashing benchmark lab comparing MD5 vs PBKDF2 | Timings in ms, memory-hard defense advantages |
| 25 | `25_security_rules_cards.png` | 10 Password Security Rules grid | Professional defensive awareness best practices |
| 26 | `26_automated_unit_tests.png` | Terminal running `pytest` / `unittest` | 35 passed in under 2 seconds |
| 27 | `27_privacy_verification_tests.png`| Terminal running `test_security_privacy.py` | Schema verification showing zero password column |
| 28 | `28_api_response_terminal.png` | Curl / Postman response for `POST /api/analyze` | JSON structured output with no reflected password |

---

## Instructions for Capturing Screenshots

1. **Launch the application:**
   ```powershell
   python backend/app.py
   ```
2. **Open browser:** Navigate to `http://127.0.0.1:5000`.
3. **Capture full-screen browser shots** using Windows Snipping Tool (`Win + Shift + S`) or browser developer tools (`Ctrl + Shift + P` -> "Capture full size screenshot").
4. **Save with standardized filenames** into this `screenshots/` directory.
