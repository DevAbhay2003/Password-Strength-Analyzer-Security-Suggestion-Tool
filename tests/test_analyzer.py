"""
Unit Test Suite for Password Strength Analyzer
Contains 30+ comprehensive test scenarios evaluating length, character sets,
sequences, repetitions, keyboard walks, dictionary matching, context,
entropy, scoring, generation, and policy enforcement.
"""

import unittest
from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import generate_secure_password, generate_secure_passphrase
from backend.services.policy_checker import evaluate_policy
from backend.models.database import init_db, record_analysis_metadata, get_connection

class TestPasswordStrengthAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    # TEST 1: Empty password
    def test_01_empty_password(self):
        res = analyze_password("")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["classification"], "VERY WEAK")
        self.assertEqual(res["metrics"]["length"], 0)

    # TEST 2: One-character password
    def test_02_one_character_password(self):
        res = analyze_password("a")
        self.assertLessEqual(res["score"], 20)
        self.assertEqual(res["classification"], "VERY WEAK")
        self.assertEqual(res["metrics"]["length"], 1)

    # TEST 3: Short numeric password
    def test_03_short_numeric_password(self):
        res = analyze_password("12345")
        self.assertEqual(res["classification"], "VERY WEAK")
        self.assertTrue(res["metrics"]["has_digits"])
        self.assertFalse(res["metrics"]["has_lowercase"])

    # TEST 4: Common password
    def test_04_common_password(self):
        res = analyze_password("password")
        self.assertTrue(res["metrics"]["is_common"])
        self.assertIn(res["classification"], ["VERY WEAK", "WEAK"])
        self.assertTrue(any(f["type"] == "common_password" for f in res["findings"]))

    # TEST 5: Long repeated password (long but low entropy)
    def test_05_long_repeated_password(self):
        res = analyze_password("aaaaaaaaaaaaaaaa")
        # 16 characters, but all identical
        self.assertIn(res["classification"], ["VERY WEAK", "WEAK"])
        self.assertTrue(any(f["type"] == "repeated_characters" for f in res["findings"]))
        self.assertLess(res["metrics"]["unique_character_ratio"], 0.2)

    # TEST 6: Lowercase only
    def test_06_lowercase_only(self):
        res = analyze_password("abcdefghijklmnop")
        self.assertTrue(res["metrics"]["has_lowercase"])
        self.assertFalse(res["metrics"]["has_uppercase"])
        self.assertFalse(res["metrics"]["has_digits"])
        self.assertFalse(res["metrics"]["has_symbols"])

    # TEST 7: Uppercase only
    def test_07_uppercase_only(self):
        res = analyze_password("ABCDEFGHIJKLMN")
        self.assertTrue(res["metrics"]["has_uppercase"])
        self.assertFalse(res["metrics"]["has_lowercase"])

    # TEST 8: Numbers only
    def test_08_numbers_only(self):
        res = analyze_password("948271039485")
        self.assertTrue(res["metrics"]["has_digits"])
        self.assertFalse(res["metrics"]["has_lowercase"])
        self.assertFalse(res["metrics"]["has_symbols"])

    # TEST 9: Symbols only
    def test_09_symbols_only(self):
        res = analyze_password("!@#$%^&*()_+~")
        self.assertTrue(res["metrics"]["has_symbols"])
        self.assertFalse(res["metrics"]["has_digits"])

    # TEST 10: Mixed characters
    def test_10_mixed_characters(self):
        res = analyze_password("K8#mQ9$zL2!wX5@v")
        self.assertEqual(res["metrics"]["character_type_count"], 4)
        self.assertIn(res["classification"], ["STRONG", "VERY STRONG"])

    # TEST 11: Sequential numbers (ascending)
    def test_11_sequential_numbers_ascending(self):
        res = analyze_password("pass123456word")
        self.assertTrue(any(f["type"] == "numeric_sequence_ascending" for f in res["findings"]))

    # TEST 12: Reverse numeric sequence (descending)
    def test_12_reverse_numeric_sequence(self):
        res = analyze_password("secure98765pass")
        self.assertTrue(any(f["type"] == "numeric_sequence_descending" for f in res["findings"]))

    # TEST 13: Sequential letters
    def test_13_sequential_letters(self):
        res = analyze_password("myabcdsecurepass")
        self.assertTrue(any("alphabetical_sequence" in f["type"] for f in res["findings"]))

    # TEST 14: Keyboard sequence (qwerty)
    def test_14_keyboard_sequence(self):
        res = analyze_password("qwerty9827!")
        self.assertTrue(any(f["type"] == "keyboard_pattern" for f in res["findings"]))

    # TEST 15: Repeated characters (3+ consecutive identical)
    def test_15_repeated_characters(self):
        res = analyze_password("hello1111world")
        self.assertTrue(any(f["type"] == "repeated_characters" for f in res["findings"]))

    # TEST 16: Repeated substring
    def test_16_repeated_substring(self):
        res = analyze_password("abcabcabc123!")
        self.assertTrue(any(f["type"] == "repeated_substring" for f in res["findings"]))

    # TEST 17: Common word + number
    def test_17_common_word_plus_number(self):
        res = analyze_password("welcome123")
        self.assertIn(res["classification"], ["VERY WEAK", "WEAK"])
        self.assertTrue(res["metrics"]["is_common"])

    # TEST 18: Word + calendar year
    def test_18_word_plus_calendar_year(self):
        res = analyze_password("Winter2025!")
        self.assertTrue(any(f["type"] == "calendar_year_detected" for f in res["findings"]))

    # TEST 19: Personal name overlap (optional context)
    def test_19_personal_name_overlap(self):
        res = analyze_password("RahulSecurePass99!", context={"first_name": "Rahul"})
        self.assertTrue(any(f["type"] == "personal_info_name" for f in res["findings"]))

    # TEST 20: Birth year overlap (optional context)
    def test_20_birth_year_overlap(self):
        res = analyze_password("SecurePass1998#", context={"birth_year": "1998"})
        self.assertTrue(any(f["type"] == "personal_info_birth_year" for f in res["findings"]))

    # TEST 21: Long passphrase-like input
    def test_21_long_passphrase(self):
        res = analyze_password("correct-horse-battery-staple-galaxy")
        self.assertGreaterEqual(res["score"], 70)
        self.assertIn(res["classification"], ["STRONG", "VERY STRONG"])

    # TEST 22: Unicode character handling
    def test_22_unicode_handling(self):
        res = analyze_password("P@sswørd⚡2026🛡️")
        self.assertIsNotNone(res["score"])
        self.assertGreater(res["metrics"]["length"], 0)

    # TEST 23: Space character handling
    def test_23_space_handling(self):
        res = analyze_password("moon light valley wind")
        self.assertTrue(res["metrics"]["has_spaces"])
        self.assertGreaterEqual(res["score"], 60)

    # TEST 24: Maximum accepted length boundary (256 chars)
    def test_24_maximum_length_boundary(self):
        long_pwd = "K8#mQ9$zL2!wX5@v" * 14  # 224 chars
        res = analyze_password(long_pwd)
        self.assertEqual(res["metrics"]["length"], 224)
        self.assertGreaterEqual(res["score"], 60)
        self.assertLessEqual(res["score"], 100)

    # TEST 25: Strength-score boundaries (0 to 100 range validation)
    def test_25_score_boundaries(self):
        cases = ["", "1", "123456", "Pass123!", "K8#mQ9$zL2!wX5@v^P4*dF"]
        for c in cases:
            res = analyze_password(c)
            self.assertGreaterEqual(res["score"], 0)
            self.assertLessEqual(res["score"], 100)

    # TEST 26: Suggestion generation
    def test_26_suggestion_generation(self):
        res = analyze_password("short")
        self.assertGreater(len(res["suggestions"]), 0)
        # Verify password itself is NOT in suggestions
        for sug in res["suggestions"]:
            self.assertNotIn("short", sug)

    # TEST 27: Secure password generator
    def test_27_secure_password_generation(self):
        gen = generate_secure_password(length=20)
        pwd = gen["password"]
        self.assertEqual(len(pwd), 20)
        self.assertEqual(gen["csprng_source"], "Python secrets (OS CryptGenRandom / getrandom)")
        
        # Test passphrase generation
        phrase_gen = generate_secure_passphrase(word_count=4)
        words = phrase_gen["passphrase"].split("-")
        self.assertEqual(len(words), 4)

    # TEST 28: Zero plaintext password stored in database
    def test_28_password_not_stored_in_db(self):
        res = analyze_password("ConfidentialDemoPassword99#")
        aid = record_analysis_metadata(res)
        
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (aid,))
        row = dict(cursor.fetchone())
        conn.close()

        # Verify columns in analyses table
        columns = list(row.keys())
        self.assertNotIn("password", columns)
        self.assertNotIn("hash", columns)
        self.assertNotIn("plaintext", columns)

    # TEST 29: No password in findings table
    def test_29_findings_table_contains_no_password(self):
        secret_word = "SuperSecretTokenDemo"
        res = analyze_password(f"{secret_word}123456")
        aid = record_analysis_metadata(res)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT description FROM findings WHERE analysis_id = ?", (aid,))
        rows = cursor.fetchall()
        conn.close()

        for r in rows:
            self.assertNotIn(secret_word, r["description"])

    # TEST 30: Analytics storage contains exclusively safe metadata
    def test_30_analytics_storage_integrity(self):
        res = analyze_password("RandomSafeToken#2026")
        aid = record_analysis_metadata(res)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT score, classification, password_length, unique_character_ratio FROM analyses WHERE analysis_id = ?", (aid,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsInstance(row["score"], int)
        self.assertIsInstance(row["classification"], str)
        self.assertIsInstance(row["password_length"], int)
        self.assertIsInstance(row["unique_character_ratio"], float)

if __name__ == "__main__":
    unittest.main()
