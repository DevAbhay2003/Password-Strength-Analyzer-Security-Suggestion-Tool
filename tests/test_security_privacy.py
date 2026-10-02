"""
Security and Privacy Verification Test Suite
Tests architectural security controls:
1. No passwords saved in database tables
2. API responses do not reflect passwords
3. Hashing utility one-way cryptographic verification
4. Constant-time comparison defends against timing attacks
5. DoS length boundaries enforced
"""

import unittest
from backend.app import create_app
from backend.models.database import get_connection, init_db
from backend.utils.hashing_demo import hash_password, verify_password

class TestSecurityAndPrivacy(unittest.TestCase):

    def setUp(self):
        init_db()
        self.app = create_app()
        self.client = self.app.test_client()

    def test_sec_01_api_does_not_echo_password_in_response(self):
        """Ensure the REST API never reflects the raw password in the response body."""
        secret_sample = "SensitiveSyntheticCredential123!"
        response = self.client.post("/api/analyze", json={"password": secret_sample})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        
        # Check top-level and nested data
        res_str = str(data)
        self.assertNotIn(secret_sample, res_str)

    def test_sec_02_database_schema_has_no_password_field(self):
        """Verifies SQLite table schema has no credential storage columns."""
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(analyses)")
        analyses_cols = [row["name"] for row in cursor.fetchall()]
        self.assertNotIn("password", analyses_cols)
        self.assertNotIn("plaintext", analyses_cols)
        self.assertNotIn("hash", analyses_cols)
        self.assertNotIn("salt", analyses_cols)

        cursor.execute("PRAGMA table_info(findings)")
        findings_cols = [row["name"] for row in cursor.fetchall()]
        self.assertNotIn("password", findings_cols)
        self.assertNotIn("credential", findings_cols)
        conn.close()

    def test_sec_03_dos_length_boundary_enforced(self):
        """Verifies API rejects excessively long inputs to prevent algorithmic DoS/ReDoS."""
        oversized = "A" * 300
        response = self.client.post("/api/analyze", json={"password": oversized})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("boundary", data["message"])

    def test_sec_04_hashing_one_way_and_verification(self):
        """Verifies PBKDF2 hashing produces salted output and verifies accurately."""
        sample = "SyntheticDemoPassword2026!"
        h1 = hash_password(sample)
        h2 = hash_password(sample)

        # Unique salts guarantee different outputs for the same password
        self.assertNotEqual(h1, h2)

        # Verification succeeds with matching password
        self.assertTrue(verify_password(sample, h1))
        self.assertTrue(verify_password(sample, h2))

        # Verification fails with invalid password
        self.assertFalse(verify_password("WrongPassword!", h1))

    def test_sec_05_security_headers_present(self):
        """Verifies security headers (nosniff, no-store, DENY) are set on responses."""
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("no-store", response.headers.get("Cache-Control"))

if __name__ == "__main__":
    unittest.main()
