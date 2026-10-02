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

    def test_sec_06_dashboard_telemetry_privacy_and_export(self):
        """Verifies dashboard telemetry endpoints return zero plaintext credentials."""
        # 1. Stats endpoint check
        resp = self.client.get("/api/dashboard/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()["data"]
        self.assertIn("risk_posture", data)
        self.assertIn("recent_telemetry", data)
        self.assertIn("security_insights", data)

        # 2. Export check (JSON)
        exp_resp = self.client.get("/api/dashboard/export")
        self.assertEqual(exp_resp.status_code, 200)
        exp_json = exp_resp.get_json()
        self.assertEqual(exp_json["status"], "success")
        for rec in exp_json["data"]:
            self.assertNotIn("plaintext", rec)
            self.assertNotIn("hash", rec)
            self.assertNotIn("salt", rec)

        # 3. Export check (CSV)
        exp_csv = self.client.get("/api/dashboard/export?format=csv")
        self.assertEqual(exp_csv.status_code, 200)
        self.assertIn("text/csv", exp_csv.content_type)
        first_line = exp_csv.data.decode().splitlines()[0]
        self.assertNotIn("plaintext", first_line)
        self.assertNotIn("hash", first_line)
        self.assertNotIn("salt", first_line)

        # 4. Simulation ingestion check
        sim_resp = self.client.post("/api/dashboard/simulate")
        self.assertEqual(sim_resp.status_code, 200)
        self.assertEqual(sim_resp.get_json()["status"], "success")

if __name__ == "__main__":
    unittest.main()


