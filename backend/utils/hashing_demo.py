"""
Password Hashing Demonstration Module
Educational utility illustrating the difference between plaintext, fast cryptographic hashes,
and modern slow, salted key-stretching functions (PBKDF2, scrypt, Argon2id).
Strictly operates on synthetic demo inputs. Does NOT integrate with live user input persistence.
"""

import os
import time
import hmac
import hashlib
import secrets
from typing import Dict, Any, Tuple

def demo_fast_vs_slow_hashing(sample_password: str = "DemoSyntheticPassphrase2026!") -> Dict[str, Any]:
    """
    Demonstrates why fast hashes (MD5, SHA-256) are dangerous for password storage
    while key-stretching functions (PBKDF2, scrypt) defend against GPU-accelerated brute force.
    """
    pwd_bytes = sample_password.encode("utf-8")
    salt = secrets.token_bytes(16)

    # 1. Fast Unsalted Hash (MD5 - Insecure legacy)
    t0 = time.perf_counter()
    fast_md5 = hashlib.md5(pwd_bytes).hexdigest()
    t_md5 = round((time.perf_counter() - t0) * 1000, 4)

    # 2. Fast Unsalted Hash (SHA-256 - Designed for file integrity, NOT passwords)
    t0 = time.perf_counter()
    fast_sha256 = hashlib.sha256(pwd_bytes).hexdigest()
    t_sha256 = round((time.perf_counter() - t0) * 1000, 4)

    # 3. Modern Key-Stretching: PBKDF2-HMAC-SHA256 (600,000 iterations per OWASP)
    iterations = 600000
    t0 = time.perf_counter()
    pbkdf2_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations)
    t_pbkdf2 = round((time.perf_counter() - t0) * 1000, 2)

    # 4. Modern Memory-Hard Function: scrypt (N=2^14, r=8, p=1)
    t0 = time.perf_counter()
    scrypt_hash = hashlib.scrypt(pwd_bytes, salt=salt, n=16384, r=8, p=1)
    t_scrypt = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "sample_input_description": "Synthetic demo password (masked)",
        "salt_hex": salt.hex(),
        "benchmarks": [
            {
                "algorithm": "MD5 (Fast, Unsalted, Cryptographically Broken)",
                "category": "INSECURE",
                "execution_time_ms": t_md5,
                "attacker_advantage": "Trillions of guesses per second on consumer GPUs. Vulnerable to precomputed Rainbow Tables.",
                "hash_sample": fast_md5
            },
            {
                "algorithm": "SHA-256 (Fast, Unsalted, General Purpose)",
                "category": "INSECURE FOR PASSWORDS",
                "execution_time_ms": t_sha256,
                "attacker_advantage": "Billions of guesses per second on modern hardware. Fast hashes maximize attacker speed.",
                "hash_sample": fast_sha256
            },
            {
                "algorithm": f"PBKDF2-HMAC-SHA256 ({iterations:,} iterations)",
                "category": "SECURE KEY-STRETCHING",
                "execution_time_ms": t_pbkdf2,
                "attacker_advantage": "CPU-bound work factor forces attackers to repeat 600k rounds per single password guess.",
                "hash_sample": pbkdf2_hash.hex()[:32] + "..."
            },
            {
                "algorithm": "scrypt (Memory-hard key derivation)",
                "category": "MODERN MEMORY-HARD",
                "execution_time_ms": t_scrypt,
                "attacker_advantage": "Requires dedicated RAM per attempt, neutralizing ASIC and GPU mass-parallelization advantages.",
                "hash_sample": scrypt_hash.hex()[:32] + "..."
            }
        ],
        "key_takeaways": [
            "Plaintext passwords must NEVER be saved to databases, logs, or persistent caches.",
            "Salts ensure that two users with identical passwords produce completely different hash outputs.",
            "Work factors (iterations/memory cost) penalize the attacker's speed while remaining imperceptible to a single legitimate user login.",
            "Argon2id and scrypt are memory-hard functions recommended by modern security standards (OWASP, NIST)."
        ]
    }

def hash_password(password: str, iterations: int = 200000) -> str:
    """
    Standard PBKDF2-HMAC-SHA256 password hashing implementation.
    Format: algorithm$iterations$salt_hex$hash_hex
    """
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a stored PBKDF2 hash using
    constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    """
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])

        computed_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        # Constant-time comparison defends against side-channel timing leaks
        return hmac.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False
