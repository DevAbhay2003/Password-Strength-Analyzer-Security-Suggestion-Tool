"""
Common Password Checker Module
Compares passwords against a safe local dictionary of common/default credentials.
Performs exact and normalized root matching without querying remote services or storing input.
"""

import os
import re

COMMON_PASSWORDS_CACHE = set()

def load_common_passwords() -> set:
    """
    Loads common passwords from the local safe data file.
    Caches the list in memory for fast local lookups.
    """
    global COMMON_PASSWORDS_CACHE
    if COMMON_PASSWORDS_CACHE:
        return COMMON_PASSWORDS_CACHE

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    data_path = os.path.join(base_dir, "data", "common_passwords.txt")
    
    passwords = set()
    if os.path.exists(data_path):
        with open(data_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    passwords.add(line.lower())
    
    COMMON_PASSWORDS_CACHE = passwords
    return COMMON_PASSWORDS_CACHE

def is_common_password(password: str) -> dict:
    """
    Checks if the password is in the common password list,
    either as an exact match or as a normalized root.
    """
    if not password:
        return {
            "is_common": False,
            "match_type": "none",
            "message": "Empty password."
        }

    common_set = load_common_passwords()
    normalized = password.strip().lower()

    # 1. Exact match
    if normalized in common_set:
        return {
            "is_common": True,
            "match_type": "exact",
            "message": "Your password matches a commonly used password pattern and should not be used.",
            "penalty": 55,
            "severity": "CRITICAL"
        }

    # 2. Check root pattern by stripping trailing digits and common symbols
    # e.g., 'password123!' -> root 'password'
    root_match = re.match(r"^([a-zA-Z]+)([\d!@#$%^&*()_+=\-`~\[\]{};':\",.<>/?]+)$", password)
    if root_match:
        root_word = root_match.group(1).lower()
        if root_word in common_set and len(root_word) >= 4:
            return {
                "is_common": True,
                "match_type": "root_pattern",
                "message": (
                    "Your password is built from a commonly used dictionary word with predictable "
                    "appended digits or symbols, making it highly vulnerable to hybrid dictionary attacks."
                ),
                "penalty": 40,
                "severity": "HIGH"
            }

    # 3. Leetspeak simple normalization (e.g., p@ssw0rd -> password)
    leetspeak_map = str.maketrans({'@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's', '5': 's', '!': 'i'})
    de_leet = normalized.translate(leetspeak_map)
    if de_leet in common_set:
        return {
            "is_common": True,
            "match_type": "leetspeak_variation",
            "message": (
                "Your password appears to be a basic leetspeak or character-substitution variation of a common password. "
                "Attackers use automated rule-engines that reverse these substitutions instantly."
            ),
            "penalty": 45,
            "severity": "HIGH"
        }

    return {
        "is_common": False,
        "match_type": "none",
        "message": "Password does not match known common credential lists in local database.",
        "penalty": 0,
        "severity": "LOW"
    }
