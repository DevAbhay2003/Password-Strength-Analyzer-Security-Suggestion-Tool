"""
Pattern Detector Module
Detects sequential characters, keyboard walks, repeated characters/substrings,
predictable word+number structures, date/year patterns, and optional personal context overlaps.
"""

import re
from typing import Optional, Dict, Any, List

KEYBOARD_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    "ASDFGHJKL:\"",
    "ZXCVBNM<>?"
]

KEYBOARD_COLUMNS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/"
]

def detect_sequences(password: str) -> List[Dict[str, Any]]:
    """
    Detects ascending and descending sequential numbers and letters of length >= 3.
    Examples: '1234', '9876', 'abcd', 'dcba'.
    """
    findings = []
    if len(password) < 3:
        return findings

    lower = password.lower()
    
    # Check numeric sequences
    num_asc_matches = []
    num_desc_matches = []
    
    for i in range(len(lower) - 2):
        chunk = lower[i:i+3]
        if chunk.isdigit():
            c0, c1, c2 = ord(chunk[0]), ord(chunk[1]), ord(chunk[2])
            if c1 == c0 + 1 and c2 == c1 + 1:
                num_asc_matches.append(chunk)
            elif c1 == c0 - 1 and c2 == c1 - 1:
                num_desc_matches.append(chunk)
                
    if num_asc_matches:
        findings.append({
            "type": "numeric_sequence_ascending",
            "severity": "MEDIUM",
            "penalty": 15,
            "description": "Contains ascending numeric sequence (e.g., consecutive digits like '123').",
            "suggestion": "Avoid sequential numbers; replace them with non-contiguous or random values."
        })
    if num_desc_matches:
        findings.append({
            "type": "numeric_sequence_descending",
            "severity": "MEDIUM",
            "penalty": 15,
            "description": "Contains descending numeric sequence (e.g., consecutive digits like '987').",
            "suggestion": "Avoid reverse sequential digits as attackers routinely scan for counting sequences."
        })

    # Check alphabetical sequences
    alpha_asc = []
    alpha_desc = []
    for i in range(len(lower) - 2):
        chunk = lower[i:i+3]
        if chunk.isalpha():
            c0, c1, c2 = ord(chunk[0]), ord(chunk[1]), ord(chunk[2])
            if c1 == c0 + 1 and c2 == c1 + 1:
                alpha_asc.append(chunk)
            elif c1 == c0 - 1 and c2 == c1 - 1:
                alpha_desc.append(chunk)

    if alpha_asc:
        findings.append({
            "type": "alphabetical_sequence_ascending",
            "severity": "MEDIUM",
            "penalty": 12,
            "description": "Contains ascending alphabetical sequence (e.g., 'abc').",
            "suggestion": "Remove alphabetical sequences like 'abc' or 'xyz'."
        })
    if alpha_desc:
        findings.append({
            "type": "alphabetical_sequence_descending",
            "severity": "MEDIUM",
            "penalty": 12,
            "description": "Contains descending alphabetical sequence (e.g., 'cba').",
            "suggestion": "Avoid reverse alphabetic sequences."
        })

    return findings

def detect_keyboard_patterns(password: str) -> List[Dict[str, Any]]:
    """
    Detects horizontal and vertical keyboard walks on standard QWERTY layouts.
    Examples: 'qwerty', 'asdf', 'zxcv', '1qaz', 'poiuy'.
    """
    findings = []
    if len(password) < 4:
        return findings

    lower = password.lower()
    detected_walks = set()

    # Horizontal walks
    for row in KEYBOARD_ROWS:
        row_clean = row.lower()
        # forward
        for i in range(len(row_clean) - 3):
            sub = row_clean[i:i+4]
            if sub in lower:
                detected_walks.add(sub)
        # reverse
        rev_row = row_clean[::-1]
        for i in range(len(rev_row) - 3):
            sub = rev_row[i:i+4]
            if sub in lower:
                detected_walks.add(sub)

    # Vertical column walks
    for col in KEYBOARD_COLUMNS:
        col_clean = col.lower()
        for i in range(len(col_clean) - 2):
            sub = col_clean[i:i+3]
            if sub in lower:
                detected_walks.add(sub)
        rev_col = col_clean[::-1]
        for i in range(len(rev_col) - 2):
            sub = rev_col[i:i+3]
            if sub in lower:
                detected_walks.add(sub)

    if detected_walks:
        findings.append({
            "type": "keyboard_pattern",
            "severity": "HIGH",
            "penalty": 18,
            "description": "Contains keyboard walk pattern (e.g., adjacent keyboard sequences like 'qwerty' or 'asdf').",
            "suggestion": "Avoid geometric keyboard walks; attackers use specialized keyboard-walk dictionaries."
        })

    return findings

def detect_repetition(password: str) -> List[Dict[str, Any]]:
    """
    Detects repeated single characters (>= 3 consecutive, e.g., 'aaa')
    and repeated multi-character substrings (e.g., 'ababab', '123123').
    """
    findings = []
    if not password:
        return findings

    lower = password.lower()

    # Consecutive identical characters (e.g., 'aaaa' or '1111')
    consecutive_match = re.search(r"(.)\1{2,}", password)
    if consecutive_match:
        findings.append({
            "type": "repeated_characters",
            "severity": "HIGH",
            "penalty": 15,
            "description": f"Contains repeated characters in succession ('{consecutive_match.group(1)}' repeats {len(consecutive_match.group(0))} times).",
            "suggestion": "Avoid repeating identical characters consecutively."
        })

    # Repeated substring patterns (e.g., 'abcabc', '121212', 'passpass')
    # Match patterns of length 2 to 6 repeating 2 or more times
    repeated_substring = False
    for pat_len in range(2, min(7, len(lower) // 2 + 1)):
        for i in range(len(lower) - 2 * pat_len + 1):
            pattern = lower[i:i+pat_len]
            rest = lower[i+pat_len:]
            if rest.startswith(pattern):
                repeated_substring = True
                break
        if repeated_substring:
            break

    if repeated_substring:
        findings.append({
            "type": "repeated_substring",
            "severity": "MEDIUM",
            "penalty": 15,
            "description": "Contains repeating multi-character sequences (e.g., 'abab' or repetitive word fragments).",
            "suggestion": "Eliminate repeating syllables, blocks, or loops."
        })

    return findings

def detect_predictable_structure(password: str) -> List[Dict[str, Any]]:
    """
    Detects predictable word + number or year combinations, e.g.,
    'Welcome2026!', 'Summer2025', 'Password1234', 'Admin2024'.
    """
    findings = []
    if not password:
        return findings

    # Year detection (1950 - 2099)
    year_match = re.search(r"(19[5-9]\d|20[0-9]\d)", password)
    if year_match:
        findings.append({
            "type": "calendar_year_detected",
            "severity": "MEDIUM",
            "penalty": 12,
            "description": f"Contains a 4-digit calendar year pattern ({year_match.group(0)}).",
            "suggestion": "Avoid including current or historical calendar years, which are standard components of wordlist rules."
        })

    # Word + trailing simple sequence or digits: Capitalized word + digits + optional symbol
    # e.g., 'Password123!', 'Welcome1'
    structure_match = re.match(r"^[A-Z][a-z]{3,}\d{1,4}[!@#$%^&*()_+=\-`~\[\]{};':\",.<>/?]?$", password)
    if structure_match:
        findings.append({
            "type": "predictable_grammar_structure",
            "severity": "HIGH",
            "penalty": 15,
            "description": "Follows the highly predictable template: [Capitalized Word] + [Digits] + [Symbol].",
            "suggestion": "Attackers specifically target the 'TitleCase + number + symbol' structure; break this predictable order."
        })

    return findings

def detect_personal_context(password: str, context: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Checks if password overlaps with user-provided voluntary context info
    (First Name, Birth Year, Organization/School name).
    Processes everything locally in memory without persistence.
    """
    findings = []
    if not context or not password:
        return findings

    pwd_lower = password.lower()

    # Check first name
    first_name = context.get("first_name", "").strip().lower()
    if first_name and len(first_name) >= 3 and first_name in pwd_lower:
        findings.append({
            "type": "personal_info_name",
            "severity": "CRITICAL",
            "penalty": 25,
            "description": "Password contains elements of your provided first name.",
            "suggestion": "Never use personal names in passwords; targeted attacks leverage OSINT and social media."
        })

    # Check birth year
    birth_year = str(context.get("birth_year", "")).strip()
    if birth_year and len(birth_year) == 4 and birth_year in pwd_lower:
        findings.append({
            "type": "personal_info_birth_year",
            "severity": "CRITICAL",
            "penalty": 25,
            "description": f"Password contains your provided birth year ({birth_year}).",
            "suggestion": "Birth years are publicly discoverable and heavily penalized in credential attacks."
        })

    # Check organization / university name
    org_name = context.get("org_name", "").strip().lower()
    if org_name and len(org_name) >= 3 and org_name in pwd_lower:
        findings.append({
            "type": "personal_info_organization",
            "severity": "HIGH",
            "penalty": 20,
            "description": "Password contains your company or educational institution name.",
            "suggestion": "Company names, internal project names, and campus acronyms are routinely guessed by attackers."
        })

    return findings

def detect_all_patterns(password: str, context: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Aggregates all pattern analyses and returns total penalty and findings list.
    """
    findings: List[Dict[str, Any]] = []
    
    findings.extend(detect_sequences(password))
    findings.extend(detect_keyboard_patterns(password))
    findings.extend(detect_repetition(password))
    findings.extend(detect_predictable_structure(password))
    if context:
        findings.extend(detect_personal_context(password, context))

    total_penalty = sum(f.get("penalty", 0) for f in findings)
    
    return {
        "findings": findings,
        "total_penalty": total_penalty,
        "pattern_count": len(findings)
    }
