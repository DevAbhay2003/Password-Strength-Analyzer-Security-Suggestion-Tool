"""
Character Analysis Module
Examines character composition, diversity, and uniqueness.
Calculates character pools, unique ratios, and explains why composition rules alone
do not guarantee unpredictable passwords.
"""

import string

def analyze_characters(password: str) -> dict:
    """
    Analyzes the composition of characters in the password.
    Returns counts for uppercase, lowercase, digits, symbols, spaces,
    unique character count, type diversity, and calculated uniqueness ratio.
    """
    length = len(password)
    if length == 0:
        return {
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digits": False,
            "has_symbols": False,
            "has_spaces": False,
            "lowercase_count": 0,
            "uppercase_count": 0,
            "digit_count": 0,
            "symbol_count": 0,
            "space_count": 0,
            "unique_character_count": 0,
            "character_type_count": 0,
            "unique_character_ratio": 0.0,
            "estimated_pool_size": 0,
            "diversity_points": 0,
            "uniqueness_points": 0,
            "summary": "No characters present."
        }

    lowercase_count = sum(1 for c in password if c.islower())
    uppercase_count = sum(1 for c in password if c.isupper())
    digit_count = sum(1 for c in password if c.isdigit())
    space_count = sum(1 for c in password if c.isspace())
    # Symbols are printable non-alphanumeric and non-space
    symbol_count = sum(1 for c in password if not c.isalnum() and not c.isspace())

    has_lowercase = lowercase_count > 0
    has_uppercase = uppercase_count > 0
    has_digits = digit_count > 0
    has_symbols = symbol_count > 0
    has_spaces = space_count > 0

    # Number of character classes present (out of 4 core classes)
    types_present = sum([has_lowercase, has_uppercase, has_digits, has_symbols])
    
    unique_chars = len(set(password))
    unique_ratio = round(unique_chars / length, 3)

    # Estimate theoretical character pool size N
    pool_size = 0
    if has_lowercase:
        pool_size += 26
    if has_uppercase:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33
    if has_spaces:
        pool_size += 1

    # Diversity points (up to 15)
    # 1 type = 3 pts, 2 types = 6 pts, 3 types = 10 pts, 4 types = 15 pts
    type_score_map = {0: 0, 1: 3, 2: 7, 3: 11, 4: 15}
    diversity_points = type_score_map.get(types_present, 0)

    # Uniqueness points (up to 10)
    # High repetition lowers uniqueness ratio
    if unique_ratio >= 0.8:
        uniqueness_points = 10
    elif unique_ratio >= 0.6:
        uniqueness_points = 7
    elif unique_ratio >= 0.4:
        uniqueness_points = 4
    else:
        uniqueness_points = 1

    summary = (
        f"Contains {types_present} of 4 character classes with {unique_chars} unique "
        f"characters across {length} total characters (uniqueness ratio: {unique_ratio:.2f})."
    )

    return {
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "has_spaces": has_spaces,
        "lowercase_count": lowercase_count,
        "uppercase_count": uppercase_count,
        "digit_count": digit_count,
        "symbol_count": symbol_count,
        "space_count": space_count,
        "unique_character_count": unique_chars,
        "character_type_count": types_present,
        "unique_character_ratio": unique_ratio,
        "estimated_pool_size": pool_size,
        "diversity_points": diversity_points,
        "uniqueness_points": uniqueness_points,
        "summary": summary,
        "educational_warning": (
            "Composition rules (requiring upper, lower, digit, and symbol) can give false "
            "confidence: e.g., 'Password123!' meets all 4 requirements but follows standard "
            "human substitutions and dictionary patterns easily exploited by rule-based attacks."
        )
    }
