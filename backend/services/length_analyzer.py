"""
Length Analyzer Module
Evaluates password length and maps it to educational evaluation bands.
Explains why length is necessary but not sufficient for password security.
"""

def analyze_length(password: str) -> dict:
    """
    Analyzes password length and returns metrics, educational band, and evaluation note.
    
    Educational bands:
    - Less than 8: Very short (high vulnerability to brute force)
    - 8–11: Short (minimum legacy boundary, vulnerable to modern hash-rate cracking)
    - 12–15: Better length (standard industry baseline for human credentials)
    - 16+: Strong length contribution (substantial resistance against offline attacks)
    """
    length = len(password)
    
    if length == 0:
        band = "Empty"
        points = 0
        message = "No password provided."
        recommendation = "Provide a password with at least 12–16 characters."
    elif length < 8:
        band = "Very Short"
        points = 5
        message = f"Length ({length} chars) is critically short. Vulnerable to fast brute-force searches."
        recommendation = "Increase length to at least 12 characters, preferably 16+."
    elif 8 <= length <= 11:
        band = "Short"
        points = 15
        message = f"Length ({length} chars) meets basic legacy criteria but remains vulnerable to offline cracking."
        recommendation = "Aim for 12–16+ characters or consider a multi-word passphrase."
    elif 12 <= length <= 15:
        band = "Better Length"
        points = 28
        message = f"Length ({length} chars) meets modern minimum defense standards."
        recommendation = "A length of 16+ or a 4-word passphrase provides even higher resilience."
    else:
        band = "Strong Length"
        points = 35
        message = f"Length ({length} chars) makes a significant positive contribution to keyspace size."
        recommendation = "Excellent length. Ensure characters are unpredictable and pattern-free."

    return {
        "length": length,
        "band": band,
        "points": points,
        "message": message,
        "recommendation": recommendation,
        "educational_note": (
            "Length significantly expands theoretical search space (keyspace), but length alone "
            "does not guarantee safety if the sequence is repetitive (e.g., 'aaaaaaaaaaaaaaaa')."
        )
    }
