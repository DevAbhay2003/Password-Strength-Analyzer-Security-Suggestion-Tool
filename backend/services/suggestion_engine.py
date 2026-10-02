"""
Suggestion Engine Module
Generates granular, actionable, context-aware security suggestions.
Never echoes the user's plaintext password in recommendations.
Offers defensive advice on passphrases, password managers, and MFA.
"""

from typing import List, Dict, Any

def generate_suggestions(
    length_metrics: dict,
    char_metrics: dict,
    common_metrics: dict,
    pattern_metrics: dict,
    score_metrics: dict
) -> List[str]:
    """
    Produces actionable, defensive security recommendations tailored to specific findings.
    Ensures zero plaintext password echoing.
    """
    suggestions = []
    
    length = length_metrics.get("length", 0)
    score = score_metrics.get("score", 0)

    # 1. Length-specific recommendations
    if length < 8:
        suggestions.append(
            "CRITICAL: Increase password length immediately to at least 12–16 characters. "
            "Passwords under 8 characters can be systematically cracked in minutes using modern offline GPU clusters."
        )
    elif 8 <= length < 12:
        suggestions.append(
            "Consider extending your password to 14–16+ characters or switching to a multi-word passphrase for exponential keyspace growth."
        )

    # 2. Common password findings
    if common_metrics.get("is_common", False):
        suggestions.append(
            "REPLACE IMMEDIATELY: Your password matches or is derived from commonly used/leaked credentials. "
            "Attackers prioritize these in dictionary and credential-stuffing attacks."
        )

    # 3. Pattern-specific findings
    for finding in pattern_metrics.get("findings", []):
        f_type = finding.get("type", "")
        f_sug = finding.get("suggestion", "")
        if f_sug and f_sug not in suggestions:
            suggestions.append(f_sug)

    # 4. Character diversity & composition notes
    types_count = char_metrics.get("character_type_count", 0)
    if types_count < 3 and length < 16:
        suggestions.append(
            "Incorporate a wider mix of characters (lowercase, uppercase, numbers, and symbols) to expand the theoretical search space."
        )

    unique_ratio = char_metrics.get("unique_character_ratio", 1.0)
    if unique_ratio < 0.6 and length >= 6:
        suggestions.append(
            "Reduce identical and repeating characters. High repetition drastically shrinks effective entropy despite overall length."
        )

    # 5. Strategic Defensive Recommendations (always provide best practices)
    if score < 70:
        suggestions.append(
            "Passphrase alternative: Try 4 or more random, unrelated words (e.g., 'cactus-orbit-velvet-frost'). "
            "Passphrases provide high length and memorability without requiring awkward substitutions."
        )

    suggestions.append(
        "Credential Hygiene: Never reuse this password across other accounts or services. "
        "A breach in one third-party service exposes every account sharing the same credential."
    )

    suggestions.append(
        "Password Manager: Use a reputable password manager (e.g., Bitwarden, 1Password) to generate, "
        "encrypt, and autofill 16–24+ character unique passwords."
    )

    suggestions.append(
        "Defense-in-Depth: Always enable Multi-Factor Authentication (MFA/2FA) such as authenticator apps or FIDO2/WebAuthn hardware keys."
    )

    return suggestions
