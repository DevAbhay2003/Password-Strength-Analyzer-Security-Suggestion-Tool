"""
Entropy Estimator Module
Calculates theoretical Shannon-style information entropy and realistic effective entropy.
Explains the mathematical concept, search space calculation, and the critical limitation:
humans do not generate passwords through uniform random sampling.
"""

import math

def estimate_theoretical_entropy(length: int, pool_size: int) -> float:
    """
    Calculates theoretical entropy: H = L * log2(N)
    where L is length and N is the character pool size.
    Assumes each character was selected uniformly and independently at random.
    """
    if length <= 0 or pool_size <= 0:
        return 0.0
    return round(length * math.log2(pool_size), 2)

def calculate_effective_entropy(password: str, theoretical_entropy: float, pattern_count: int, is_common: bool) -> float:
    """
    Adjusts theoretical entropy downwards based on observed non-random structures,
    repetitions, and dictionary presence to better reflect realistic guessing resistance.
    """
    if theoretical_entropy <= 0:
        return 0.0

    effective = theoretical_entropy

    # Severe penalty if based on common dictionary entry
    if is_common:
        # Common passwords have close to 0-10 bits of real entropy because they are in top lists
        effective = min(effective, 10.0)
        return round(effective, 2)

    # Discount for each detected human pattern (sequences, keyboard walks, repeated substrings)
    discount_per_pattern = 12.0
    effective -= (pattern_count * discount_per_pattern)

    # Repeated characters discount
    if len(password) > 0:
        unique_ratio = len(set(password)) / len(password)
        if unique_ratio < 0.6:
            effective *= (unique_ratio / 0.6)

    return max(0.0, round(effective, 2))

def analyze_entropy(password: str, char_metrics: dict, pattern_count: int, is_common: bool) -> dict:
    """
    Comprehensive entropy analysis returning theoretical bits, effective bits,
    theoretical keyspace search space, and educational explanations.
    """
    length = len(password)
    pool_size = char_metrics.get("estimated_pool_size", 0)

    theoretical_bits = estimate_theoretical_entropy(length, pool_size)
    effective_bits = calculate_effective_entropy(password, theoretical_bits, pattern_count, is_common)

    # Qualitative resistance categories (educational estimation only)
    if effective_bits < 28:
        strength_tier = "Very Low Resistance"
        assessment = "Vulnerable to immediate automated offline search or top wordlist enumeration."
    elif effective_bits < 45:
        strength_tier = "Low Resistance"
        assessment = "Feasible to search with modest computational resources in offline hash attacks."
    elif effective_bits < 65:
        strength_tier = "Moderate Resistance"
        assessment = "Good baseline against casual attacks; may be susceptible to high-budget targeted cracking clusters."
    elif effective_bits < 85:
        strength_tier = "High Resistance"
        assessment = "Very strong mathematical search space for modern authentication scenarios."
    else:
        strength_tier = "Extremely High Resistance"
        assessment = "Exponential search space exceeding feasibility for current offline brute-force hardware."

    # Search space size
    keyspace_notation = f"2^{theoretical_bits:.1f} combinations" if theoretical_bits > 0 else "0 combinations"

    return {
        "theoretical_bits": theoretical_bits,
        "effective_bits": effective_bits,
        "pool_size": pool_size,
        "search_space_notation": keyspace_notation,
        "strength_tier": strength_tier,
        "assessment": assessment,
        "educational_explanation": (
            "Password entropy measures the uncertainty or unpredictability of a password in bits. "
            "Theoretical entropy assumes purely random character selection (H = L * log2(N)). "
            "However, human-chosen passwords follow predictable habits (e.g., 'Password123!' gets ~78 bits "
            "theoretically, but is cracked within seconds by rule-based attacks). "
            "Therefore, effective entropy discounts predictable patterns and word roots."
        ),
        "disclaimer": (
            "Educational estimate only. Actual offline cracking speed depends heavily on attacker hardware (GPUs/ASICs), "
            "password hashing algorithm (e.g., fast MD5 vs slow memory-hard Argon2id), salt uniqueness, and rate limiting."
        )
    }
