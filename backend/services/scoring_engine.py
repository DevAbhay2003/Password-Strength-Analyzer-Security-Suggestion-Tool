"""
Scoring Engine Module
Calculates a balanced 0–100 password strength score combining positive contributions
(length, diversity, uniqueness, unpredictability) with explicit penalties for common
passwords, keyboard walks, repetitions, and contextual patterns.
"""

from typing import Dict, Any, Tuple

CLASSIFICATION_BANDS = [
    (20, "VERY WEAK", "Critically vulnerable to immediate dictionary, mask, or brute-force compromise."),
    (40, "WEAK", "Vulnerable to basic rule-based attacks or modest hash searches."),
    (60, "MODERATE", "Adequate against casual guessing; susceptible to specialized cracking rigs or offline leaks."),
    (80, "STRONG", "High level of resistance against standard offline and online attack techniques."),
    (100, "VERY STRONG", "Outstanding resistance with extensive keyspace and zero detected predictable patterns.")
]

def calculate_score(
    length_metrics: dict,
    char_metrics: dict,
    common_metrics: dict,
    pattern_metrics: dict,
    entropy_metrics: dict
) -> Dict[str, Any]:
    """
    Computes a granular, defensible 0–100 password strength score.
    Returns the score, classification, breakdown of positive points,
    and applied penalties.
    """
    length = length_metrics.get("length", 0)
    if length == 0:
        return {
            "score": 0,
            "classification": "VERY WEAK",
            "description": "No password entered.",
            "score_breakdown": {
                "length_points": 0,
                "diversity_points": 0,
                "uniqueness_points": 0,
                "pattern_resistance_points": 0,
                "non_common_points": 0,
                "unpredictability_points": 0,
                "total_positive": 0,
                "total_penalty": 0
            }
        }

    # 1. Positive Contributions (Max = 100)
    # Length: up to 35
    length_points = length_metrics.get("points", 0)

    # Character Diversity: up to 15
    diversity_points = char_metrics.get("diversity_points", 0)

    # Unique Character Ratio: up to 10
    uniqueness_points = char_metrics.get("uniqueness_points", 0)

    # Pattern Resistance: up to 20 (Full points if zero patterns, scaled down if patterns exist)
    pattern_count = pattern_metrics.get("pattern_count", 0)
    if pattern_count == 0:
        pattern_resistance_points = 20
    elif pattern_count == 1:
        pattern_resistance_points = 10
    elif pattern_count == 2:
        pattern_resistance_points = 4
    else:
        pattern_resistance_points = 0

    # Non-Common Password: up to 10
    is_common = common_metrics.get("is_common", False)
    non_common_points = 0 if is_common else 10

    # Additional Unpredictability (Effective Entropy): up to 10
    effective_bits = entropy_metrics.get("effective_bits", 0.0)
    if effective_bits >= 70:
        unpredictability_points = 10
    elif effective_bits >= 50:
        unpredictability_points = 7
    elif effective_bits >= 35:
        unpredictability_points = 4
    elif effective_bits >= 20:
        unpredictability_points = 2
    else:
        unpredictability_points = 0

    total_positive = (
        length_points
        + diversity_points
        + uniqueness_points
        + pattern_resistance_points
        + non_common_points
        + unpredictability_points
    )

    # 2. Penalties
    total_penalty = 0

    # Common password penalty
    common_penalty = common_metrics.get("penalty", 0)
    total_penalty += common_penalty

    # Pattern penalties (sequences, keyboard walks, repetitions, personal info, dates)
    patterns_penalty = pattern_metrics.get("total_penalty", 0)
    total_penalty += patterns_penalty

    # Compute raw score and clamp to [0, 100]
    raw_score = total_positive - total_penalty
    final_score = max(0, min(100, int(round(raw_score))))

    # 3. Determine Classification
    classification = "VERY STRONG"
    description = ""
    for ceiling, label, desc in CLASSIFICATION_BANDS:
        if final_score <= ceiling:
            classification = label
            description = desc
            break

    # Guard rail: If password is in common list, cap at WEAK regardless of appended elements
    if is_common and final_score > 35:
        final_score = 35
        classification = "WEAK"
        description = "Matches or is derived from common credential list; capped at WEAK."

    # Guard rail: Strict length & single-class guardrails
    if length < 6 or (length < 8 and char_metrics.get("character_type_count", 0) <= 1):
        final_score = min(final_score, 18)
        classification = "VERY WEAK"
        description = "Critically short length or single character set creates a tiny search space; classified as VERY WEAK."
    elif length < 8:
        final_score = min(final_score, 30)
        classification = "WEAK"
        description = "Short length (<8 characters) caps maximum strength at WEAK."

    return {
        "score": final_score,
        "classification": classification,
        "description": description,
        "score_breakdown": {
            "length_points": length_points,
            "diversity_points": diversity_points,
            "uniqueness_points": uniqueness_points,
            "pattern_resistance_points": pattern_resistance_points,
            "non_common_points": non_common_points,
            "unpredictability_points": unpredictability_points,
            "total_positive": total_positive,
            "total_penalty": total_penalty
        },
        "educational_disclaimer": (
            "These scoring bands are project-defined metrics created for defensive education and "
            "engineering guidance, rather than a universal mathematical law. Password resilience "
            "is context-dependent based on the adversary's capabilities and hashing architecture."
        )
    }
