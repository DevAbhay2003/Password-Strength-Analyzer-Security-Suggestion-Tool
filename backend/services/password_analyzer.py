"""
Password Analyzer Orchestrator Module
Coordinates length analysis, character diversity, common password matching,
pattern detection, entropy calculation, strength scoring, policy checking,
and tailored security suggestion generation.
Strictly in-memory processing: zero password logging or caching.
"""

from typing import Dict, Any, Optional

from backend.services.length_analyzer import analyze_length
from backend.services.character_analyzer import analyze_characters
from backend.services.common_checker import is_common_password
from backend.services.pattern_detector import detect_all_patterns
from backend.services.entropy_estimator import analyze_entropy
from backend.services.scoring_engine import calculate_score
from backend.services.suggestion_engine import generate_suggestions
from backend.services.policy_checker import evaluate_policy

def analyze_password(
    password: str,
    context: Optional[Dict[str, str]] = None,
    policy_config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main entry point for evaluating password security.
    Processes the password strictly in memory and returns a rich, structured evaluation.
    """
    if password is None:
        password = ""

    # 1. Length Analysis
    length_res = analyze_length(password)

    # 2. Character Analysis
    char_res = analyze_characters(password)

    # 3. Common Password Check
    common_res = is_common_password(password)

    # 4. Pattern Detection (Sequences, Keyboard walks, Repetitions, Dates, Context)
    pattern_res = detect_all_patterns(password, context)

    # 5. Entropy-Style Estimation (Theoretical + Realistic Effective Entropy)
    entropy_res = analyze_entropy(
        password=password,
        char_metrics=char_res,
        pattern_count=pattern_res.get("pattern_count", 0),
        is_common=common_res.get("is_common", False)
    )

    # 6. Scoring Engine
    score_res = calculate_score(
        length_metrics=length_res,
        char_metrics=char_res,
        common_metrics=common_res,
        pattern_metrics=pattern_res,
        entropy_metrics=entropy_res
    )

    # 7. Suggestions Engine
    suggestions = generate_suggestions(
        length_metrics=length_res,
        char_metrics=char_res,
        common_metrics=common_res,
        pattern_metrics=pattern_res,
        score_metrics=score_res
    )

    # 8. Password Policy Evaluation
    policy_res = evaluate_policy(
        password=password,
        length_metrics=length_res,
        char_metrics=char_res,
        common_metrics=common_res,
        pattern_metrics=pattern_res,
        custom_policy=policy_config
    )

    # 9. Consolidate Structured Findings
    all_findings = []
    
    # Common password finding
    if common_res.get("is_common"):
        all_findings.append({
            "type": "common_password",
            "severity": common_res.get("severity", "HIGH"),
            "description": common_res.get("message"),
            "penalty": common_res.get("penalty", 0)
        })

    # Pattern findings
    for f in pattern_res.get("findings", []):
        all_findings.append({
            "type": f.get("type"),
            "severity": f.get("severity", "MEDIUM"),
            "description": f.get("description"),
            "penalty": f.get("penalty", 0)
        })

    # Length finding if short
    if length_res.get("length", 0) < 8:
        all_findings.append({
            "type": "critically_short_length",
            "severity": "CRITICAL",
            "description": length_res.get("message"),
            "penalty": 20
        })

    # Return structured industry-grade analysis payload
    return {
        "score": score_res["score"],
        "classification": score_res["classification"],
        "classification_description": score_res["description"],
        "findings": all_findings,
        "suggestions": suggestions,
        "metrics": {
            "length": length_res["length"],
            "length_band": length_res["band"],
            "character_type_count": char_res["character_type_count"],
            "unique_character_count": char_res["unique_character_count"],
            "unique_character_ratio": char_res["unique_character_ratio"],
            "has_lowercase": char_res["has_lowercase"],
            "has_uppercase": char_res["has_uppercase"],
            "has_digits": char_res["has_digits"],
            "has_symbols": char_res["has_symbols"],
            "has_spaces": char_res["has_spaces"],
            "estimated_pool_size": char_res["estimated_pool_size"],
            "pattern_count": pattern_res["pattern_count"],
            "is_common": common_res["is_common"]
        },
        "entropy": entropy_res,
        "score_breakdown": score_res["score_breakdown"],
        "policy": policy_res,
        "privacy_guarantee": (
            "This analysis was performed strictly in-memory. The analyzed password was not logged, "
            "not saved to disk, and not transmitted to external third-party services."
        )
    }
