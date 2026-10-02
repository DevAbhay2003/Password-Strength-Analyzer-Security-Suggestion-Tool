"""
Password Policy Checker Module
Evaluates passwords against organizational or NIST SP 800-63B modern authentication policies.
Differentiates formal policy compliance (binary PASS/FAIL) from mathematical password strength.
"""

from typing import Dict, Any, List, Optional

DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "allow_spaces": True,
    "reject_common": True,
    "reject_personal": True,
    "require_upper": False,
    "require_lower": False,
    "require_digit": False,
    "require_symbol": False
}

def evaluate_policy(
    password: str,
    length_metrics: dict,
    char_metrics: dict,
    common_metrics: dict,
    pattern_metrics: dict,
    custom_policy: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Checks if the password satisfies organizational policy requirements.
    Separates policy adherence from strength scoring.
    """
    policy = dict(DEFAULT_POLICY)
    if custom_policy:
        policy.update(custom_policy)

    violations: List[str] = []
    length = length_metrics.get("length", 0)

    # 1. Length bounds
    min_len = policy.get("min_length", 12)
    max_len = policy.get("max_length", 128)

    if length < min_len:
        violations.append(f"Password must be at least {min_len} characters in length (current: {length}).")

    if length > max_len:
        violations.append(f"Password exceeds maximum allowed length of {max_len} characters.")

    # 2. Spaces rule
    if not policy.get("allow_spaces", True) and char_metrics.get("has_spaces", False):
        violations.append("Spaces are not permitted under current configuration.")

    # 3. Common password rejection (NIST SP 800-63B recommendation)
    if policy.get("reject_common", True) and common_metrics.get("is_common", False):
        violations.append("Password matches a known compromised or common password pattern.")

    # 4. Personal context rejection
    if policy.get("reject_personal", True):
        for finding in pattern_metrics.get("findings", []):
            if finding.get("type", "").startswith("personal_info_"):
                violations.append("Password must not contain identifiable personal information.")
                break

    # 5. Optional traditional composition rules (if configured)
    if policy.get("require_upper", False) and not char_metrics.get("has_uppercase", False):
        violations.append("Password must contain at least one uppercase letter.")
    if policy.get("require_lower", False) and not char_metrics.get("has_lowercase", False):
        violations.append("Password must contain at least one lowercase letter.")
    if policy.get("require_digit", False) and not char_metrics.get("has_digits", False):
        violations.append("Password must contain at least one digit.")
    if policy.get("require_symbol", False) and not char_metrics.get("has_symbols", False):
        violations.append("Password must contain at least one symbol.")

    status = "PASS" if len(violations) == 0 else "FAIL"

    return {
        "status": status,
        "policy_passed": status == "PASS",
        "violations": violations,
        "configured_policy": policy,
        "educational_distinction": (
            "Policy compliance and password strength are distinct concepts. "
            "A password can pass an organizational policy (e.g. 'Password123!' meets 8 chars + upper + lower + number + symbol) "
            "yet remain critically weak and predictable. Modern standards (NIST SP 800-63B) favor length and "
            "screening against breached lists over arbitrary composition and forced periodic expiration."
        )
    }
