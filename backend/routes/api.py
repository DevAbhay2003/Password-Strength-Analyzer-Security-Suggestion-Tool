"""
API Routes Module
Defines REST endpoints for password analysis, dashboard metrics,
secure credential generation, and educational hashing demonstrations.
Implements privacy boundaries: passwords exist transiently in memory only.
"""

from flask import Blueprint, request, jsonify
from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import generate_secure_password, generate_secure_passphrase
from backend.models.database import record_analysis_metadata, get_dashboard_stats
from backend.utils.hashing_demo import demo_fast_vs_slow_hashing

api_bp = Blueprint("api", __name__, url_prefix="/api")

@api_bp.route("/analyze", methods=["POST"])
def analyze_endpoint():
    """
    POST /api/analyze
    Analyzes password strength in memory and returns security findings and recommendations.
    Ensures input is never logged to disk or console.
    """
    try:
        data = request.get_json(silent=True)
        if not data or "password" not in data:
            return jsonify({
                "status": "error",
                "message": "Missing 'password' parameter in request body."
            }), 400

        raw_password = str(data.get("password", ""))
        
        # Enforce defensive payload boundary against buffer/DoS abuse
        if len(raw_password) > 256:
            return jsonify({
                "status": "error",
                "message": "Password exceeds maximum supported length boundary of 256 characters."
            }), 400

        # Optional voluntary context (first name, birth year, org)
        context = data.get("context", {})
        policy_config = data.get("policy", None)
        record_analytics = data.get("record_analytics", True)

        # In-memory evaluation
        result = analyze_password(raw_password, context=context, policy_config=policy_config)

        # Anonymized aggregate metadata persistence (only safe numbers, never the password)
        if record_analytics and len(raw_password) > 0:
            try:
                record_analysis_metadata(result)
            except Exception:
                # Analytics failure should never break or block the user's defensive analysis
                pass

        return jsonify({
            "status": "success",
            "data": result
        }), 200

    except Exception as e:
        # Never echo raw inputs in error responses
        return jsonify({
            "status": "error",
            "message": "An internal error occurred during defensive evaluation."
        }), 500

@api_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats_endpoint():
    """
    GET /api/dashboard/stats
    Returns aggregated educational statistics without revealing passwords.
    """
    try:
        stats = get_dashboard_stats()
        return jsonify({
            "status": "success",
            "data": stats
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Unable to compile aggregate dashboard statistics."
        }), 500

@api_bp.route("/generate-password", methods=["POST"])
def generate_password_endpoint():
    """
    POST /api/generate-password
    Generates a cryptographically strong random password or passphrase using Python secrets.
    """
    try:
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "password")

        if mode == "passphrase":
            word_count = int(data.get("word_count", 4))
            separator = str(data.get("separator", "-"))
            gen_res = generate_secure_passphrase(word_count=word_count, separator=separator)
        else:
            length = int(data.get("length", 20))
            upper = bool(data.get("include_upper", True))
            lower = bool(data.get("include_lower", True))
            digits = bool(data.get("include_digits", True))
            symbols = bool(data.get("include_symbols", True))
            gen_res = generate_secure_password(
                length=length,
                include_upper=upper,
                include_lower=lower,
                include_digits=digits,
                include_symbols=symbols
            )

        return jsonify({
            "status": "success",
            "data": gen_res
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Failed to generate secure credential."
        }), 500

@api_bp.route("/hashing-demo", methods=["POST"])
def hashing_demo_endpoint():
    """
    POST /api/hashing-demo
    Executes a real-time educational benchmark comparing fast hashes (MD5, SHA-256)
    with slow salted key-stretching functions (PBKDF2, scrypt) on a synthetic demo word.
    """
    try:
        data = request.get_json(silent=True) or {}
        # Strictly use synthetic sample or generic default
        sample = str(data.get("sample", "DemoSyntheticPassphrase2026!"))[:64]
        benchmark_results = demo_fast_vs_slow_hashing(sample)
        return jsonify({
            "status": "success",
            "data": benchmark_results
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Hashing demonstration encountered an error."
        }), 500
