"""
Database Module for Privacy-Preserving Analytics
Stores exclusively anonymized aggregate metadata (scores, classifications, lengths, finding types).
Strictly contains NO password column, NO hash column, and NO reversible credential representations.
"""

import sqlite3
import os
import uuid
from datetime import datetime
from typing import Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "analytics.db")

def get_connection():
    """
    Returns an SQLite connection configured with row factory.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes database tables. Notice the intentional, verifiable absence
    of any password or hash storage fields.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Table 1: Safe metadata per analysis session
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            password_length INTEGER NOT NULL,
            unique_character_ratio REAL NOT NULL,
            weakness_count INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Table 2: Safe weakness category statistics
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
        );
    """)

    conn.commit()
    conn.close()

def record_analysis_metadata(analysis_result: Dict[str, Any]) -> str:
    """
    Records ONLY safe, non-reversible metadata from the analysis.
    The password itself is discarded immediately and never reaches this function.
    """
    conn = get_connection()
    cursor = conn.cursor()

    analysis_id = str(uuid.uuid4())
    score = analysis_result.get("score", 0)
    classification = analysis_result.get("classification", "UNKNOWN")
    metrics = analysis_result.get("metrics", {})
    length = metrics.get("length", 0)
    unique_ratio = metrics.get("unique_character_ratio", 0.0)
    findings = analysis_result.get("findings", [])
    weakness_count = len(findings)

    cursor.execute("""
        INSERT INTO analyses (analysis_id, score, classification, password_length, unique_character_ratio, weakness_count)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (analysis_id, score, classification, length, unique_ratio, weakness_count))

    for f in findings:
        cursor.execute("""
            INSERT INTO findings (analysis_id, finding_type, severity, description)
            VALUES (?, ?, ?, ?)
        """, (analysis_id, f.get("type", "unknown"), f.get("severity", "LOW"), f.get("description", "")))

    conn.commit()
    conn.close()
    return analysis_id

def get_dashboard_stats() -> Dict[str, Any]:
    """
    Calculates aggregated analytics for the defensive dashboard.
    Returns counts by tier, averages, distribution arrays for Chart.js,
    severity breakdown, entropy analysis, recent telemetry feed, and security insights.
    All data is strictly non-reversible numeric metadata.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Total count
    cursor.execute("SELECT COUNT(*) AS total FROM analyses")
    total_row = cursor.fetchone()
    total_analyses = total_row["total"] if total_row else 0

    if total_analyses == 0:
        conn.close()
        # Seed safe demo distribution so initial dashboard loads educational visuals
        seed_demo_analytics_if_empty()
        return get_dashboard_stats()

    # Classification counts
    cursor.execute("""
        SELECT classification, COUNT(*) AS count
        FROM analyses
        GROUP BY classification
    """)
    classification_counts = {
        "VERY WEAK": 0,
        "WEAK": 0,
        "MODERATE": 0,
        "STRONG": 0,
        "VERY STRONG": 0
    }
    for row in cursor.fetchall():
        cls_name = row["classification"]
        if cls_name in classification_counts:
            classification_counts[cls_name] = row["count"]

    # Average score, length, uniqueness, and weakness count
    cursor.execute("""
        SELECT 
            AVG(score) AS avg_score, 
            AVG(password_length) AS avg_length,
            AVG(unique_character_ratio) AS avg_ratio,
            AVG(weakness_count) AS avg_weaknesses
        FROM analyses
    """)
    avg_row = cursor.fetchone()
    avg_score = round(avg_row["avg_score"] or 0, 1)
    avg_length = round(avg_row["avg_length"] or 0, 1)
    avg_ratio = round(avg_row["avg_ratio"] or 0.0, 2)
    avg_weaknesses = round(avg_row["avg_weaknesses"] or 0.0, 1)

    # Score bands for histogram
    score_bins = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    cursor.execute("SELECT score FROM analyses")
    for row in cursor.fetchall():
        s = row["score"]
        if s <= 20:
            score_bins["0-20"] += 1
        elif s <= 40:
            score_bins["21-40"] += 1
        elif s <= 60:
            score_bins["41-60"] += 1
        elif s <= 80:
            score_bins["61-80"] += 1
        else:
            score_bins["81-100"] += 1

    # Length distribution bands
    length_bins = {"<8": 0, "8-11": 0, "12-15": 0, "16+": 0}
    cursor.execute("SELECT password_length FROM analyses")
    for row in cursor.fetchall():
        l = row["password_length"]
        if l < 8:
            length_bins["<8"] += 1
        elif l <= 11:
            length_bins["8-11"] += 1
        elif l <= 15:
            length_bins["12-15"] += 1
        else:
            length_bins["16+"] += 1

    # Most common weaknesses
    cursor.execute("""
        SELECT finding_type, COUNT(*) AS count
        FROM findings
        GROUP BY finding_type
        ORDER BY count DESC
        LIMIT 6
    """)
    weakness_stats = [{"type": row["finding_type"], "count": row["count"]} for row in cursor.fetchall()]

    # Severity distribution
    severity_bins = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cursor.execute("""
        SELECT severity, COUNT(*) AS count
        FROM findings
        GROUP BY severity
    """)
    for row in cursor.fetchall():
        sev = row["severity"]
        if sev in severity_bins:
            severity_bins[sev] = row["count"]

    # Uniqueness distribution
    uniqueness_bins = {
        "<50% (Repetitive)": 0,
        "50-75% (Moderate)": 0,
        "75-90% (Good)": 0,
        "90%+ (High Diversity)": 0
    }
    cursor.execute("SELECT unique_character_ratio FROM analyses")
    for row in cursor.fetchall():
        r = row["unique_character_ratio"]
        if r < 0.50:
            uniqueness_bins["<50% (Repetitive)"] += 1
        elif r < 0.75:
            uniqueness_bins["50-75% (Moderate)"] += 1
        elif r < 0.90:
            uniqueness_bins["75-90% (Good)"] += 1
        else:
            uniqueness_bins["90%+ (High Diversity)"] += 1

    # Enterprise posture metrics
    at_risk_count = classification_counts["VERY WEAK"] + classification_counts["WEAK"]
    at_risk_percentage = round((at_risk_count / total_analyses) * 100, 1) if total_analyses > 0 else 0.0

    strong_tier_count = classification_counts["STRONG"] + classification_counts["VERY STRONG"]
    strong_tier_percentage = round((strong_tier_count / total_analyses) * 100, 1) if total_analyses > 0 else 0.0

    # NIST SP 800-63B Compliance estimate (length >= 12 and weakness_count == 0)
    cursor.execute("SELECT COUNT(*) AS count FROM analyses WHERE password_length >= 12 AND weakness_count = 0")
    nist_row = cursor.fetchone()
    nist_compliant_count = nist_row["count"] if nist_row else 0
    nist_compliance_rate = round((nist_compliant_count / total_analyses) * 100, 1) if total_analyses > 0 else 0.0

    # Overall Posture Rating & Health Index (0 - 100)
    # Formulate: 50% avg score + 30% NIST compliance + 20% (100 - at_risk_percentage)
    posture_score = int(round(0.50 * avg_score + 0.30 * nist_compliance_rate + 0.20 * (100 - at_risk_percentage)))
    posture_score = max(0, min(100, posture_score))

    if posture_score >= 75:
        risk_posture = "STRONG DEFENSE"
        risk_level = "success"
    elif posture_score >= 55:
        risk_posture = "MODERATE POSTURE"
        risk_level = "info"
    elif posture_score >= 40:
        risk_posture = "ELEVATED RISK"
        risk_level = "warning"
    else:
        risk_posture = "CRITICAL EXPOSURE"
        risk_level = "danger"

    # Recent Telemetry Sessions (latest 15)
    cursor.execute("""
        SELECT analysis_id, score, classification, password_length, unique_character_ratio, weakness_count, created_at
        FROM analyses
        ORDER BY rowid DESC
        LIMIT 15
    """)
    recent_analyses = []
    for r in cursor.fetchall():
        aid = r["analysis_id"]
        # Query top severity for this session
        cursor.execute("""
            SELECT finding_type, severity
            FROM findings
            WHERE analysis_id = ?
            ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END
            LIMIT 1
        """, (aid,))
        top_finding = cursor.fetchone()
        top_sev = top_finding["severity"] if top_finding else "CLEAN"
        primary_w = top_finding["finding_type"] if top_finding else "None (Clean)"

        # NIST compliance status
        is_nist_pass = (r["password_length"] >= 12) and (r["weakness_count"] == 0 or top_sev in ("LOW", "CLEAN"))

        # Truncated safe ID
        short_id = aid[:8] if len(aid) >= 8 else aid

        # Clean timestamp display
        created_str = str(r["created_at"])[:19]

        recent_analyses.append({
            "analysis_id": short_id,
            "full_id": aid,
            "created_at": created_str,
            "score": r["score"],
            "classification": r["classification"],
            "password_length": r["password_length"],
            "unique_ratio_pct": int(round(r["unique_character_ratio"] * 100)),
            "weakness_count": r["weakness_count"],
            "top_severity": top_sev,
            "primary_weakness": primary_w.replace("_", " ").title(),
            "nist_status": "PASS" if is_nist_pass else "FAIL"
        })

    # Security Insights formulation
    total_findings_count = sum(severity_bins.values())
    insights = []

    # 1. Threat vector insight
    if weakness_stats:
        top_w = weakness_stats[0]
        top_w_share = round((top_w["count"] / max(1, total_findings_count)) * 100, 1)
        insights.append({
            "type": "threat",
            "icon": "🚨",
            "title": f"Primary Adversary Pattern: {top_w['type'].replace('_', ' ').title()}",
            "detail": f"Represents {top_w['count']} detections ({top_w_share}% of all flaws). Attackers prioritize automated dictionary rules and sequential walks against this vector."
        })

    # 2. Length band insight
    short_pct = round(((length_bins["<8"] + length_bins["8-11"]) / max(1, total_analyses)) * 100, 1)
    if short_pct > 30:
        insights.append({
            "type": "length",
            "icon": "📏",
            "title": f"Length Deficit: {short_pct}% Below 12-Character Baseline",
            "detail": f"{length_bins['<8'] + length_bins['8-11']} of {total_analyses} evaluated credentials fail modern NIST SP 800-63B minimum length recommendations."
        })
    else:
        insights.append({
            "type": "length",
            "icon": "✅",
            "title": f"Healthy Length Baseline: {100 - short_pct}% Meet 12+ Character Guideline",
            "detail": "Robust length distribution observed across the evaluated corpus, significantly expanding keyspace search resistance."
        })

    # 3. Posture resilience insight
    if at_risk_percentage > 40:
        insights.append({
            "type": "risk",
            "icon": "⚠️",
            "title": f"High Vulnerability Ratio: {at_risk_percentage}% Require Remediation",
            "detail": f"{at_risk_count} credentials categorized as VERY WEAK or WEAK. Deploying Diceware passphrases or password managers mitigates this risk immediately."
        })
    else:
        insights.append({
            "type": "risk",
            "icon": "🛡️",
            "title": f"High Resilience Cohort: {strong_tier_percentage}% Strong / Very Strong",
            "detail": f"Majority of evaluated credentials exhibit defense-in-depth characteristics, including diverse character pools and effective entropy resilience."
        })

    # 4. Compliance & Policy guidance
    insights.append({
        "type": "policy",
        "icon": "📋",
        "title": f"NIST SP 800-63B Alignment: {nist_compliance_rate}% Strict Compliance",
        "detail": f"{nist_compliant_count} credentials satisfy zero-weakness requirements with length ≥ 12 characters. Modern identity policies should decouple from legacy composition mandates."
    })

    conn.close()

    return {
        "total_analyses": total_analyses,
        "classifications": classification_counts,
        "average_score": avg_score,
        "average_length": avg_length,
        "average_uniqueness_ratio": avg_ratio,
        "average_weaknesses": avg_weaknesses,
        "score_distribution": score_bins,
        "length_distribution": length_bins,
        "common_weaknesses": weakness_stats,
        "severity_distribution": severity_bins,
        "uniqueness_distribution": uniqueness_bins,
        "at_risk_count": at_risk_count,
        "at_risk_percentage": at_risk_percentage,
        "strong_tier_percentage": strong_tier_percentage,
        "nist_compliant_count": nist_compliant_count,
        "nist_compliance_rate": nist_compliance_rate,
        "risk_posture": risk_posture,
        "risk_level": risk_level,
        "risk_posture_score": posture_score,
        "security_insights": insights,
        "recent_telemetry": recent_analyses,
        "privacy_statement": "All statistics are aggregated strictly from non-reversible numeric metadata. Zero passwords or hashes are persisted."
    }

def seed_demo_analytics_if_empty():
    """
    Seeds a realistic set of synthetic educational metadata records to populate
    the dashboard visuals immediately with rich defensive telemetry.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM analyses")
    if cursor.fetchone()["total"] == 0:
        demo_records = [
            ("sim-01", 15, "VERY WEAK", 6, 0.50, 3, [("common_password", "CRITICAL", "Known compromised password"), ("numeric_sequence_ascending", "HIGH", "Ascending sequence")]),
            ("sim-02", 35, "WEAK", 10, 0.70, 2, [("predictable_grammar_structure", "HIGH", "Capitalized word followed by digits"), ("calendar_year_detected", "MEDIUM", "Calendar year in password")]),
            ("sim-03", 55, "MODERATE", 12, 0.83, 1, [("alphabetical_sequence_ascending", "MEDIUM", "Alphabetical sequence")]),
            ("sim-04", 78, "STRONG", 16, 0.88, 0, []),
            ("sim-05", 96, "VERY STRONG", 24, 0.92, 0, []),
            ("sim-06", 10, "VERY WEAK", 5, 0.40, 2, [("critically_short_length", "CRITICAL", "Critically short length"), ("repeated_characters", "HIGH", "Repeated consecutive characters")]),
            ("sim-07", 38, "WEAK", 8, 0.63, 2, [("keyboard_pattern", "HIGH", "Horizontal QWERTY walk")]),
            ("sim-08", 62, "MODERATE", 14, 0.79, 1, [("calendar_year_detected", "MEDIUM", "Calendar year pattern")]),
            ("sim-09", 84, "STRONG", 18, 0.89, 0, []),
            ("sim-10", 22, "VERY WEAK", 7, 0.57, 2, [("common_password", "CRITICAL", "Common password variant")]),
            ("sim-11", 90, "VERY STRONG", 22, 0.86, 0, []),
            ("sim-12", 45, "MODERATE", 11, 0.73, 1, [("numeric_sequence_ascending", "MEDIUM", "Sequence at tail")]),
            ("sim-13", 18, "VERY WEAK", 6, 0.50, 2, [("critically_short_length", "CRITICAL", "Short length"), ("keyboard_pattern", "HIGH", "Keyboard walk")]),
            ("sim-14", 72, "STRONG", 15, 0.87, 0, []),
            ("sim-15", 30, "WEAK", 9, 0.67, 2, [("predictable_grammar_structure", "HIGH", "Predictable grammar structure")]),
            ("sim-16", 98, "VERY STRONG", 28, 0.93, 0, []),
            ("sim-17", 58, "MODERATE", 13, 0.77, 1, [("numeric_sequence_descending", "MEDIUM", "Descending sequence")]),
            ("sim-18", 80, "STRONG", 16, 0.88, 0, []),
        ]
        for aid, score, cls, length, ratio, wcount, findings in demo_records:
            cursor.execute("""
                INSERT INTO analyses (analysis_id, score, classification, password_length, unique_character_ratio, weakness_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (aid, score, cls, length, ratio, wcount))
            for ftype, sev, desc in findings:
                cursor.execute("""
                    INSERT INTO findings (analysis_id, finding_type, severity, description)
                    VALUES (?, ?, ?, ?)
                """, (aid, ftype, sev, desc))
        conn.commit()
    conn.close()

def reset_demo_analytics():
    """
    Clears all recorded telemetry and reseeds clean baseline educational demo dataset.
    Strictly preserves schema and zero-persistence integrity.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    cursor.execute("DELETE FROM analyses")
    conn.commit()
    conn.close()
    seed_demo_analytics_if_empty()

def simulate_enterprise_ingestion() -> int:
    """
    Simulates ingestion of 5 anonymized corporate evaluation sessions
    reflecting real-world threat telemetry. Returns number of ingested sessions.
    """
    conn = get_connection()
    cursor = conn.cursor()

    simulated_batch = [
        ("corp-sim-" + str(uuid.uuid4())[:8], 28, "WEAK", 9, 0.67, 2, [
            ("predictable_grammar_structure", "HIGH", "TitleCase + Digits pattern"),
            ("calendar_year_detected", "MEDIUM", "Current year suffix")
        ]),
        ("corp-sim-" + str(uuid.uuid4())[:8], 88, "STRONG", 18, 0.89, 0, []),
        ("corp-sim-" + str(uuid.uuid4())[:8], 15, "VERY WEAK", 6, 0.50, 3, [
            ("critically_short_length", "CRITICAL", "Below minimum enterprise length"),
            ("keyboard_pattern", "HIGH", "QWERTY keyboard walk"),
            ("numeric_sequence_ascending", "MEDIUM", "Numeric sequence")
        ]),
        ("corp-sim-" + str(uuid.uuid4())[:8], 98, "VERY STRONG", 24, 0.92, 0, []),
        ("corp-sim-" + str(uuid.uuid4())[:8], 52, "MODERATE", 13, 0.77, 1, [
            ("numeric_sequence_ascending", "MEDIUM", "Ascending sequence")
        ]),
    ]

    for aid, score, cls, length, ratio, wcount, findings in simulated_batch:
        cursor.execute("""
            INSERT INTO analyses (analysis_id, score, classification, password_length, unique_character_ratio, weakness_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (aid, score, cls, length, ratio, wcount))
        for ftype, sev, desc in findings:
            cursor.execute("""
                INSERT INTO findings (analysis_id, finding_type, severity, description)
                VALUES (?, ?, ?, ?)
            """, (aid, ftype, sev, desc))

    conn.commit()
    conn.close()
    return len(simulated_batch)

def export_telemetry_dataset() -> List[Dict[str, Any]]:
    """
    Retrieves safe, non-reversible metadata records for compliance and audit reporting.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT analysis_id, score, classification, password_length, unique_character_ratio, weakness_count, created_at
        FROM analyses
        ORDER BY created_at DESC, rowid DESC
    """)
    records = []
    for r in cursor.fetchall():
        records.append({
            "analysis_id": r["analysis_id"][:8],
            "score": r["score"],
            "classification": r["classification"],
            "password_length": r["password_length"],
            "unique_character_ratio": round(r["unique_character_ratio"], 3),
            "weakness_count": r["weakness_count"],
            "timestamp": str(r["created_at"])[:19]
        })
    conn.close()
    return records

