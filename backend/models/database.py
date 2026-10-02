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
    Returns counts by tier, averages, and distribution arrays for Chart.js.
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

    # Average score & average length
    cursor.execute("SELECT AVG(score) AS avg_score, AVG(password_length) AS avg_length FROM analyses")
    avg_row = cursor.fetchone()
    avg_score = round(avg_row["avg_score"] or 0, 1)
    avg_length = round(avg_row["avg_length"] or 0, 1)

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

    conn.close()

    return {
        "total_analyses": total_analyses,
        "classifications": classification_counts,
        "average_score": avg_score,
        "average_length": avg_length,
        "score_distribution": score_bins,
        "length_distribution": length_bins,
        "common_weaknesses": weakness_stats,
        "privacy_statement": "All statistics are aggregated strictly from non-reversible numeric metadata."
    }

def seed_demo_analytics_if_empty():
    """
    Seeds a small set of synthetic educational metadata records to populate
    the dashboard visuals immediately for demonstration purposes.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM analyses")
    if cursor.fetchone()["total"] == 0:
        demo_records = [
            ("demo-1", 15, "VERY WEAK", 6, 0.5, 3, [("common_password", "CRITICAL", "Common password"), ("numeric_sequence_ascending", "MEDIUM", "Sequence")]),
            ("demo-2", 35, "WEAK", 10, 0.7, 2, [("predictable_grammar_structure", "HIGH", "Word+Digits")]),
            ("demo-3", 55, "MODERATE", 12, 0.8, 1, [("alphabetical_sequence_ascending", "MEDIUM", "Alpha seq")]),
            ("demo-4", 75, "STRONG", 16, 0.9, 0, []),
            ("demo-5", 95, "VERY STRONG", 20, 0.95, 0, []),
            ("demo-6", 18, "VERY WEAK", 5, 0.4, 2, [("critically_short_length", "CRITICAL", "Short"), ("repeated_characters", "HIGH", "Repeated")]),
            ("demo-7", 40, "WEAK", 8, 0.6, 2, [("keyboard_pattern", "HIGH", "Qwerty")]),
            ("demo-8", 60, "MODERATE", 13, 0.75, 1, [("calendar_year_detected", "MEDIUM", "Year")]),
            ("demo-9", 82, "STRONG", 18, 0.88, 0, []),
            ("demo-10", 25, "WEAK", 8, 0.5, 2, [("common_password", "HIGH", "Common pattern")]),
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
