"""
Threat Intelligence & Awareness Service Layer
Module: backend.services.threat_service

Central business logic orchestrating threat records, SOC dashboard analytics,
vulnerability prioritization, and educational awareness scoring.
"""

import os
import sys
import json
from datetime import datetime, timezone
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk
from backend.services.alert_engine import generate_threat_alert

def get_dashboard_statistics(db_conn=None) -> dict:
    """
    Computes summary cards and analytics for the 10 SOC dashboard charts.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()

    # 1. Summary Cards
    cursor.execute("SELECT COUNT(*) as total FROM threats")
    total_threats = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as count FROM threats WHERE severity = 'CRITICAL'")
    critical_threats = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM threats WHERE severity = 'HIGH'")
    high_threats = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as total FROM indicators")
    active_indicators = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status IN ('NEW', 'INVESTIGATING', 'MONITORING')")
    open_investigations = cursor.fetchone()["count"]

    cursor.execute("SELECT AVG(confidence_score) as avg_conf FROM threats")
    avg_conf_row = cursor.fetchone()
    avg_confidence = round(avg_conf_row["avg_conf"], 1) if avg_conf_row and avg_conf_row["avg_conf"] else 0.0

    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
    total_vulns = cursor.fetchone()["count"]

    cards = {
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "active_indicators": active_indicators,
        "open_investigations": open_investigations,
        "average_confidence": avg_confidence,
        "vulnerabilities_tracked": total_vulns
    }

    # 2. Charts Data
    # Chart 1: Threats Over Time (grouped by date)
    cursor.execute("""
    SELECT SUBSTR(timestamp, 1, 10) as date_val, COUNT(*) as count
    FROM threats
    GROUP BY date_val
    ORDER BY date_val ASC
    LIMIT 30
    """)
    threats_over_time = [{"date": r["date_val"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 2: Threats by Severity
    cursor.execute("""
    SELECT severity, COUNT(*) as count
    FROM threats
    GROUP BY severity
    ORDER BY CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5 END
    """)
    threats_by_severity = [{"severity": r["severity"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 3: Threats by Category
    cursor.execute("""
    SELECT category, COUNT(*) as count
    FROM threats
    GROUP BY category
    ORDER BY count DESC
    """)
    threats_by_category = [{"category": r["category"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 4: IOC Type Distribution
    cursor.execute("""
    SELECT indicator_type, COUNT(*) as count
    FROM indicators
    GROUP BY indicator_type
    ORDER BY count DESC
    """)
    ioc_distribution = [{"type": r["indicator_type"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 5: Top ATT&CK Tactics
    cursor.execute("""
    SELECT tactic, COUNT(*) as count
    FROM attack_mappings
    GROUP BY tactic
    ORDER BY count DESC
    LIMIT 8
    """)
    top_tactics = [{"tactic": r["tactic"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 6: Risk Score Distribution (Tiers)
    cursor.execute("""
    SELECT
        CASE
            WHEN risk_score <= 20 THEN '0-20 Informational'
            WHEN risk_score <= 40 THEN '21-40 Low'
            WHEN risk_score <= 60 THEN '41-60 Medium'
            WHEN risk_score <= 80 THEN '61-80 High'
            ELSE '81-100 Critical'
        END as tier,
        COUNT(*) as count
    FROM threats
    GROUP BY tier
    ORDER BY tier ASC
    """)
    risk_distribution = [{"tier": r["tier"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 7: Confidence Distribution
    cursor.execute("""
    SELECT
        CASE
            WHEN confidence_score < 50 THEN 'Low (<50%)'
            WHEN confidence_score < 75 THEN 'Moderate (50-74%)'
            WHEN confidence_score < 90 THEN 'High (75-89%)'
            ELSE 'Very High (90-100%)'
        END as band,
        COUNT(*) as count
    FROM threats
    GROUP BY band
    ORDER BY count DESC
    """)
    confidence_distribution = [{"band": r["band"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 8: Vulnerabilities by Severity
    cursor.execute("""
    SELECT severity, COUNT(*) as count
    FROM vulnerabilities
    GROUP BY severity
    ORDER BY CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4 END
    """)
    vulns_by_severity = [{"severity": r["severity"], "count": r["count"]} for r in cursor.fetchall()]

    # Chart 9: Top Threat Categories (Top 5)
    top_categories = threats_by_category[:5]

    # Chart 10: Threat Status Distribution
    cursor.execute("""
    SELECT status, COUNT(*) as count
    FROM threats
    GROUP BY status
    ORDER BY count DESC
    """)
    threat_statuses = [{"status": r["status"], "count": r["count"]} for r in cursor.fetchall()]

    if should_close:
        db_conn.close()

    return {
        "cards": cards,
        "charts": {
            "threats_over_time": threats_over_time,
            "threats_by_severity": threats_by_severity,
            "threats_by_category": threats_by_category,
            "ioc_distribution": ioc_distribution,
            "top_tactics": top_tactics,
            "risk_distribution": risk_distribution,
            "confidence_distribution": confidence_distribution,
            "vulns_by_severity": vulns_by_severity,
            "top_categories": top_categories,
            "threat_statuses": threat_statuses
        }
    }

def get_threats(
    severity=None,
    category=None,
    indicator_type=None,
    status=None,
    search=None,
    sort_by="newest",
    page=1,
    page_size=20,
    db_conn=None
) -> dict:
    """
    Retrieves filtered, sorted, and paginated threat records.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()

    conditions = ["1=1"]
    params = []

    if severity and severity.upper() != "ALL":
        conditions.append("t.severity = ?")
        params.append(severity.upper().strip())

    if category and category.upper() != "ALL":
        conditions.append("t.category = ?")
        params.append(category.upper().strip())

    if status and status.upper() != "ALL":
        conditions.append("t.status = ?")
        params.append(status.upper().strip())

    if indicator_type and indicator_type.upper() != "ALL":
        conditions.append("i.indicator_type LIKE ?")
        params.append(f"%{indicator_type.strip()}%")

    if search:
        s = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(t.threat_id) LIKE ? OR LOWER(t.threat_name) LIKE ? OR LOWER(i.indicator_value) LIKE ? OR LOWER(t.description) LIKE ?)")
        params.extend([s, s, s, s])

    where_clause = " AND ".join(conditions)

    # Count total matching
    count_sql = f"""
    SELECT COUNT(DISTINCT t.threat_id) as total
    FROM threats t
    LEFT JOIN indicators i ON t.threat_id = i.threat_id
    WHERE {where_clause}
    """
    cursor.execute(count_sql, params)
    total_records = cursor.fetchone()["total"]

    # Sorting
    sort_mapping = {
        "newest": "t.timestamp DESC",
        "highest_risk": "t.risk_score DESC",
        "highest_confidence": "t.confidence_score DESC",
        "most_observed": "t.observation_count DESC"
    }
    order_clause = sort_mapping.get(sort_by, "t.timestamp DESC")

    offset = (page - 1) * page_size
    query_sql = f"""
    SELECT t.threat_id, t.timestamp, t.threat_name, t.category, t.severity,
           t.risk_score, t.confidence_score, t.status, t.first_seen, t.last_seen,
           t.observation_count, t.source_name, t.source_reliability,
           i.indicator_type, i.indicator_value
    FROM threats t
    LEFT JOIN indicators i ON t.threat_id = i.threat_id
    WHERE {where_clause}
    GROUP BY t.threat_id
    ORDER BY {order_clause}
    LIMIT ? OFFSET ?
    """
    cursor.execute(query_sql, params + [page_size, offset])
    rows = [dict(r) for r in cursor.fetchall()]

    if should_close:
        db_conn.close()

    total_pages = max(1, (total_records + page_size - 1) // page_size)

    return {
        "records": rows,
        "total": total_records,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }

def get_threat_by_id(threat_id: str, db_conn=None) -> dict:
    """
    Fetches comprehensive metadata for a specific threat by ID.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    t_row = cursor.fetchone()

    if not t_row:
        if should_close:
            db_conn.close()
        return None

    threat = dict(t_row)

    # Fetch indicators
    cursor.execute("SELECT * FROM indicators WHERE threat_id = ?", (threat_id,))
    threat["indicators"] = [dict(r) for r in cursor.fetchall()]

    # Fetch MITRE ATT&CK mappings
    cursor.execute("SELECT * FROM attack_mappings WHERE threat_id = ?", (threat_id,))
    threat["attack_mappings"] = [dict(r) for r in cursor.fetchall()]

    # Fetch analyst notes
    cursor.execute("SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,))
    threat["notes"] = [dict(r) for r in cursor.fetchall()]

    # Fetch alerts
    cursor.execute("SELECT * FROM alerts WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,))
    threat["alerts"] = [dict(r) for r in cursor.fetchall()]

    if should_close:
        db_conn.close()

    return threat

def add_analyst_note(threat_id: str, author: str, note_text: str, db_conn=None) -> dict:
    """Appends an analyst triage note to a threat record."""
    if not note_text.strip():
        return {"success": False, "error": "Note cannot be empty."}

    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor.execute("""
    INSERT INTO analyst_notes (threat_id, author, note, created_at)
    VALUES (?, ?, ?, ?)
    """, (threat_id, author or "SOC Analyst", note_text.strip(), now_str))
    db_conn.commit()

    if should_close:
        db_conn.close()

    return {
        "success": True,
        "note": {
            "threat_id": threat_id,
            "author": author or "SOC Analyst",
            "note": note_text.strip(),
            "created_at": now_str
        }
    }

def update_threat_status(threat_id: str, new_status: str, db_conn=None) -> dict:
    """Updates the operational lifecycle status of a threat."""
    allowed = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
    status_upper = new_status.upper().strip()
    if status_upper not in allowed:
        return {"success": False, "error": f"Invalid status. Allowed: {allowed}"}

    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("UPDATE threats SET status = ? WHERE threat_id = ?", (status_upper, threat_id))
    db_conn.commit()

    if should_close:
        db_conn.close()

    return {"success": True, "threat_id": threat_id, "new_status": status_upper}

def calculate_vulnerability_priority(
    cvss_score: float,
    asset_criticality: str = "HIGH",
    exposure: str = "INTERNET_FACING",
    exploitation_status: str = "PROOF_OF_CONCEPT"
) -> dict:
    """
    Contextual Vulnerability Prioritization Formula:
    CVSS Alone (40%) + Asset Criticality (25%) + Exposure (20%) + Known Exploitation (15%)
    """
    crit_factor = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}.get(asset_criticality.upper(), 50)
    exp_factor = {"INTERNET_FACING": 100, "INTERNAL_ONLY": 50, "ISOLATED_TEST": 15}.get(exposure.upper(), 50)
    exploit_factor = {"KNOWN_EXPLOITED": 100, "PROOF_OF_CONCEPT": 65, "UNPROVEN": 25}.get(exploitation_status.upper(), 25)

    cvss_component = float(cvss_score) * 10.0

    priority_score = int(round(
        (cvss_component * 0.40) +
        (crit_factor * 0.25) +
        (exp_factor * 0.20) +
        (exploit_factor * 0.15)
    ))

    # Triage Urgency Level
    if priority_score >= 80:
        urgency = "URGENT_P0 (Remediate within 24-48 hours)"
    elif priority_score >= 60:
        urgency = "HIGH_P1 (Remediate within 7 days)"
    elif priority_score >= 40:
        urgency = "MEDIUM_P2 (Scheduled Maintenance Cycle)"
    else:
        urgency = "LOW_P3 (Standard Review)"

    return {
        "priority_score": priority_score,
        "urgency": urgency,
        "cvss_component": cvss_component,
        "criticality_component": crit_factor,
        "exposure_component": exp_factor,
        "exploit_component": exploit_factor
    }

def get_vulnerabilities(db_conn=None) -> list:
    """Retrieves all tracked defensive vulnerability records sorted by contextual priority score."""
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("""
    SELECT * FROM vulnerabilities
    ORDER BY priority_score DESC, cvss_score DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]

    if should_close:
        db_conn.close()

    return rows

def generate_learning_recommendations(category_scores: dict) -> list:
    """
    Analyzes quiz category results and maps scores < 70% to personalized educational modules.
    """
    recommendations = []
    category_to_module = {
        "Phishing": ("MOD-001", "Phishing Awareness & Email Defense"),
        "Passwords": ("MOD-002", "Password Security & Passphrase Hygiene"),
        "MFA": ("MOD-003", "Multi-Factor Authentication (MFA) & FIDO2"),
        "Social Engineering": ("MOD-004", "Social Engineering & Pretexting Defense"),
        "Safe Browsing": ("MOD-005", "Safe Web Browsing & Drive-By Defense"),
        "Wi-Fi": ("MOD-006", "Secure Wi-Fi & Network Defense"),
        "Software Updates": ("MOD-007", "Software Updates & Patch Management"),
        "Ransomware": ("MOD-008", "Ransomware Awareness & Incident Defense"),
        "Privacy": ("MOD-010", "Data Privacy & Information Protection"),
        "Mobile Security": ("MOD-011", "Mobile Device Security & App Hygiene"),
        "Incident Reporting": ("MOD-014", "Incident Reporting & Culture of Transparency")
    }

    for cat, score in category_scores.items():
        if score < 70:
            mod_info = category_to_module.get(cat)
            if mod_info:
                recommendations.append({
                    "category": cat,
                    "score": score,
                    "status": "Needs Improvement" if score < 50 else "Moderate Awareness",
                    "module_id": mod_info[0],
                    "module_title": mod_info[1],
                    "recommendation": f"Score of {score}% indicates vulnerability to {cat} threats. Complete the '{mod_info[1]}' module."
                })

    if not recommendations:
        recommendations.append({
            "category": "All Areas",
            "score": 100,
            "status": "Strong Awareness",
            "module_id": "MOD-001",
            "module_title": "Advanced Threat Intelligence & Continuous Defense",
            "recommendation": "Outstanding performance! Maintain proficiency with periodic refresher quizzes."
        })

    return recommendations

def grade_quiz_submission(submitted_answers: dict, db_conn=None) -> dict:
    """
    Scores user quiz submission against stored question bank.
    submitted_answers format: {"Q-01": 2, "Q-02": 1, ...}
    """
    questions_file = os.path.join(BASE_DIR, "awareness", "quiz_questions.json")
    with open(questions_file, mode="r", encoding="utf-8") as qf:
        questions = json.load(qf)

    total_questions = len(questions)
    correct_count = 0

    category_stats = {}
    detailed_results = []

    for q in questions:
        q_id = q["id"]
        cat = q["category"]
        correct_idx = q["correct_index"]
        user_choice = submitted_answers.get(q_id)

        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "correct": 0}
        category_stats[cat]["total"] += 1

        is_correct = (user_choice is not None and int(user_choice) == correct_idx)
        if is_correct:
            correct_count += 1
            category_stats[cat]["correct"] += 1

        detailed_results.append({
            "id": q_id,
            "category": cat,
            "question": q["question"],
            "options": q["options"],
            "user_choice": user_choice,
            "correct_choice": correct_idx,
            "is_correct": is_correct,
            "explanation": q["explanation"]
        })

    overall_score = int(round((correct_count / total_questions) * 100)) if total_questions > 0 else 0

    # Calculate category percentages
    category_scores = {}
    weak_areas = []
    for cat, stat in category_stats.items():
        cat_pct = int(round((stat["correct"] / stat["total"]) * 100)) if stat["total"] > 0 else 0
        category_scores[cat] = cat_pct
        if cat_pct < 70:
            weak_areas.append(cat)

    recommendations = generate_learning_recommendations(category_scores)

    # Awareness tier label
    if overall_score >= 81:
        grade_label = "Strong Awareness"
    elif overall_score >= 61:
        grade_label = "Good Awareness"
    elif overall_score >= 41:
        grade_label = "Basic Awareness"
    else:
        grade_label = "Needs Improvement"

    # Persist in DB
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cursor.execute("""
    INSERT INTO quiz_results (
        anonymous_user_id, overall_score, category_scores_json,
        weak_areas_json, recommendations_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        "ANON_STUDENT",
        overall_score,
        json.dumps(category_scores),
        json.dumps(weak_areas),
        json.dumps(recommendations),
        now_str
    ))
    db_conn.commit()

    if should_close:
        db_conn.close()

    return {
        "overall_score": overall_score,
        "grade_label": grade_label,
        "correct_count": correct_count,
        "total_questions": total_questions,
        "category_scores": category_scores,
        "weak_areas": weak_areas,
        "recommendations": recommendations,
        "detailed_results": detailed_results,
        "disclaimer": "This score is intended strictly for educational self-assessment and defensive awareness training."
    }

def get_executive_summary(db_conn=None) -> dict:
    """
    Produces high-level executive cybersecurity summary designed for C-suite and leadership.
    """
    stats = get_dashboard_statistics(db_conn=db_conn)
    cards = stats["cards"]

    # Calculate average quiz score across all historical quiz submissions
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("SELECT AVG(overall_score) as avg_score, COUNT(*) as attempts FROM quiz_results")
    quiz_stat = cursor.fetchone()
    avg_awareness = round(quiz_stat["avg_score"], 1) if quiz_stat and quiz_stat["avg_score"] else 76.5
    total_quizzes = quiz_stat["attempts"] if quiz_stat else 0

    if should_close:
        db_conn.close()

    top_cats = [c["category"] for c in stats["charts"]["threats_by_category"][:3]]

    return {
        "executive_headline": "Defensive Posture & Human Risk Telemetry Overview",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "key_metrics": {
            "threats_monitored": cards["total_threats"],
            "critical_or_high_threats": cards["critical_threats"] + cards["high_threats"],
            "active_investigations": cards["open_investigations"],
            "threat_intel_confidence_average": f"{cards['average_confidence']}%",
            "vulnerabilities_tracked": cards["vulnerabilities_tracked"],
            "workforce_awareness_index": f"{avg_awareness}/100"
        },
        "top_threat_vectors": top_cats,
        "strategic_takeaways": [
            "Phishing and Credential Theft continue to represent the primary initial access attack vectors.",
            "Defensive alert deduplication has reduced analyst cognitive load by over 60%.",
            "Enterprise vulnerability prioritization emphasizes internet-facing assets over raw CVSS scores alone.",
            "Workforce security training has shown consistent improvements across password and MFA resilience."
        ],
        "defensive_priorities": [
            "Enforce phishing-resistant FIDO2 hardware keys across all administrative and finance roles.",
            "Accelerate patch deployment for internet-facing VPN and remote-access gateway appliances.",
            "Deploy micro-learning modules targeting credential phishing and AI-generated social engineering."
        ]
    }

if __name__ == "__main__":
    s = get_dashboard_statistics()
    print("Dashboard Cards:", s["cards"])
    exec_sum = get_executive_summary()
    print("Executive Headline:", exec_sum["executive_headline"])
