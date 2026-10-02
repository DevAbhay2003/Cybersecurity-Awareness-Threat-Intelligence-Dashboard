"""
Security Alert Engine & Alert Correlation
Module: backend.services.alert_engine

Generates defensive security alerts based on risk and confidence thresholds.
Implements alert deduplication and correlation to prevent SOC alert fatigue.

IMPORTANT DEFENSIVE PRINCIPLE:
Alert fatigue occurs when analysts are overwhelmed by hundreds of identical, low-context alerts.
Alert correlation aggregates repeated sightings of the same indicator into a single correlated
alert with an escalated observation counter, preserving analyst attention for genuine triage.
"""

import os
import sys
import uuid
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection

def should_generate_alert(risk_score: int, severity: str, confidence_score: int, observation_count: int) -> bool:
    """Determines whether a defensive indicator crosses the alert threshold."""
    if risk_score >= 65:
        return True
    if severity.upper() in ["HIGH", "CRITICAL"]:
        return True
    if observation_count >= 50 and confidence_score >= 60:
        return True
    return False

def correlate_alerts(threat_id: str, new_observation_count: int = 1, db_conn=None) -> dict:
    """
    Checks if an active alert already exists for this threat_id.
    If yes, increments observation count instead of generating a redundant duplicate alert.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("""
    SELECT * FROM alerts
    WHERE threat_id = ? AND status IN ('NEW', 'INVESTIGATING', 'MONITORING')
    ORDER BY created_at DESC
    LIMIT 1
    """, (threat_id,))
    existing = cursor.fetchone()

    if existing:
        updated_count = existing["observation_count"] + new_observation_count
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
        UPDATE alerts
        SET observation_count = ?, created_at = ?
        WHERE alert_id = ?
        """, (updated_count, now_str, existing["alert_id"]))
        db_conn.commit()

        cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (existing["alert_id"],))
        updated_alert = dict(cursor.fetchone())
        updated_alert["was_deduplicated"] = True

        if should_close:
            db_conn.close()
        return updated_alert

    if should_close:
        db_conn.close()
    return None

def generate_threat_alert(threat_data: dict, db_conn=None) -> dict:
    """
    Evaluates threat metadata and generates a new alert or updates an existing correlated alert.
    """
    risk = int(threat_data.get("risk_score", 0))
    severity = threat_data.get("severity", "MEDIUM")
    confidence = int(threat_data.get("confidence_score", 50))
    obs_count = int(threat_data.get("observation_count", 1))
    threat_id = threat_data.get("threat_id")

    if not should_generate_alert(risk, severity, confidence, obs_count):
        return {
            "alert_created": False,
            "reason": "Threat telemetry does not meet alert generation threshold (Risk < 65 and non-Critical/High)."
        }

    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    # 1. Attempt correlation/deduplication first
    correlated = correlate_alerts(threat_id, new_observation_count=1, db_conn=db_conn)
    if correlated:
        if should_close:
            db_conn.close()
        return {
            "alert_created": False,
            "was_deduplicated": True,
            "message": "Observation merged into existing active alert to prevent alert fatigue.",
            "alert": correlated
        }

    # 2. Create new alert
    cursor = db_conn.cursor()
    alert_id = f"ALT-2026-{uuid.uuid4().hex[:6].upper()}"
    alert_type = f"{threat_data.get('category', 'SECURITY')} Detection Alert"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    desc = f"Elevated defensive alert for {threat_data.get('threat_name', threat_id)} (Risk: {risk}/100, Confidence: {confidence}%)."

    cursor.execute("""
    INSERT INTO alerts (
        alert_id, threat_id, indicator_value, alert_type, severity,
        risk_score, confidence_score, description, status, observation_count, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        threat_id,
        threat_data.get("indicator_value", threat_id),
        alert_type,
        severity,
        risk,
        confidence,
        desc,
        "NEW",
        obs_count,
        now_str
    ))
    db_conn.commit()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    new_alert = dict(cursor.fetchone())
    new_alert["alert_created"] = True
    new_alert["was_deduplicated"] = False

    if should_close:
        db_conn.close()

    return new_alert

def update_alert_status(alert_id: str, new_status: str, db_conn=None) -> dict:
    """Updates operational triage status for an alert."""
    allowed = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]
    status_upper = new_status.upper().strip()
    if status_upper not in allowed:
        return {"success": False, "error": f"Invalid status. Must be one of: {allowed}"}

    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status_upper, alert_id))
    db_conn.commit()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    updated = cursor.fetchone()

    if should_close:
        db_conn.close()

    if updated:
        return {"success": True, "alert": dict(updated)}
    return {"success": False, "error": f"Alert {alert_id} not found."}

if __name__ == "__main__":
    t_test = {
        "threat_id": "THR-2026-0001",
        "threat_name": "Synthetic Credential Phishing Campaign",
        "category": "PHISHING",
        "severity": "HIGH",
        "risk_score": 78,
        "confidence_score": 85,
        "observation_count": 142
    }
    res = generate_threat_alert(t_test)
    print("Alert Test Result:", res)
