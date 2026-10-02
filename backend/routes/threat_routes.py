"""
Threat Intelligence API Routes
Module: backend.routes.threat_routes
"""

import os
import sys
from flask import Blueprint, request, jsonify

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection
from backend.services.threat_service import (
    get_threats, get_threat_by_id, add_analyst_note, update_threat_status
)
from backend.services.correlation_engine import generate_threat_timeline
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk
from backend.services.alert_engine import generate_threat_alert
from backend.utils.helpers import sanitize_input, format_api_response, get_tlp_classification

threat_bp = Blueprint("threats", __name__, url_prefix="/api/threats")

@threat_bp.route("", methods=["GET"])
def list_threats():
    """
    GET /api/threats
    Query parameters:
    - severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, ALL)
    - category (PHISHING, MALWARE, etc., or ALL)
    - indicator_type (IP ADDRESS, DOMAIN, etc., or ALL)
    - status (NEW, MONITORING, CLOSED, etc., or ALL)
    - search (text query)
    - sort_by (newest, highest_risk, highest_confidence, most_observed)
    - page (int)
    - page_size (int)
    """
    severity = request.args.get("severity")
    category = request.args.get("category")
    indicator_type = request.args.get("indicator_type")
    status = request.args.get("status")
    search = request.args.get("search")
    sort_by = request.args.get("sort_by", "newest")
    
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(100, max(1, int(request.args.get("page_size", 20))))
    except ValueError:
        page, page_size = 1, 20

    data = get_threats(
        severity=severity,
        category=category,
        indicator_type=indicator_type,
        status=status,
        search=search,
        sort_by=sort_by,
        page=page,
        page_size=page_size
    )

    return format_api_response(data=data, message="Threat records retrieved successfully")

@threat_bp.route("/<threat_id>", methods=["GET"])
def get_single_threat(threat_id):
    """
    GET /api/threats/{id}
    Retrieves full details including indicators, ATT&CK mapping, and analyst notes.
    """
    clean_id = sanitize_input(threat_id).upper()
    threat = get_threat_by_id(clean_id)

    if not threat:
        return format_api_response(error=f"Threat '{clean_id}' not found.", status_code=404)

    # Attach TLP rating
    threat["tlp"] = get_tlp_classification(threat["source_reliability"], threat["risk_score"])

    return format_api_response(data=threat, message="Threat details retrieved")

@threat_bp.route("/<threat_id>/timeline", methods=["GET"])
def get_timeline(threat_id):
    """
    GET /api/threats/{id}/timeline
    Returns incident milestones for the threat.
    """
    clean_id = sanitize_input(threat_id).upper()
    timeline = generate_threat_timeline(clean_id)
    return format_api_response(data=timeline, message="Threat timeline retrieved")

@threat_bp.route("", methods=["POST"])
def create_threat():
    """
    POST /api/threats
    Analyst creates a new defensive threat intelligence entry.
    Body:
    {
        "threat_name": "Synthetic Test Phish",
        "category": "PHISHING",
        "indicator_type": "DOMAIN",
        "indicator_value": "auth-verify.invalid",
        "severity": "HIGH",
        "confidence_score": 85,
        "source_name": "Internal SOC",
        "source_reliability": "A – Highly Reliable",
        "description": "Observed phishing telemetry."
    }
    """
    body = request.get_json() or {}
    name = sanitize_input(body.get("threat_name", "")).strip()
    category = sanitize_input(body.get("category", "PHISHING")).upper().strip()
    ind_val = sanitize_input(body.get("indicator_value", "")).strip()
    severity = sanitize_input(body.get("severity", "MEDIUM")).upper().strip()
    source_name = sanitize_input(body.get("source_name", "Internal SOC")).strip()
    source_rel = sanitize_input(body.get("source_reliability", "A – Highly Reliable")).strip()
    desc = sanitize_input(body.get("description", "Analyst submitted threat record.")).strip()

    if not name or not ind_val:
        return format_api_response(error="Missing required fields: threat_name and indicator_value are mandatory.", status_code=400)

    # Syntactic IOC Validation
    val_res = validate_indicator(ind_val)
    if not val_res["valid"]:
        return format_api_response(
            error=f"Syntactic validation failed for indicator '{ind_val}': {val_res['validation_notes']}",
            status_code=422
        )

    ind_type = val_res["indicator_type"]
    norm_ind = val_res["normalized_value"]

    confidence = max(0, min(100, int(body.get("confidence_score", 70))))

    # Calculate multi-factor risk score
    risk_data = calculate_threat_risk(
        severity=severity,
        confidence=confidence,
        recency_days=0,
        observation_count=1,
        source_reliability=source_rel
    )
    risk_score = risk_data["risk_score"]

    from datetime import datetime, timezone
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Generate sequential or UUID threat_id
    cursor.execute("SELECT COUNT(*) as count FROM threats")
    count = cursor.fetchone()["count"]
    new_id = f"THR-2026-{(count + 1):04d}"

    cursor.execute("""
    INSERT INTO threats (
        threat_id, timestamp, threat_name, category, description,
        severity, risk_score, confidence_score, status, first_seen,
        last_seen, source_name, source_reliability, campaign_id,
        related_indicators, analyst_notes, observation_count
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        new_id, now_str, name, category, desc,
        severity, risk_score, confidence, "NEW", now_str,
        now_str, source_name, source_rel, "NONE",
        "", f"Created by analyst triage. {desc}", 1
    ))

    cursor.execute("""
    INSERT INTO indicators (threat_id, indicator_type, indicator_value, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?)
    """, (new_id, ind_type, norm_ind, now_str, now_str))

    cursor.execute("""
    INSERT INTO analyst_notes (threat_id, author, note, created_at)
    VALUES (?, ?, ?, ?)
    """, (new_id, "Triage Analyst", f"Threat recorded. {val_res['validation_notes']}", now_str))

    conn.commit()

    # Check alert generation
    alert_info = generate_threat_alert({
        "threat_id": new_id,
        "threat_name": name,
        "category": category,
        "severity": severity,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "observation_count": 1,
        "indicator_value": norm_ind
    }, db_conn=conn)

    conn.close()

    return format_api_response(
        data={"threat_id": new_id, "risk_score": risk_score, "alert_result": alert_info},
        message=f"Threat '{new_id}' successfully created and validated.",
        status_code=201
    )

@threat_bp.route("/<threat_id>", methods=["PUT"])
def update_threat(threat_id):
    """
    PUT /api/threats/{id}
    Updates status or metadata.
    """
    clean_id = sanitize_input(threat_id).upper()
    body = request.get_json() or {}
    new_status = body.get("status")

    if not new_status:
        return format_api_response(error="Missing 'status' in update payload.", status_code=400)

    res = update_threat_status(clean_id, new_status)
    if not res["success"]:
        return format_api_response(error=res.get("error", "Update failed"), status_code=400)

    return format_api_response(data=res, message="Threat updated successfully")

@threat_bp.route("/<threat_id>/notes", methods=["POST"])
def add_note(threat_id):
    """
    POST /api/threats/{id}/notes
    Appends analyst note.
    """
    clean_id = sanitize_input(threat_id).upper()
    body = request.get_json() or {}
    note_text = sanitize_input(body.get("note", "")).strip()
    author = sanitize_input(body.get("author", "SOC Analyst")).strip()

    if not note_text:
        return format_api_response(error="Note text is required.", status_code=400)

    res = add_analyst_note(clean_id, author, note_text)
    if not res["success"]:
        return format_api_response(error=res.get("error", "Note creation failed"), status_code=400)

    return format_api_response(data=res["note"], message="Analyst note logged successfully", status_code=201)
