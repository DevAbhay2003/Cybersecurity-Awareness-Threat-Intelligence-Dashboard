"""
Security Alert Management Routes
Module: backend.routes.alert_routes
"""

import os
import sys
from flask import Blueprint, request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection
from backend.services.alert_engine import update_alert_status, generate_threat_alert
from backend.utils.helpers import sanitize_input, format_api_response

alert_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")

@alert_bp.route("", methods=["GET"])
def list_alerts():
    """
    GET /api/alerts
    Query params: status, severity, limit
    """
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = min(200, max(1, int(request.args.get("limit", 50))))

    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = ["1=1"]
    params = []

    if status and status.upper() != "ALL":
        conditions.append("status = ?")
        params.append(status.upper().strip())

    if severity and severity.upper() != "ALL":
        conditions.append("severity = ?")
        params.append(severity.upper().strip())

    where = " AND ".join(conditions)

    cursor.execute(f"""
    SELECT alert_id, threat_id, indicator_value, alert_type, severity,
           risk_score, confidence_score, description, status, observation_count, created_at
    FROM alerts
    WHERE {where}
    ORDER BY created_at DESC, risk_score DESC
    LIMIT ?
    """, params + [limit])

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return format_api_response(data={"alerts": rows, "count": len(rows)}, message="Alerts retrieved successfully")

@alert_bp.route("/<alert_id>", methods=["GET"])
def get_single_alert(alert_id):
    clean_id = sanitize_input(alert_id).upper()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (clean_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return format_api_response(error=f"Alert '{clean_id}' not found.", status_code=404)

    return format_api_response(data=dict(row), message="Alert details retrieved")

@alert_bp.route("/<alert_id>/status", methods=["PUT"])
def update_status(alert_id):
    """
    PUT /api/alerts/{id}/status
    Body: {"status": "INVESTIGATING" | "MONITORING" | "RESOLVED" | "FALSE_POSITIVE"}
    """
    clean_id = sanitize_input(alert_id).upper()
    body = request.get_json() or {}
    new_status = sanitize_input(body.get("status", ""))

    if not new_status:
        return format_api_response(error="Missing required 'status' in request body.", status_code=400)

    res = update_alert_status(clean_id, new_status)
    if not res["success"]:
        return format_api_response(error=res.get("error", "Failed to update alert status"), status_code=400)

    return format_api_response(data=res["alert"], message=f"Alert '{clean_id}' status updated to {new_status.upper()}")
