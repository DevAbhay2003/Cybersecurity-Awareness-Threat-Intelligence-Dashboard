"""
Defensive Security Utilities & Input Sanitization
Module: backend.utils.helpers

Provides input sanitization, XSS prevention, defensive TLP labeling,
and API formatting helpers.
"""

import html
import re
from flask import jsonify

def sanitize_input(value: str) -> str:
    """
    Sanitizes user input to prevent Cross-Site Scripting (XSS) and injection attacks.
    Escapes HTML entities and strips suspicious control characters.
    """
    if not isinstance(value, str):
        return ""
    # Strip dangerous script/eval tags
    cleaned = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", value, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"javascript:", "", cleaned, flags=re.IGNORECASE)
    # Escape HTML special characters
    return html.escape(cleaned.strip())

def format_api_response(data=None, message="Success", status_code=200, error=None):
    """
    Standardized REST API JSON envelope.
    """
    payload = {
        "status": "success" if error is None else "error",
        "status_code": status_code,
        "message": message,
        "data": data
    }
    if error:
        payload["error"] = error
    return jsonify(payload), status_code

def get_tlp_classification(source_reliability: str, risk_score: int) -> dict:
    """
    Maps Traffic Light Protocol (TLP 2.0) sharing restrictions:
    TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED
    """
    if risk_score >= 80 or source_reliability.startswith("A"):
        return {"tlp": "TLP:AMBER+STRICT", "color": "#d97706", "description": "Restricted to internal SOC and designated IR personnel."}
    elif risk_score >= 60:
        return {"tlp": "TLP:AMBER", "color": "#f59e0b", "description": "Limited disclosure within organization and defense partners."}
    elif risk_score >= 40:
        return {"tlp": "TLP:GREEN", "color": "#10b981", "description": "Shareable across community defensive stakeholders."}
    else:
        return {"tlp": "TLP:CLEAR", "color": "#6b7280", "description": "Public defensive intelligence; no distribution restrictions."}
