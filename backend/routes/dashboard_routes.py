"""
Dashboard Analytics & SOC Executive Routes
Module: backend.routes.dashboard_routes
"""

import os
import sys
from flask import Blueprint, request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.services.threat_service import get_dashboard_statistics, get_executive_summary
from backend.services.correlation_engine import correlate_threats
from backend.services.attack_mapper import get_attack_matrix_summary, get_threats_by_technique
from backend.utils.helpers import sanitize_input, format_api_response

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")

@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """
    GET /api/dashboard/stats
    Returns top KPI cards and data series for all 10 SOC charts.
    """
    data = get_dashboard_statistics()
    return format_api_response(data=data, message="Dashboard metrics retrieved successfully")

@dashboard_bp.route("/dashboard/trends", methods=["GET"])
def dashboard_trends():
    """
    GET /api/dashboard/trends
    Returns correlated threat clusters and campaign infrastructure groupings.
    """
    clusters = correlate_threats()
    return format_api_response(data={"clusters": clusters, "total_clusters": len(clusters)}, message="Correlated clusters retrieved")

@dashboard_bp.route("/dashboard/executive", methods=["GET"])
def executive_summary():
    """
    GET /api/dashboard/executive
    Returns high-level non-technical cybersecurity executive summary.
    """
    summary = get_executive_summary()
    return format_api_response(data=summary, message="Executive summary generated successfully")

@dashboard_bp.route("/attack/matrix", methods=["GET"])
def attack_matrix():
    """
    GET /api/attack/matrix
    Returns MITRE ATT&CK tactic frequencies and top observed techniques.
    """
    summary = get_attack_matrix_summary()
    return format_api_response(data=summary, message="MITRE ATT&CK matrix summary retrieved")

@dashboard_bp.route("/attack/techniques/<path:tech_query>", methods=["GET"])
def attack_threats(tech_query):
    """
    GET /api/attack/techniques/{tech_id}
    Returns threats associated with a specific ATT&CK technique (e.g. T1566).
    """
    clean_query = sanitize_input(tech_query).strip()
    threats = get_threats_by_technique(clean_query)
    return format_api_response(data={"technique": clean_query, "threats": threats, "count": len(threats)}, message="Technique threats retrieved")
