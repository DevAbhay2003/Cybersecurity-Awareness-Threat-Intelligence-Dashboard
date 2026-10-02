"""
Indicator of Compromise (IOC) API Routes
Module: backend.routes.indicator_routes

Handles IOC syntactic validation, lookup search, and enrichment.

DEFENSIVE SAFETY DIRECTIVE:
These endpoints perform strictly passive local database and syntax queries.
No external network sockets, probes, or outbound connections are ever made.
"""

import os
import sys
from flask import Blueprint, request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.models.database import get_db_connection
from backend.utils.helpers import sanitize_input, format_api_response

indicator_bp = Blueprint("indicators", __name__, url_prefix="/api/indicators")

@indicator_bp.route("/validate", methods=["GET"])
def validate_ioc():
    """
    GET /api/indicators/validate?q=<indicator>
    Validates syntax for IPv4, IPv6, Domain, URL, Hashes, or CVE ID.
    """
    query = request.args.get("q") or request.args.get("indicator") or ""
    clean_q = sanitize_input(query).strip()

    if not clean_q:
        return format_api_response(error="Query parameter 'q' or 'indicator' is required.", status_code=400)

    val_res = validate_indicator(clean_q)
    return format_api_response(data=val_res, message="Indicator syntactic validation completed")

@indicator_bp.route("/search", methods=["GET"])
def search_ioc():
    """
    GET /api/indicators/search?q=<indicator>
    Searches the local defensive dataset and returns enriched threat intelligence.
    IMPORTANT: Passive local lookup only. No outbound network requests.
    """
    query = request.args.get("q") or request.args.get("indicator") or ""
    clean_q = sanitize_input(query).strip()

    if not clean_q:
        return format_api_response(error="Search query 'q' or 'indicator' is required.", status_code=400)

    enriched = enrich_indicator(clean_q)
    return format_api_response(data=enriched, message="Indicator lookup and enrichment completed")

@indicator_bp.route("", methods=["GET"])
def list_indicators():
    """
    GET /api/indicators
    Lists tracked indicators with optional type filter and pagination.
    """
    ind_type = request.args.get("type")
    search = request.args.get("search")
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(100, max(1, int(request.args.get("page_size", 25))))
    except ValueError:
        page, page_size = 1, 25

    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = ["1=1"]
    params = []

    if ind_type and ind_type.upper() != "ALL":
        conditions.append("indicator_type LIKE ?")
        params.append(f"%{ind_type.strip()}%")

    if search:
        s = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(indicator_value) LIKE ? OR LOWER(threat_id) LIKE ?)")
        params.extend([s, s])

    where = " AND ".join(conditions)

    cursor.execute(f"SELECT COUNT(*) as total FROM indicators WHERE {where}", params)
    total = cursor.fetchone()["total"]

    offset = (page - 1) * page_size
    cursor.execute(f"""
    SELECT indicator_id, threat_id, indicator_type, indicator_value, first_seen, last_seen
    FROM indicators
    WHERE {where}
    ORDER BY indicator_id DESC
    LIMIT ? OFFSET ?
    """, params + [page_size, offset])

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_pages = max(1, (total + page_size - 1) // page_size)

    return format_api_response(data={
        "indicators": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }, message="Indicators retrieved successfully")
