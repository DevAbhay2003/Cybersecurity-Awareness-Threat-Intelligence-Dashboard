"""
Threat Correlation Engine & Timeline Generator
Module: backend.services.correlation_engine

Clusters related defensive threat records by campaign identifiers, shared indicators,
and observation windows. Generates operational investigation timelines.

IMPORTANT DEFENSIVE PRINCIPLE:
Correlation indicates shared infrastructure, common observed telemetry, or campaign clustering.
It does NOT constitute absolute attribution or proof of a single threat actor.
"""

import os
import sys
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection

def correlate_threats(db_conn=None) -> list:
    """
    Identifies related threat clusters across the dataset based on:
    - Shared campaign_id
    - Shared indicator values
    - Common category and time proximity
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()

    # Query campaigns with multiple threats
    cursor.execute("""
    SELECT campaign_id, category, COUNT(*) as count, AVG(risk_score) as avg_risk,
           MIN(first_seen) as cluster_first_seen, MAX(last_seen) as cluster_last_seen
    FROM threats
    WHERE campaign_id != 'NONE' AND campaign_id != ''
    GROUP BY campaign_id, category
    HAVING COUNT(*) > 1
    ORDER BY count DESC
    LIMIT 25
    """)
    campaign_groups = cursor.fetchall()

    clusters = []
    for idx, cg in enumerate(campaign_groups, start=1):
        camp_id = cg["campaign_id"]
        cat = cg["category"]

        # Fetch member threats
        cursor.execute("""
        SELECT threat_id, threat_name, severity, risk_score, confidence_score, status, last_seen, related_indicators
        FROM threats
        WHERE campaign_id = ? AND category = ?
        ORDER BY risk_score DESC
        LIMIT 10
        """, (camp_id, cat))
        threats = [dict(r) for r in cursor.fetchall()]

        # Collect unique indicators in this cluster
        t_ids = [t["threat_id"] for t in threats]
        placeholders = ",".join("?" for _ in t_ids)
        cursor.execute(f"""
        SELECT DISTINCT indicator_type, indicator_value
        FROM indicators
        WHERE threat_id IN ({placeholders})
        """, t_ids)
        cluster_indicators = [dict(r) for r in cursor.fetchall()]

        clusters.append({
            "cluster_id": f"CLUS-{camp_id}-{idx}",
            "campaign_id": camp_id,
            "category": cat,
            "cluster_name": f"{camp_id.replace('-', ' ').title()} Infrastructure Cluster",
            "threat_count": cg["count"],
            "average_risk": round(cg["avg_risk"], 1),
            "first_seen": cg["cluster_first_seen"],
            "last_seen": cg["cluster_last_seen"],
            "sample_threats": threats,
            "associated_indicators": cluster_indicators,
            "attribution_confidence": "Medium (Defensive Telemetry Only - Non-Attributed)"
        })

    if should_close:
        db_conn.close()

    return clusters

def generate_threat_timeline(threat_id: str, db_conn=None) -> list:
    """
    Constructs an analyst-friendly event timeline for a specific threat:
    First Seen -> Initial Sighting -> Risk Elevation -> SOC Investigation -> Continuous Monitoring -> Current Status
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    t = cursor.fetchone()

    if not t:
        if should_close:
            db_conn.close()
        return []

    timeline = []

    # 1. First Seen Milestone
    timeline.append({
        "stage": "FIRST_SEEN",
        "timestamp": t["first_seen"],
        "title": "Initial Observation Recorded",
        "description": f"First defensive observation recorded via {t['source_name']} ({t['source_reliability']}).",
        "badge_color": "info"
    })

    # 2. Ingestion & Validation
    timeline.append({
        "stage": "VALIDATION_AND_INGESTION",
        "timestamp": t["first_seen"],
        "title": "Indicator Syntactic Validation & Normalization",
        "description": "Syntactic validation confirmed format integrity. Passed to local defensive risk engine.",
        "badge_color": "secondary"
    })

    # 3. Risk Elevation
    timeline.append({
        "stage": "RISK_CALCULATION",
        "timestamp": t["timestamp"],
        "title": f"Risk Scored: {t['risk_score']}/100 ({t['severity']})",
        "description": f"Calculated with confidence {t['confidence_score']}% across {t['observation_count']} recorded sighting(s).",
        "badge_color": "warning" if t["risk_score"] < 75 else "danger"
    })

    # 4. Campaign Correlation
    if t["campaign_id"] and t["campaign_id"] != "NONE":
        timeline.append({
            "stage": "CORRELATION",
            "timestamp": t["timestamp"],
            "title": f"Correlated with {t['campaign_id']}",
            "description": f"Associated with cluster infrastructure: {t['related_indicators'] or 'Shared campaign pattern'}.",
            "badge_color": "primary"
        })

    # 5. Current Status Milestone
    timeline.append({
        "stage": "CURRENT_STATUS",
        "timestamp": t["last_seen"],
        "title": f"Current Operational State: {t['status']}",
        "description": f"Analyst review posture set to {t['status']}. Telemetry monitored continuously in SOC queue.",
        "badge_color": "success" if t["status"] == "CLOSED" else "danger"
    })

    if should_close:
        db_conn.close()

    return timeline

if __name__ == "__main__":
    cl = correlate_threats()
    print(f"Discovered {len(cl)} correlated clusters.")
    if cl:
        print("Sample cluster:", cl[0]["cluster_name"], "Threats:", cl[0]["threat_count"])
    tl = generate_threat_timeline("THR-2026-0001")
    print(f"Timeline for THR-2026-0001 has {len(tl)} events.")
