"""
MITRE ATT&CK Mapping & Visualization Engine
Module: backend.services.attack_mapper

Maps defensive threat telemetry to the MITRE ATT&CK Enterprise Matrix.

IMPORTANT DEFENSIVE PRINCIPLE:
Indicators of Compromise (IOCs) describe WHAT technical artifacts were observed (e.g., an IP or hash).
MITRE ATT&CK describes HOW an adversary operates across tactics, techniques, and procedures (TTPs).
Mapping is performed only when sufficient behavioral context exists, avoiding speculative mappings.
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection

# Curated reference of current MITRE ATT&CK Enterprise Matrix definitions
MITRE_ATTACK_TACTICS = {
    "Initial Access": "Adversaries trying to get into your network.",
    "Execution": "Adversaries trying to run malicious code.",
    "Persistence": "Adversaries trying to maintain their foothold.",
    "Privilege Escalation": "Adversaries trying to gain higher-level permissions.",
    "Defense Evasion": "Adversaries trying to avoid being detected.",
    "Credential Access": "Adversaries trying to steal account names and passwords.",
    "Discovery": "Adversaries trying to figure out your environment.",
    "Lateral Movement": "Adversaries trying to move through your environment.",
    "Collection": "Adversaries trying to gather data of interest to their goal.",
    "Command and Control": "Adversaries trying to communicate with compromised systems to control them.",
    "Exfiltration": "Adversaries trying to steal data from your network.",
    "Impact": "Adversaries trying to manipulate, interrupt, or destroy your systems and data."
}

def get_attack_matrix_summary(db_conn=None) -> dict:
    """
    Summarizes ATT&CK tactical distribution, top techniques, and technique frequencies across the threat dataset.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()

    # Tactics frequency
    cursor.execute("""
    SELECT tactic, COUNT(*) as count
    FROM attack_mappings
    GROUP BY tactic
    ORDER BY count DESC
    """)
    tactics = [dict(r) for r in cursor.fetchall()]

    # Top Techniques
    cursor.execute("""
    SELECT technique, technique_id, tactic, COUNT(*) as count
    FROM attack_mappings
    GROUP BY technique, technique_id, tactic
    ORDER BY count DESC
    LIMIT 15
    """)
    techniques = [dict(r) for r in cursor.fetchall()]

    total_mappings = sum(t["count"] for t in tactics)

    if should_close:
        db_conn.close()

    return {
        "total_mappings": total_mappings,
        "tactics_distribution": tactics,
        "top_techniques": techniques,
        "reference_tactics": MITRE_ATTACK_TACTICS
    }

def get_threats_by_technique(technique_query: str, db_conn=None) -> list:
    """
    Returns all threats mapped to a specific technique ID or technique name.
    """
    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()
    query = f"%{technique_query.strip()}%"

    cursor.execute("""
    SELECT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score,
           t.confidence_score, t.status, t.last_seen, m.tactic, m.technique, m.technique_id
    FROM attack_mappings m
    JOIN threats t ON m.threat_id = t.threat_id
    WHERE m.technique_id LIKE ? OR m.technique LIKE ?
    ORDER BY t.risk_score DESC
    LIMIT 50
    """, (query, query))

    results = [dict(r) for r in cursor.fetchall()]

    if should_close:
        db_conn.close()

    return results

if __name__ == "__main__":
    summary = get_attack_matrix_summary()
    print("ATT&CK Total Mappings:", summary["total_mappings"])
    if summary["tactics_distribution"]:
        print("Top Tactic:", summary["tactics_distribution"][0])
    hits = get_threats_by_technique("T1566")
    print("Threats mapped to T1566 (Phishing):", len(hits))
