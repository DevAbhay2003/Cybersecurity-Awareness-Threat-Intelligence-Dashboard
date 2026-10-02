"""
Threat Enrichment Engine
Module: backend.services.enrichment_engine

Performs purely LOCAL, offline enrichment against local synthetic intelligence databases.

DEFENSIVE SAFETY DIRECTIVE:
Never perform live network lookups, ping, curl, or reverse DNS lookups against
suspicious indicators. All enrichment is conducted strictly in-memory against
sanitized local defensive datasets.
"""

import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection
from backend.services.ioc_validator import validate_indicator

def get_defensive_actions_for_category(category: str) -> list:
    """Returns recommended defensive SOC actions based on threat category."""
    actions = {
        "PHISHING": [
            "Review email gateway logs for related incoming sender domains or subject lines",
            "Check endpoint email client telemetry for user clicks or credential submissions",
            "Verify whether targeted accounts have MFA enabled; reset credentials if clicked",
            "Add indicator to defensive proxy/firewall blocklists in monitoring mode",
            "Deploy targeted phishing awareness micro-learning to affected departments"
        ],
        "MALWARE": [
            "Search endpoint EDR telemetry for matching file hash executions or staging paths",
            "Isolate suspicious host systems to prevent lateral movement across subnets",
            "Extract memory dump for volatile artifact analysis without rebooting host",
            "Block outbound C2 communication channels at enterprise perimeter firewall",
            "Update endpoint signature baselines and schedule full antivirus scans"
        ],
        "RANSOMWARE": [
            "Immediately disconnect affected endpoint from wireless and wired network adapters",
            "Verify immutability and air-gap status of offline enterprise backups",
            "Audit Volume Shadow Copy and backup agent logs for unauthorized deletion attempts",
            "Check for suspicious lateral movement via SMB, RDP, or WMI protocols",
            "Activate Incident Response Plan (IRP) and notify designated crisis leadership"
        ],
        "CREDENTIAL THREATS": [
            "Enforce immediate password reset and revoke all active cloud session tokens",
            "Audit authentication logs for anomalous geolocation or impossible travel anomalies",
            "Mandate phishing-resistant FIDO2 hardware keys or authenticator number matching",
            "Search for unauthorized OAuth third-party enterprise application consents",
            "Review dark-web credential leak telemetry for corporate domain mentions"
        ],
        "WEB THREATS": [
            "Inspect web application firewall (WAF) logs for injection or scraping attempts",
            "Validate SSL/TLS certificate chain and domain registration WHOIS creation dates",
            "Implement browser isolation or URL categorization filtering on egress proxies",
            "Check Content Security Policy (CSP) headers on corporate web properties",
            "Verify client browser patch levels against known browser zero-day advisories"
        ],
        "NETWORK THREATS": [
            "Analyze NetFlow and firewall session tables for abnormal outbound data spikes",
            "Inspect DNS query logs for high-entropy Domain Generation Algorithms (DGA)",
            "Review VPN and remote access logs for unauthorized simultaneous sessions",
            "Verify network segmentation rules between corporate and operational technology (OT)",
            "Deploy IDS/IPS intrusion rules for matching network signature patterns"
        ],
        "VULNERABILITY EXPOSURE": [
            "Scan internal and external assets to determine exact patch and version baseline",
            "Prioritize remediation based on CVSS score, asset criticality, and internet exposure",
            "Apply vendor security patch or deploy temporary virtual patching WAF rule",
            "Isolate vulnerable test or legacy systems to restricted staging VLANs",
            "Verify patch integrity and run post-remediation confirmation scans"
        ],
        "SOCIAL ENGINEERING": [
            "Alert service desk and executive assistants regarding active impersonation attempts",
            "Re-enforce dual-approval protocol for all wire transfers and bank changes",
            "Publish internal security advisory detailing caller pretexts or deceptive scripts",
            "Review visitor logs and inspect physical access badge readers for tailgating",
            "Promote blameless incident reporting culture across all business units"
        ],
        "DATA EXPOSURE": [
            "Audit cloud storage buckets (AWS S3, Azure Blob) for unintended public access",
            "Scan public code repositories (GitHub, GitLab) for committed secrets or API tokens",
            "Rotate exposed API keys, certificates, and access tokens immediately",
            "Engage Data Protection Officer (DPO) to assess regulatory reporting mandates",
            "Deploy Data Loss Prevention (DLP) filters on endpoint USB and email channels"
        ],
        "ACCOUNT SECURITY": [
            "Review privileged Identity Management (PIM) and Azure AD/Okta sign-in logs",
            "Disable legacy authentication protocols (e.g., IMAP, POP3) that bypass MFA",
            "Audit Active Directory administrative group memberships for privilege escalation",
            "Configure conditional access policies restricting logins to compliant devices",
            "Conduct quarterly access reviews to remove stale or orphaned accounts"
        ]
    }
    return actions.get(category.upper(), [
        "Perform internal log correlation against SIEM and endpoint telemetry",
        "Add indicator to defensive threat watchlists",
        "Conduct peer review with senior threat intelligence analyst"
    ])

def enrich_indicator(indicator_input: str, db_conn=None) -> dict:
    """
    Validates the indicator and enriches it with contextual threat intelligence from the local database.
    """
    validation = validate_indicator(indicator_input)
    norm_val = validation["normalized_value"]

    should_close = False
    if db_conn is None:
        db_conn = get_db_connection()
        should_close = True

    cursor = db_conn.cursor()

    # Search threats for matching indicator_value or threat_id
    cursor.execute("""
    SELECT t.*, i.indicator_type as direct_ind_type, i.indicator_value as direct_ind_val
    FROM threats t
    LEFT JOIN indicators i ON t.threat_id = i.threat_id
    WHERE LOWER(i.indicator_value) = LOWER(?)
       OR LOWER(t.threat_id) = LOWER(?)
    ORDER BY t.risk_score DESC
    LIMIT 1
    """, (norm_val, norm_val))

    threat_match = cursor.fetchone()

    # Search vulnerabilities if it's a CVE
    cursor.execute("""
    SELECT * FROM vulnerabilities
    WHERE LOWER(cve_id) = LOWER(?) OR LOWER(vulnerability_id) = LOWER(?)
    LIMIT 1
    """, (norm_val, norm_val))
    vuln_match = cursor.fetchone()

    if threat_match:
        t_id = threat_match["threat_id"]

        # Fetch ATT&CK mappings
        cursor.execute("SELECT tactic, technique, technique_id FROM attack_mappings WHERE threat_id = ?", (t_id,))
        attacks = [dict(r) for r in cursor.fetchall()]

        # Fetch alerts
        cursor.execute("SELECT * FROM alerts WHERE threat_id = ? ORDER BY created_at DESC", (t_id,))
        alerts = [dict(r) for r in cursor.fetchall()]

        # Fetch analyst notes
        cursor.execute("SELECT author, note, created_at FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (t_id,))
        notes = [dict(r) for r in cursor.fetchall()]

        # Fetch related indicators
        related = []
        if threat_match["related_indicators"]:
            related = [x.strip() for x in threat_match["related_indicators"].split(";") if x.strip()]

        cat = threat_match["category"]
        recommended_actions = get_defensive_actions_for_category(cat)

        enrichment_result = {
            "valid": validation["valid"],
            "indicator_type": threat_match["direct_ind_type"] or validation["indicator_type"],
            "normalized_value": norm_val,
            "validation_notes": validation["validation_notes"],
            "known_in_dataset": True,
            "threat_id": threat_match["threat_id"],
            "threat_name": threat_match["threat_name"],
            "category": cat,
            "severity": threat_match["severity"],
            "risk_score": threat_match["risk_score"],
            "confidence_score": threat_match["confidence_score"],
            "status": threat_match["status"],
            "source_name": threat_match["source_name"],
            "source_reliability": threat_match["source_reliability"],
            "first_seen": threat_match["first_seen"],
            "last_seen": threat_match["last_seen"],
            "observation_count": threat_match["observation_count"],
            "description": threat_match["description"],
            "campaign_id": threat_match["campaign_id"],
            "related_indicators": related,
            "attack_mapping": attacks,
            "alerts": alerts,
            "analyst_notes": notes,
            "cve_association": vuln_match["cve_id"] if vuln_match else None,
            "recommended_actions": recommended_actions,
            "enrichment_source": "Local Defensive Threat Database"
        }
    elif vuln_match:
        enrichment_result = {
            "valid": validation["valid"],
            "indicator_type": "CVE ID",
            "normalized_value": vuln_match["cve_id"],
            "validation_notes": validation["validation_notes"],
            "known_in_dataset": True,
            "threat_id": vuln_match["vulnerability_id"],
            "threat_name": f"Security Exposure {vuln_match['cve_id']}",
            "category": "VULNERABILITY EXPOSURE",
            "severity": vuln_match["severity"],
            "risk_score": vuln_match["priority_score"],
            "confidence_score": 95,
            "status": "MONITORING",
            "source_name": "Vulnerability Database",
            "source_reliability": "A – Highly Reliable",
            "first_seen": vuln_match["published_date"],
            "last_seen": vuln_match["published_date"],
            "observation_count": 1,
            "description": vuln_match["description"],
            "campaign_id": "NONE",
            "related_indicators": [],
            "attack_mapping": [{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application (T1190)", "technique_id": "T1190"}],
            "alerts": [],
            "analyst_notes": [{"author": "Vulnerability Analyst", "note": f"Patch available: {vuln_match['patch_available']}. Asset criticality: {vuln_match['asset_criticality']}.", "created_at": vuln_match["published_date"]}],
            "cve_association": vuln_match["cve_id"],
            "recommended_actions": get_defensive_actions_for_category("VULNERABILITY EXPOSURE"),
            "enrichment_source": "Local Vulnerability Knowledgebase"
        }
    else:
        # Not known in local dataset, but valid syntax
        enrichment_result = {
            "valid": validation["valid"],
            "indicator_type": validation["indicator_type"],
            "normalized_value": norm_val,
            "validation_notes": validation["validation_notes"],
            "known_in_dataset": False,
            "threat_id": "UNKNOWN",
            "threat_name": "Uncorrelated Indicator",
            "category": "UNKNOWN",
            "severity": "INFORMATIONAL",
            "risk_score": 10 if validation["valid"] else 0,
            "confidence_score": 30 if validation["valid"] else 0,
            "status": "NEW",
            "source_name": "Direct Analyst Query",
            "source_reliability": "D – Reliability Unknown",
            "first_seen": "N/A",
            "last_seen": "N/A",
            "observation_count": 0,
            "description": "Indicator is not currently present in the local defensive dataset. No matching telemetry found.",
            "campaign_id": "NONE",
            "related_indicators": [],
            "attack_mapping": [],
            "alerts": [],
            "analyst_notes": [],
            "cve_association": None,
            "recommended_actions": [
                "Validate indicator against internal network and authentication proxy logs",
                "Create new defensive tracking ticket if telemetry shows active internal sighting",
                "Ensure indicator adheres to threat intelligence sharing guidelines (TLP standards)"
            ],
            "enrichment_source": "Local Validator Engine"
        }

    if should_close:
        db_conn.close()

    return enrichment_result

if __name__ == "__main__":
    res = enrich_indicator("login-check.invalid")
    print("Enrichment Demo for login-check.invalid:")
    print("Found:", res["known_in_dataset"])
    print("Threat ID:", res["threat_id"])
    print("Risk / Confidence:", res["risk_score"], res["confidence_score"])
    print("Actions:", res["recommended_actions"][:2])
