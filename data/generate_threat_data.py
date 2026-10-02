"""
Synthetic Defensive Threat Intelligence Data Generator
Project: Cybersecurity Awareness & Threat Intelligence Dashboard
Author: Defensive Cybersecurity Engineer & Mentor

Generates at least 2,500 safe, sanitized, synthetic threat intelligence records
using official documentation IP ranges (RFC 5737, RFC 3849), safe test domains
(RFC 2606, RFC 6761), fictional URLs, synthetic hashes, and realistic defensive metadata.
"""

import os
import csv
import random
import hashlib
from datetime import datetime, timedelta, timezone

def generate_synthetic_data(num_threats=2500, output_dir=None):
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    
    os.makedirs(output_dir, exist_ok=True)
    threat_csv_path = os.path.join(output_dir, "threat_intelligence_dataset.csv")
    vuln_csv_path = os.path.join(output_dir, "vulnerabilities.csv")

    random.seed(42)  # Deterministic generation for reproducible research and grading

    # Threat Categories
    categories = [
        "PHISHING",
        "MALWARE",
        "RANSOMWARE",
        "CREDENTIAL THREATS",
        "WEB THREATS",
        "NETWORK THREATS",
        "VULNERABILITY EXPOSURE",
        "SOCIAL ENGINEERING",
        "DATA EXPOSURE",
        "ACCOUNT SECURITY"
    ]

    sources = [
        ("Internal SOC", "A – Highly Reliable"),
        ("Security Vendor", "A – Highly Reliable"),
        ("Research Report", "B – Usually Reliable"),
        ("Public Threat Feed", "C – Fairly Reliable"),
        ("Community Submission", "C – Fairly Reliable"),
        ("Unknown Source", "D – Reliability Unknown")
    ]

    severities = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    statuses = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

    # MITRE ATT&CK Valid Tactic & Technique pairs
    attack_mappings = [
        ("Initial Access", "Phishing: Spearphishing Link", "T1566.002"),
        ("Initial Access", "Phishing: Spearphishing Attachment", "T1566.001"),
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        ("Initial Access", "External Remote Services", "T1133"),
        ("Execution", "Command and Scripting Interpreter: PowerShell", "T1059.001"),
        ("Execution", "User Execution: Malicious File", "T1204.002"),
        ("Persistence", "Account Manipulation", "T1098"),
        ("Persistence", "Scheduled Task/Job", "T1053"),
        ("Credential Access", "Brute Force: Credential Stuffing", "T1110.004"),
        ("Credential Access", "Adversary-in-the-Middle", "T1557"),
        ("Credential Access", "OS Credential Dumping", "T1003"),
        ("Discovery", "Network Service Discovery", "T1046"),
        ("Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001"),
        ("Command and Control", "DNS: Domain Generation Algorithms", "T1568.002"),
        ("Exfiltration", "Exfiltration Over C2 Channel", "T1041"),
        ("Impact", "Data Encrypted for Impact", "T1486"),
        ("Impact", "Account Wipeout / Disruption", "T1531")
    ]

    # Safe documentation address pools (RFC 5737 and RFC 3849)
    safe_ipv4_prefixes = ["192.0.2.", "198.51.100.", "203.0.113."]
    safe_domain_stems = [
        "auth-portal", "update-service", "vpn-gateway", "payroll-verify",
        "cloud-sync", "cdn-static", "security-alert", "billing-check",
        "telemetry-node", "api-gateway", "login-check", "session-verify",
        "patch-delivery", "sso-connect", "file-download"
    ]
    safe_tlds = [".invalid", ".example.com", ".example.org", ".example.net"]

    countries = ["US", "DE", "GB", "NL", "FR", "SG", "JP", "AU", "CA", "CH", "GLOBAL"]

    threat_rows = []
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    # 1. ALWAYS inject the required demonstration scenario threat THR-2026-0001
    threat_rows.append({
        "threat_id": "THR-2026-0001",
        "timestamp": (base_time - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threat_name": "Synthetic Credential Phishing Campaign",
        "threat_category": "PHISHING",
        "indicator_type": "DOMAIN",
        "indicator_value": "login-check.invalid",
        "source_name": "Internal SOC",
        "source_reliability": "A – Highly Reliable",
        "confidence_score": 85,
        "severity": "HIGH",
        "risk_score": 78,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": (base_time - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "country_or_region_optional": "US",
        "description": "Synthetic credential phishing portal masquerading as single sign-on authentication gateway. Correlated with malicious IP 198.51.100.25.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Phishing: Spearphishing Link (T1566.002)",
        "cve_id_optional": "",
        "campaign_id": "CAMP-2026-PHISH-A",
        "related_indicators": "198.51.100.25; support-desk.invalid",
        "analyst_notes": "Indicator appears in multiple synthetic phishing observations. Correlated with infrastructure cluster CAMP-2026-PHISH-A.",
        "observation_count": 142
    })

    # Related IP for the demonstration scenario
    threat_rows.append({
        "threat_id": "THR-2026-0002",
        "timestamp": (base_time - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threat_name": "Synthetic Phishing Hosting Node",
        "threat_category": "PHISHING",
        "indicator_type": "IP ADDRESS",
        "indicator_value": "198.51.100.25",
        "source_name": "Security Vendor",
        "source_reliability": "A – Highly Reliable",
        "confidence_score": 90,
        "severity": "HIGH",
        "risk_score": 80,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": (base_time - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "country_or_region_optional": "US",
        "description": "Safe documentation IP hosting synthetic phishing web pages targeting enterprise credentials.",
        "mitre_tactic_optional": "Command and Control",
        "mitre_technique_optional": "Application Layer Protocol: Web Protocols (T1071.001)",
        "cve_id_optional": "",
        "campaign_id": "CAMP-2026-PHISH-A",
        "related_indicators": "login-check.invalid",
        "analyst_notes": "Hosting node for login-check.invalid. Defensive monitoring active.",
        "observation_count": 285
    })

    # Campaigns for correlation
    campaign_pool = [
        "CAMP-2026-PHISH-A", "CAMP-2026-RANSOM-SHADOW", "CAMP-2026-INFOCRED-STEALER",
        "CAMP-2026-WEBSHELL-APT", "CAMP-2026-CLOUD-SPRAY", "CAMP-2026-SUPPLY-CHAIN",
        "NONE"
    ]

    for i in range(3, num_threats + 1):
        threat_id = f"THR-2026-{i:04d}"
        category = random.choice(categories)
        source_name, source_reliability = random.choice(sources)
        severity = random.choices(severities, weights=[15, 25, 30, 20, 10])[0]

        # Indicator Type
        ind_type = random.choice(["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"])

        if ind_type == "IP ADDRESS":
            prefix = random.choice(safe_ipv4_prefixes)
            last_octet = random.randint(1, 254)
            indicator_val = f"{prefix}{last_octet}"
            name = f"Synthetic Suspicious Host {indicator_val}"
            desc = f"Observed suspicious defensive connection telemetry involving safe documentation IP {indicator_val}."
        elif ind_type == "DOMAIN":
            stem = random.choice(safe_domain_stems)
            tld = random.choice(safe_tlds)
            indicator_val = f"{stem}-{random.randint(10, 999)}{tld}"
            name = f"Synthetic Malicious Domain {indicator_val}"
            desc = f"Synthetic defensive domain telemetry flagged in correlation with {category.lower()} activity."
        elif ind_type == "URL":
            stem = random.choice(safe_domain_stems)
            tld = random.choice(safe_tlds)
            indicator_val = f"https://{stem}-{random.randint(10, 999)}{tld}/path/resource?auth={random.randint(1000, 9999)}"
            name = f"Synthetic Deceptive URI Resource"
            desc = f"Sanitized synthetic URI detected in email gateway inspection telemetry."
        elif ind_type == "FILE HASH":
            synthetic_seed = f"synthetic-payload-{i}-{random.random()}"
            indicator_val = hashlib.sha256(synthetic_seed.encode("utf-8")).hexdigest()
            name = f"Synthetic Malware Sample Binary [SHA-256]"
            desc = f"Synthetic hash signature representing simulated {category.lower()} payload. SYNTHETIC / DEMO ONLY."
        elif ind_type == "EMAIL/SENDER DOMAIN":
            stem = random.choice(safe_domain_stems)
            tld = random.choice(safe_tlds)
            indicator_val = f"alerts@{stem}{tld}"
            name = f"Synthetic Deceptive Sender Identity"
            desc = f"Synthetic sender address exhibiting SPF/DKIM validation failures in simulated mail logs."
        else: # CVE ID
            cve_num = random.randint(1000, 9999)
            indicator_val = f"CVE-2026-{cve_num}"
            name = f"Synthetic Security Vulnerability Exposure {indicator_val}"
            desc = f"Defensive vulnerability intelligence tracked for unpatched enterprise software assets."

        # Dates within last 45 days
        days_ago = random.randint(0, 45)
        last_seen_dt = base_time - timedelta(days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59))
        first_seen_dt = last_seen_dt - timedelta(days=random.randint(1, 30))

        confidence = random.randint(40, 98)
        if source_reliability.startswith("A"):
            confidence = max(confidence, random.randint(75, 99))
        elif source_reliability.startswith("D"):
            confidence = min(confidence, random.randint(25, 60))

        # Risk score calculation
        sev_weights = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 78, "CRITICAL": 95}
        base_risk = sev_weights[severity]
        risk_score = int(min(100, max(5, (base_risk * 0.5) + (confidence * 0.3) + (random.randint(5, 20)))))

        status = random.choices(statuses, weights=[30, 25, 25, 15, 5])[0]

        # MITRE ATT&CK mapping
        if category in ["PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "NETWORK THREATS"]:
            tactic, tech_name, tech_id = random.choice(attack_mappings)
            mitre_tactic = tactic
            mitre_technique = f"{tech_name} ({tech_id})"
        else:
            mitre_tactic = ""
            mitre_technique = ""

        cve_id_val = indicator_val if ind_type == "CVE ID" else (f"CVE-2026-{random.randint(1000, 9999)}" if random.random() < 0.15 else "")
        campaign = random.choices(campaign_pool, weights=[15, 15, 15, 10, 10, 10, 25])[0]
        obs_count = random.randint(1, 450) if status != "CLOSED" else 1

        threat_rows.append({
            "threat_id": threat_id,
            "timestamp": last_seen_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "threat_name": name,
            "threat_category": category,
            "indicator_type": ind_type,
            "indicator_value": indicator_val,
            "source_name": source_name,
            "source_reliability": source_reliability,
            "confidence_score": confidence,
            "severity": severity,
            "risk_score": risk_score,
            "status": status,
            "first_seen": first_seen_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_seen": last_seen_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country_or_region_optional": random.choice(countries),
            "description": desc,
            "mitre_tactic_optional": mitre_tactic,
            "mitre_technique_optional": mitre_technique,
            "cve_id_optional": cve_id_val,
            "campaign_id": campaign,
            "related_indicators": f"192.0.2.{random.randint(1, 254)}" if campaign != "NONE" else "",
            "analyst_notes": f"Synthetic defensive record generated for testing and SOC workflow education. Campaign: {campaign}.",
            "observation_count": obs_count
        })

    # Write Threat CSV
    threat_headers = [
        "threat_id", "timestamp", "threat_name", "threat_category",
        "indicator_type", "indicator_value", "source_name", "source_reliability",
        "confidence_score", "severity", "risk_score", "status",
        "first_seen", "last_seen", "country_or_region_optional",
        "description", "mitre_tactic_optional", "mitre_technique_optional",
        "cve_id_optional", "campaign_id", "related_indicators",
        "analyst_notes", "observation_count"
    ]

    with open(threat_csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=threat_headers)
        writer.writeheader()
        writer.writerows(threat_rows)

    print(f"Successfully generated {len(threat_rows)} synthetic threat records at: {threat_csv_path}")

    # 2. Generate Vulnerabilities CSV (50+ defensive vulnerability records)
    vuln_rows = []
    vuln_categories = [
        "Web Server", "Remote Access / SSL VPN", "Operating System Kernel",
        "Database Engine", "Identity Provider / SSO", "Container Runtime",
        "Enterprise Email Gateway", "Cryptographic Library", "Cloud Management Agent"
    ]
    exploit_statuses = ["KNOWN_EXPLOITED", "PROOF_OF_CONCEPT", "UNPROVEN"]
    asset_criticalities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    exposures = ["INTERNET_FACING", "INTERNAL_ONLY", "ISOLATED_TEST"]

    for v_idx in range(1, 60):
        cve_id = f"CVE-2026-{1000 + v_idx}"
        prod_cat = random.choice(vuln_categories)
        cvss = round(random.uniform(4.0, 9.9), 1)
        if cvss >= 9.0:
            v_sev = "CRITICAL"
        elif cvss >= 7.0:
            v_sev = "HIGH"
        elif cvss >= 4.0:
            v_sev = "MEDIUM"
        else:
            v_sev = "LOW"

        patch = random.choice(["YES", "YES", "YES", "NO"])
        exploit_demo = random.choice(exploit_statuses)
        crit = random.choice(asset_criticalities)
        exp = random.choice(exposures)

        # Contextual Prioritization Engine
        # CVSS (40%) + Asset Criticality (25%) + Exposure (20%) + Exploitation Status (15%)
        crit_factor = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}[crit]
        exp_factor = {"INTERNET_FACING": 100, "INTERNAL_ONLY": 50, "ISOLATED_TEST": 15}[exp]
        exploit_factor = {"KNOWN_EXPLOITED": 100, "PROOF_OF_CONCEPT": 65, "UNPROVEN": 25}[exploit_demo]

        priority_score = int(round(
            (cvss * 10 * 0.40) +
            (crit_factor * 0.25) +
            (exp_factor * 0.20) +
            (exploit_factor * 0.15)
        ))

        pub_dt = (base_time - timedelta(days=random.randint(2, 60))).strftime("%Y-%m-%d")

        vuln_rows.append({
            "vulnerability_id": f"VULN-2026-{v_idx:03d}",
            "cve_id": cve_id,
            "product_category": prod_cat,
            "severity": v_sev,
            "cvss_score": cvss,
            "published_date": pub_dt,
            "patch_available": patch,
            "exploitation_status_demo": exploit_demo,
            "asset_criticality": crit,
            "exposure": exp,
            "priority_score": priority_score,
            "description": f"Synthetic vulnerability tracked for defensive patch prioritization in {prod_cat}. CVSS {cvss} with {exp.lower()} exposure."
        })

    vuln_headers = [
        "vulnerability_id", "cve_id", "product_category", "severity",
        "cvss_score", "published_date", "patch_available",
        "exploitation_status_demo", "asset_criticality", "exposure",
        "priority_score", "description"
    ]

    with open(vuln_csv_path, mode="w", newline="", encoding="utf-8") as vf:
        vwriter = csv.DictWriter(vf, fieldnames=vuln_headers)
        vwriter.writeheader()
        vwriter.writerows(vuln_rows)

    print(f"Successfully generated {len(vuln_rows)} synthetic vulnerability records at: {vuln_csv_path}")

if __name__ == "__main__":
    generate_synthetic_data()
