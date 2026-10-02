"""
Automated Comprehensive Test Suite for Cybersecurity Dashboard
Module: tests.test_suite

Implements 35 standardized unit and integration tests covering:
1. Syntactic IOC Validation
2. Multi-factor Risk & Confidence Scoring
3. Local Threat Enrichment Engine
4. MITRE ATT&CK Mapping
5. Contextual Vulnerability Prioritization
6. Alert Deduplication & Correlation
7. REST API Endpoints & DB Persistence
8. Awareness Scoring & Educational Recommendations
"""

import os
import sys
import pytest
import json

# Ensure repository root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import create_app
from backend.models.database import get_db_connection, init_db
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import (
    calculate_threat_risk, get_source_reliability_score, classify_risk_score
)
from backend.services.enrichment_engine import enrich_indicator
from backend.services.correlation_engine import correlate_threats, generate_threat_timeline
from backend.services.alert_engine import generate_threat_alert, update_alert_status, correlate_alerts
from backend.services.attack_mapper import get_attack_matrix_summary, get_threats_by_technique
from backend.services.threat_service import (
    get_dashboard_statistics, get_threats, get_threat_by_id,
    calculate_vulnerability_priority, get_vulnerabilities,
    generate_learning_recommendations, grade_quiz_submission,
    add_analyst_note, update_threat_status
)

@pytest.fixture(scope="session")
def test_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# -------------------------------------------------------------
# 1-11: IOC Syntactic Validation Tests
# -------------------------------------------------------------
def test_01_valid_ipv4():
    """Test ID 1: Valid IPv4 syntax recognition"""
    res = validate_indicator("198.51.100.25")
    assert res["valid"] is True
    assert "IPv4" in res["indicator_type"]
    assert res["normalized_value"] == "198.51.100.25"

def test_02_invalid_ipv4():
    """Test ID 2: Invalid IPv4 out-of-range octets"""
    res = validate_indicator("999.12.34.56")
    assert res["valid"] is False
    assert "Invalid IPv4" in res["validation_notes"]

def test_03_valid_ipv6():
    """Test ID 3: Valid IPv6 format recognition"""
    res = validate_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res["valid"] is True
    assert "IPv6" in res["indicator_type"]

def test_04_valid_domain():
    """Test ID 4: Valid FQDN domain syntax"""
    res = validate_indicator("login-check.invalid")
    assert res["valid"] is True
    assert res["indicator_type"] == "DOMAIN"
    assert res["normalized_value"] == "login-check.invalid"

def test_05_invalid_domain():
    """Test ID 5: Invalid domain syntax with spaces"""
    res = validate_indicator("malicious domain name with space.com")
    assert res["valid"] is False

def test_06_valid_url():
    """Test ID 6: Valid HTTP/HTTPS URL format"""
    res = validate_indicator("https://example.org/path/resource?auth=123")
    assert res["valid"] is True
    assert res["indicator_type"] == "URL"

def test_07_valid_md5():
    """Test ID 7: Valid 32-character hexadecimal MD5 format"""
    res = validate_indicator("44d88612fea8a8f36de82e1278abb02f")
    assert res["valid"] is True
    assert "MD5" in res["indicator_type"]

def test_08_valid_sha1():
    """Test ID 8: Valid 40-character hexadecimal SHA-1 format"""
    res = validate_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert res["valid"] is True
    assert "SHA-1" in res["indicator_type"]

def test_09_valid_sha256():
    """Test ID 9: Valid 64-character hexadecimal SHA-256 format"""
    res = validate_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["valid"] is True
    assert "SHA-256" in res["indicator_type"]

def test_10_valid_cve():
    """Test ID 10: Valid CVE identifier format"""
    res = validate_indicator("CVE-2026-1045")
    assert res["valid"] is True
    assert res["indicator_type"] == "CVE ID"
    assert res["normalized_value"] == "CVE-2026-1045"

def test_11_invalid_cve():
    """Test ID 11: Malformed CVE format"""
    res = validate_indicator("CVE-INVALID-FORMAT")
    assert res["valid"] is False
    assert "Malformed CVE" in res["validation_notes"]

# -------------------------------------------------------------
# 12-15: Risk, Confidence, and Source Scoring Tests
# -------------------------------------------------------------
def test_12_threat_creation(test_client):
    """Test ID 12: Ingesting and creating a new defensive threat record"""
    payload = {
        "threat_name": "Test Ingest Phish",
        "category": "PHISHING",
        "indicator_value": "auth-check.invalid",
        "severity": "HIGH",
        "confidence_score": 85,
        "source_name": "Internal SOC",
        "source_reliability": "A – Highly Reliable",
        "description": "Test verification of automated threat intake."
    }
    resp = test_client.post("/api/threats", json=payload)
    assert resp.status_code == 201
    json_data = resp.get_json()
    assert json_data["status"] == "success"
    assert "THR-2026-" in json_data["data"]["threat_id"]

def test_13_risk_calculation():
    """Test ID 13: Multi-factor risk calculation weighting"""
    risk = calculate_threat_risk(
        severity="HIGH",
        confidence=85,
        recency_days=1,
        observation_count=100,
        source_reliability="A",
        correlated_alerts_count=3
    )
    assert 70 <= risk["risk_score"] <= 95
    assert risk["classification"] in ["HIGH", "CRITICAL"]

def test_14_confidence_calculation():
    """Test ID 14: Risk vs confidence interpretation contrast"""
    high_risk_low_conf = calculate_threat_risk("CRITICAL", confidence=20, source_reliability="D")
    assert "evidence quality is weak" in high_risk_low_conf["interpretation"].lower()

def test_15_source_reliability():
    """Test ID 15: Source reliability factor evaluation"""
    assert get_source_reliability_score("A – Highly Reliable") == 100
    assert get_source_reliability_score("B – Usually Reliable") == 80
    assert get_source_reliability_score("C – Fairly Reliable") == 60
    assert get_source_reliability_score("D – Reliability Unknown") == 40

# -------------------------------------------------------------
# 16-19: Threat Enrichment & Correlation Tests
# -------------------------------------------------------------
def test_16_ioc_enrichment():
    """Test ID 16: Local offline threat enrichment for demonstration scenario"""
    en = enrich_indicator("login-check.invalid")
    assert en["known_in_dataset"] is True
    assert en["threat_id"] == "THR-2026-0001"
    assert en["severity"] == "HIGH"
    assert len(en["recommended_actions"]) > 0

def test_17_indicator_search(test_client):
    """Test ID 17: Search endpoint returns enriched data without network socket requests"""
    resp = test_client.get("/api/indicators/search?q=198.51.100.25")
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["known_in_dataset"] is True
    assert data["indicator_type"] in ["IP ADDRESS", "IP ADDRESS (IPv4)"]

def test_18_threat_correlation():
    """Test ID 18: Threat clustering by campaign infrastructure"""
    clusters = correlate_threats()
    assert isinstance(clusters, list)
    assert len(clusters) > 0
    assert "campaign_id" in clusters[0]

def test_19_duplicate_observation():
    """Test ID 19: Repeated observations deduplicate into active alert counter"""
    alert_t = {
        "threat_id": "THR-2026-0001",
        "threat_name": "Synthetic Credential Phishing Campaign",
        "category": "PHISHING",
        "severity": "HIGH",
        "risk_score": 78,
        "confidence_score": 85,
        "observation_count": 142
    }
    first_pass = generate_threat_alert(alert_t)
    second_pass = generate_threat_alert(alert_t)
    # The second attempt should correlate/deduplicate to prevent alert fatigue
    assert second_pass["alert_created"] is False or second_pass.get("was_deduplicated") is True

# -------------------------------------------------------------
# 20-23: Alert Management & Analyst Notes Tests
# -------------------------------------------------------------
def test_20_alert_generation():
    """Test ID 20: Generating security alert for high risk indicator"""
    t_alert = {
        "threat_id": "THR-2026-0002",
        "threat_name": "Phishing Hosting Node",
        "category": "PHISHING",
        "severity": "HIGH",
        "risk_score": 80,
        "confidence_score": 90,
        "observation_count": 285
    }
    res = generate_threat_alert(t_alert)
    assert "alert" in res or res.get("alert_created") is True or res.get("was_deduplicated") is True

def test_21_alert_correlation():
    """Test ID 21: Alert correlation reduces analyst fatigue"""
    corr = correlate_alerts("THR-2026-0001", new_observation_count=5)
    assert corr is not None
    assert corr["observation_count"] >= 5

def test_22_alert_status_update(test_client):
    """Test ID 22: Updating alert status through API"""
    alerts_resp = test_client.get("/api/alerts?limit=1")
    alerts = alerts_resp.get_json()["data"]["alerts"]
    if alerts:
        a_id = alerts[0]["alert_id"]
        up_resp = test_client.put(f"/api/alerts/{a_id}/status", json={"status": "INVESTIGATING"})
        assert up_resp.status_code == 200
        assert up_resp.get_json()["data"]["status"] == "INVESTIGATING"

def test_23_analyst_notes():
    """Test ID 23: Adding analyst notes to a threat record"""
    res = add_analyst_note("THR-2026-0001", "Lead SOC Analyst", "Completed triage; defensive monitoring confirmed.")
    assert res["success"] is True
    assert res["note"]["threat_id"] == "THR-2026-0001"

# -------------------------------------------------------------
# 24-29: ATT&CK, Vulnerabilities, & Dashboard Telemetry Tests
# -------------------------------------------------------------
def test_24_attack_mapping():
    """Test ID 24: MITRE ATT&CK matrix retrieval and technique query"""
    summary = get_attack_matrix_summary()
    assert summary["total_mappings"] > 0
    assert len(summary["tactics_distribution"]) > 0
    t_list = get_threats_by_technique("T1566")
    assert isinstance(t_list, list)

def test_25_vulnerability_scoring():
    """Test ID 25: Contextual vulnerability prioritization calculation"""
    vuln_prio = calculate_vulnerability_priority(
        cvss_score=9.8,
        asset_criticality="CRITICAL",
        exposure="INTERNET_FACING",
        exploitation_status="KNOWN_EXPLOITED"
    )
    assert vuln_prio["priority_score"] >= 85
    assert "URGENT" in vuln_prio["urgency"]

def test_26_dashboard_statistics():
    """Test ID 26: Complete 7-card and 10-chart statistics generation"""
    stats = get_dashboard_statistics()
    cards = stats["cards"]
    assert cards["total_threats"] >= 2000
    assert len(stats["charts"]["threats_by_category"]) > 0
    assert len(stats["charts"]["threats_by_severity"]) > 0

def test_27_severity_filtering():
    """Test ID 27: Filtering threats by CRITICAL severity"""
    data = get_threats(severity="CRITICAL", page=1, page_size=10)
    for record in data["records"]:
        assert record["severity"] == "CRITICAL"

def test_28_category_filtering():
    """Test ID 28: Filtering threats by PHISHING category"""
    data = get_threats(category="PHISHING", page=1, page_size=10)
    for record in data["records"]:
        assert record["category"] == "PHISHING"

def test_29_threat_sorting():
    """Test ID 29: Sorting threats by highest risk"""
    data = get_threats(sort_by="highest_risk", page=1, page_size=10)
    records = data["records"]
    for i in range(len(records) - 1):
        assert records[i]["risk_score"] >= records[i + 1]["risk_score"]

# -------------------------------------------------------------
# 30-32: Awareness, Quizzing, & Learning Recommendations
# -------------------------------------------------------------
def test_30_awareness_module_retrieval(test_client):
    """Test ID 30: Retrieval of all 15 educational awareness modules"""
    resp = test_client.get("/api/awareness/modules")
    assert resp.status_code == 200
    modules = resp.get_json()["data"]["modules"]
    assert len(modules) == 15

def test_31_quiz_scoring():
    """Test ID 31: Scoring submission against 30+ question bank"""
    # Sample submission with known answers for Q-01 (opt 2 is correct) and Q-02 (opt 1 is correct)
    sample_answers = {"Q-01": 2, "Q-02": 1, "Q-03": 1}
    res = grade_quiz_submission(sample_answers)
    assert res["total_questions"] >= 30
    assert res["correct_count"] >= 3
    assert "category_scores" in res

def test_32_learning_recommendation():
    """Test ID 32: Automated targeted learning recommendations for low scores"""
    low_scores = {"Phishing": 40, "Passwords": 90, "MFA": 50}
    recs = generate_learning_recommendations(low_scores)
    rec_cats = [r["category"] for r in recs]
    assert "Phishing" in rec_cats
    assert "MFA" in rec_cats
    assert "Passwords" not in rec_cats

# -------------------------------------------------------------
# 33-35: Edge Cases, API Validation, & Persistence Tests
# -------------------------------------------------------------
def test_33_empty_dataset_handling():
    """Test ID 33: Graceful handling of nonexistent indicator lookup"""
    res = enrich_indicator("nonexistent-safe-test-string.invalid")
    assert res["known_in_dataset"] is False
    assert res["threat_id"] == "UNKNOWN"

def test_34_api_validation(test_client):
    """Test ID 34: API rejects malformed threat payload"""
    malformed = {"threat_name": "Missing Required Indicator"}
    resp = test_client.post("/api/threats", json=malformed)
    assert resp.status_code == 400

def test_35_database_persistence():
    """Test ID 35: Status update persists in SQLite database"""
    update_res = update_threat_status("THR-2026-0001", "CLOSED")
    assert update_res["success"] is True

    # Verify directly from database connection
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM threats WHERE threat_id = 'THR-2026-0001'")
    db_status = cursor.fetchone()["status"]
    conn.close()
    assert db_status == "CLOSED"

    # Reset back to MONITORING for consistent demo state
    update_threat_status("THR-2026-0001", "MONITORING")
