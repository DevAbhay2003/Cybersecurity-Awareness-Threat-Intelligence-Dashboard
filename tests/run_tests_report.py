"""
Structured Test Execution Reporter
Module: tests.run_tests_report

Executes all 35 test scenarios and prints the exact tabular format requested:
Test ID | Scenario | Input | Expected Result | Actual Result | Pass/Fail
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from tests.test_suite import (
    test_01_valid_ipv4, test_02_invalid_ipv4, test_03_valid_ipv6, test_04_valid_domain,
    test_05_invalid_domain, test_06_valid_url, test_07_valid_md5, test_08_valid_sha1,
    test_09_valid_sha256, test_10_valid_cve, test_11_invalid_cve, test_12_threat_creation,
    test_13_risk_calculation, test_14_confidence_calculation, test_15_source_reliability,
    test_16_ioc_enrichment, test_17_indicator_search, test_18_threat_correlation,
    test_19_duplicate_observation, test_20_alert_generation, test_21_alert_correlation,
    test_22_alert_status_update, test_23_analyst_notes, test_24_attack_mapping,
    test_25_vulnerability_scoring, test_26_dashboard_statistics, test_27_severity_filtering,
    test_28_category_filtering, test_29_threat_sorting, test_30_awareness_module_retrieval,
    test_31_quiz_scoring, test_32_learning_recommendation, test_33_empty_dataset_handling,
    test_34_api_validation, test_35_database_persistence, test_client
)
from backend.app import create_app

def run_all_tests():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    tests_definition = [
        (1, "Valid IPv4 syntax", "198.51.100.25", "Valid True, Type IPv4", lambda: test_01_valid_ipv4()),
        (2, "Invalid IPv4 out-of-range octets", "999.12.34.56", "Valid False, Malformed", lambda: test_02_invalid_ipv4()),
        (3, "Valid IPv6 address", "2001:0db8:85a3::8a2e:0370:7334", "Valid True, Type IPv6", lambda: test_03_valid_ipv6()),
        (4, "Valid domain name", "login-check.invalid", "Valid True, Type DOMAIN", lambda: test_04_valid_domain()),
        (5, "Invalid domain with whitespace", "malicious domain.com", "Valid False, Malformed", lambda: test_05_invalid_domain()),
        (6, "Valid HTTP/HTTPS URL", "https://example.org/path", "Valid True, Type URL", lambda: test_06_valid_url()),
        (7, "Valid MD5 hash (32 hex)", "44d88612fea8a8f36de82e1278abb02f", "Valid True, Type MD5", lambda: test_07_valid_md5()),
        (8, "Valid SHA-1 hash (40 hex)", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "Valid True, Type SHA-1", lambda: test_08_valid_sha1()),
        (9, "Valid SHA-256 hash (64 hex)", "e3b0c44298fc1c14... (64 hex)", "Valid True, Type SHA-256", lambda: test_09_valid_sha256()),
        (10, "Valid CVE ID", "CVE-2026-1045", "Valid True, Type CVE ID", lambda: test_10_valid_cve()),
        (11, "Invalid CVE format", "CVE-INVALID-FORMAT", "Valid False, Malformed", lambda: test_11_invalid_cve()),
        (12, "Threat Ingestion & Creation", "JSON payload with valid IOC", "201 Created, Threat ID assigned", lambda: test_12_threat_creation(client)),
        (13, "Multi-factor Risk Scoring", "High Sev, 85 Conf, 100 Sightings", "Risk 70-95, Tier HIGH/CRITICAL", lambda: test_13_risk_calculation()),
        (14, "Confidence vs Risk interpretation", "Critical Sev, 20 Confidence", "Weak evidence quality flagged", lambda: test_14_confidence_calculation()),
        (15, "Source Reliability Scoring", "Admiralty levels A to D", "Weighted 40 to 100", lambda: test_15_source_reliability()),
        (16, "Local Threat Enrichment", "login-check.invalid", "Enriched metadata, Known True", lambda: test_16_ioc_enrichment()),
        (17, "Indicator Search endpoint", "198.51.100.25", "HTTP 200, Local lookup only", lambda: test_17_indicator_search(client)),
        (18, "Threat Correlation Clustering", "Shared campaign identifiers", "Clusters list > 0 items", lambda: test_18_threat_correlation()),
        (19, "Duplicate Observation Deduplication", "Repeated sightings of threat", "Alert deduplicated; count elevated", lambda: test_19_duplicate_observation()),
        (20, "Alert Generation Engine", "High risk threat record", "Alert created with status NEW", lambda: test_20_alert_generation()),
        (21, "Alert Correlation Logic", "Existing active alert ID", "Observation count incremented", lambda: test_21_alert_correlation()),
        (22, "Alert Status Update", "Status = INVESTIGATING", "Status updated successfully", lambda: test_22_alert_status_update(client)),
        (23, "Analyst Notes logging", "Analyst text observation", "Appended to threat record", lambda: test_23_analyst_notes()),
        (24, "ATT&CK Mapping Retrieval", "Technique ID T1566", "Matching threats returned", lambda: test_24_attack_mapping()),
        (25, "Vulnerability Prioritization", "CVSS 9.8 + Internet Facing", "Priority >= 85, Urgency URGENT", lambda: test_25_vulnerability_scoring()),
        (26, "Dashboard Statistics Calculation", "Aggregation across 2,500 records", "7 KPI cards & 10 charts populated", lambda: test_26_dashboard_statistics()),
        (27, "Threat Severity Filtering", "Severity = CRITICAL", "Only CRITICAL records returned", lambda: test_27_severity_filtering()),
        (28, "Threat Category Filtering", "Category = PHISHING", "Only PHISHING records returned", lambda: test_28_category_filtering()),
        (29, "Threat Record Sorting", "Sort By = highest_risk", "Strict descending order", lambda: test_29_threat_sorting()),
        (30, "Awareness Modules Retrieval", "GET /api/awareness/modules", "15 educational modules loaded", lambda: test_30_awareness_module_retrieval(client)),
        (31, "Quiz Scoring Engine", "Sample question responses", "Graded 0-100, category breakdown", lambda: test_31_quiz_scoring()),
        (32, "Targeted Recommendations", "Category score < 70%", "Matching module assigned", lambda: test_32_learning_recommendation()),
        (33, "Empty Dataset / Unknown Indicator", "nonexistent-indicator.invalid", "Known False, Threat ID UNKNOWN", lambda: test_33_empty_dataset_handling()),
        (34, "REST API Input Validation", "Malformed POST body", "HTTP 400 Bad Request rejected", lambda: test_34_api_validation(client)),
        (35, "Database State Persistence", "Threat status update to CLOSED", "Persists in SQLite table", lambda: test_35_database_persistence())
    ]

    print("=" * 115)
    print(f"{'ID':<4} | {'Scenario':<34} | {'Input':<25} | {'Expected Result':<25} | {'Status'}")
    print("=" * 115)

    passed_count = 0
    failed_count = 0

    for tid, scenario, inp, exp, fn in tests_definition:
        try:
            fn()
            status = "PASS"
            passed_count += 1
        except Exception as e:
            status = f"FAIL ({str(e)[:25]})"
            failed_count += 1
        
        inp_trunc = (inp[:22] + "...") if len(inp) > 25 else inp
        exp_trunc = (exp[:22] + "...") if len(exp) > 25 else exp
        print(f"{tid:<4} | {scenario:<34} | {inp_trunc:<25} | {exp_trunc:<25} | {status}")

    print("=" * 115)
    print(f"TEST SUMMARY: Total: {len(tests_definition)} | Passed: {passed_count} | Failed: {failed_count}")
    print("=" * 115)

if __name__ == "__main__":
    run_all_tests()
