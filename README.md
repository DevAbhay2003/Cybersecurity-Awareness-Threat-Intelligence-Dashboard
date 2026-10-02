# Cybersecurity Awareness & Threat Intelligence Dashboard

> **An Industry-Oriented Defensive Cyber Threat Intelligence (CTI) & Human Risk Reduction Platform**

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Backend-Flask%203.1-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Security Focus](https://img.shields.io/badge/Focus-Defensive%20Security%20Only-emerald.svg)]()
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15%20Enterprise-red.svg)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Tests-35%2F35%20Passed-brightgreen.svg)]()

---

## Ethical Disclaimer & Defensive Directive

> **IMPORTANT DEFENSIVE PRINCIPLE:**  
> This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.  
> Indicators (IPs, domains, URLs, and file hashes) are analyzed purely as passive data records and are never automatically probed, scanned, pinged, or visited over network sockets. All synthetic indicators utilize official RFC documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and reserved top-level domains (`.invalid`, `.example`).

---

## Overview

Modern enterprise defense requires a symbiotic union of **Technical Threat Intelligence** and **Human Defense**:

1. **Technical Defense:** Security Operations Center (SOC) analysts must triage thousands of Indicators of Compromise (IOCs), correlate telemetry across campaigns, map adversary behaviors to the MITRE ATT&CK framework, and prioritize vulnerabilities contextually.
2. **Human Defense:** Over 80% of enterprise intrusions initiate through social engineering and phishing targeting human employees. Without defensive awareness, hardened firewalls cannot prevent credential theft.

The **Cybersecurity Awareness & Threat Intelligence Dashboard** is an end-to-end, industry-oriented platform that unifies both domains into an analyst-grade operations portal. It ingests 2,500+ defensive threat records, performs automated syntactic validation, enriches indicators offline, scores multi-factor risk (0–100), correlates campaign clusters, mitigates alert fatigue, and trains personnel through a 15-module curriculum and diagnostic 32-question evaluation engine.

---

## Problem Statement

Enterprise security operations face three critical bottlenecks:

- **Alert Fatigue:** Analysts are overwhelmed by hundreds of redundant, low-fidelity alerts for identical indicators, leading to burnout and missed intrusions.
- **Speculative Correlation & False Equivalences:** Teams often confuse raw observations with confirmed compromises or rely blindly on CVSS scores without factoring in internet exposure or asset criticality.
- **The Human Defense Gap:** Technical security controls operate in isolation from employee awareness programs. When employees fall for credential harvesting or MFA push fatigue, perimeter defenses fail.

This project addresses these challenges by implementing automated alert deduplication, contextual vulnerability prioritization, Admiralty source reliability grading, and personalized educational learning recommendations.

---

## Objectives

- Ingest, normalize, and validate defensive threat indicators across 6 primary types (IPv4, IPv6, Domain, URL, Hashes, and CVE IDs).
- Enforce strict distinction between: `OBSERVATION`, `INDICATOR`, `ALERT`, `THREAT`, and `INCIDENT`.
- Calculate multi-factor risk scores (0–100) using 6 weighted defensive dimensions.
- Map adversary Tactics, Techniques, and Procedures (TTPs) to MITRE ATT&CK Enterprise Matrix when behavioral evidence is justified.
- Cluster campaign infrastructure using non-attributed correlation logic.
- Prevent SOC alert fatigue through observation counter deduplication.
- Deliver an interactive 15-module Cybersecurity Awareness Center adhering to NIST SP 800-50 guidelines.
- Provide a 32-question diagnostic evaluation quiz with automated category radar scoring and targeted module recommendations.
- Present an Executive Cybersecurity Summary for non-technical leadership.

---

## Cybersecurity Relevance & Industry Roles

This project directly demonstrates real-world competencies across core cybersecurity job families:

| Cybersecurity Role | How This Project Demonstrates Industry Competence |
| :--- | :--- |
| **SOC Analyst (Tier 1/2)** | Triage telemetry queues, inspect indicator syntax, manage alert states, and document investigation notes. |
| **Threat Intelligence Analyst** | Perform IOC enrichment, evaluate Admiralty source reliability, classify TLP, and map campaign clusters. |
| **Incident Response Analyst** | Follow the 6-phase NIST incident response lifecycle, evaluate threat timelines, and prepare containment checklists. |
| **Vulnerability Analyst** | Calculate contextual vulnerability priority combining CVSS with asset criticality and internet exposure. |
| **Security Awareness Specialist** | Design curriculum, analyze human risk telemetry, identify weak knowledge areas, and automate remedial assignments. |
| **Defensive Security Engineer** | Build modular REST APIs, enforce input sanitization (XSS defense), and maintain safe, non-exploitative architectures. |

---

## Key Features

### 🛡️ 1. Technical Threat Intelligence Engine
- **IOC Validation Engine (`validate_indicator`):** Validates syntactic structures for IPv4, IPv6, FQDNs, URLs, MD5, SHA-1, SHA-256, and CVE IDs.
- **Local Threat Enrichment (`enrich_indicator`):** Passive, offline enrichment against local database telemetry with zero external network socket requests.
- **Multi-Factor Risk Engine (`calculate_threat_risk`):**
  - Severity: 30%
  - Confidence: 25%
  - Recency: 15%
  - Observation Frequency: 10%
  - Source Reliability: 10%
  - Correlation Context: 10%
- **Admiralty Source Reliability:** Levels A (Highly Reliable) through D (Reliability Unknown).
- **Campaign Correlation Engine (`correlate_threats`):** Groups threats into non-attributed clusters by campaign ID and observation window.
- **Alert Fatigue Reducer (`correlate_alerts`):** Merges repeated sightings into single active alerts with elevated counters.
- **MITRE ATT&CK Navigator:** Tactical breakdown, top techniques, and interactive threat drilldown.
- **Contextual Vulnerability Prioritization:** Balances CVSS (40%) with Asset Criticality (25%), Exposure (20%), and Known Exploitation (15%).

### 🎓 2. Human Defense & Awareness Center
- **15 Educational Modules:** Phishing, Password Hygiene, MFA/Passkeys, Social Engineering, Safe Browsing, Wi-Fi Defense, Patch Management, Ransomware Defense, USB Media, Data Privacy, Mobile Security, Remote Work, Cloud SaaS Security, Incident Reporting, and AI-Generated Scams.
- **Phishing Anatomy Deep Dive:** Visual breakdown of deceptive headers, artificial urgency, Quishing, and lookalike domains.
- **32-Question Diagnostic Quiz:** Scenario-based evaluations spanning all 10 threat categories.
- **Awareness Scoring Engine:** Grades 0–100 with category proficiency radar chart.
- **Adaptive Recommendations:** Automatically assigns targeted modules for category scores < 70%.
- **Blameless Reporting Framework:** Guides employees on rapid incident disclosure without fear of punitive action.

---

## System Architecture

```text
 ┌────────────────────────────────────────────────────────┐
 │       DEFENSIVE THREAT DATA INGESTION & PIPELINE       │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │    Data Ingestion Layer   │
              │  (2,500+ Synthetic Records)│
              └─────────────┬─────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │ Syntactic IOC Validation  │
              │ (IP, Domain, URL, Hashes) │
              └─────────────┬─────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │  Local Threat Enrichment  │
              │   (Zero Outbound Probes)  │
              └─────────────┬─────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │  Risk & Confidence Engine │
              │ (6 Weighted Dimensions)   │
              └─────────────┬─────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │ Campaign Correlation &    │
              │ Deduplication Engine      │
              └─────────────┬─────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Threat DB   │     │ Alert Engine │     │ MITRE ATT&CK │
│   (SQLite)   │     │ (Deduplicate)│     │   Mapping    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       └────────────────────┼────────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │  REST API Service Layer   │
              │    (Flask Blueprints)     │
              └─────────────┬─────────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│   SOC Analyst Portal    │   │ Human Defense Center    │
│  • 10 Chart Visuals     │   │ • 15 Awareness Modules  │
│  • Investigation View   │   │ • 32 Scenario Questions │
│  • Timeline & Notes     │   │ • Radar Proficiency     │
│  • Campaign Clusters    │   │ • Adaptive Recommendations│
└─────────────────────────┘   └─────────────────────────┘
```

---

## Crucial Distinction: Observation vs Incident

To avoid false alarms and misattributed escalations, the platform enforces strict operational semantics:

| Stage | Operational Definition | Example | Action |
| :--- | :--- | :--- | :--- |
| **OBSERVATION** | Raw telemetry event logged by sensors | Port 443 outbound packet | Logged in SIEM |
| **INDICATOR (IOC)** | Technical artifact with associated intel | `login-check.invalid` | Validated & enriched |
| **ALERT** | Prioritized notification exceeding risk thresholds | Phishing Risk Elevation (78) | Triaged & deduplicated |
| **THREAT** | Actor capability or vector threatening assets | Credential harvesting campaign | ATT&CK mapped |
| **INCIDENT** | Confirmed compromise of CIA triad | Unauthorized data exfiltration | Contain, Eradicate, Recover |

---

## Technology Stack

- **Backend:** Python 3.10+, Flask 3.1, Flask-CORS
- **Database:** SQLite 3 with relational schemas, foreign keys, and optimized performance indexes
- **Analytics & Processing:** Pandas 3.0, NumPy, standard library `ipaddress` and `hashlib`
- **Frontend:** Semantic HTML5, Modern Dark-SOC CSS3 Grid/Flexbox, Vanilla JavaScript ES6+
- **Visualizations:** Chart.js (Line, Doughnut, Horizontal Bar, Radar, Pie)
- **Testing:** Pytest 9.1 with automated 35-scenario test runner

---

## Project Folder Structure

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
│
├── backend/
│   ├── app.py                      # Master application server & route dispatcher
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py             # SQLite schemas, indexes, and automated seeding
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── threat_routes.py        # Threat feed, details, intake, and notes
│   │   ├── indicator_routes.py     # Passive IOC validation & search
│   │   ├── alert_routes.py         # SOC alert queue & triage status
│   │   ├── vulnerability_routes.py # CVE prioritization & awareness
│   │   ├── awareness_routes.py     # Modules, quiz submission, and scoring
│   │   └── dashboard_routes.py     # 10 SOC charts, clusters, and executive summary
│   ├── services/
│   │   ├── __init__.py
│   │   ├── threat_service.py       # Core business logic & analytics aggregation
│   │   ├── ioc_validator.py        # Regex & syntactic format validation engine
│   │   ├── enrichment_engine.py    # Local offline threat intelligence enrichment
│   │   ├── risk_engine.py          # Multi-factor risk & confidence scoring
│   │   ├── correlation_engine.py   # Campaign clustering & incident timeline
│   │   ├── alert_engine.py         # Alert generation & deduplication logic
│   │   └── attack_mapper.py        # MITRE ATT&CK matrix correlation
│   └── utils/
│       ├── __init__.py
│       └── helpers.py              # XSS sanitization, TLP tags, and API envelopes
│
├── frontend/
│   ├── index.html                  # Landing page & Executive Cybersecurity Summary
│   ├── threat-dashboard.html       # Full SOC dashboard with 10 interactive charts
│   ├── threat-details.html         # Deep SOC investigation view with timeline & notes
│   ├── awareness.html              # Cybersecurity Awareness Center (15 modules)
│   ├── quiz.html                   # 32-Question diagnostic quiz with radar chart
│   ├── css/
│   │   └── styles.css              # SOC-grade responsive dark theme stylesheet
│   └── js/
│       ├── app.js                  # Global API client, toast alerts, badge formatters
│       ├── dashboard.js            # Chart.js initialization & threat feed table
│       ├── details.js              # Threat investigation controller & action handlers
│       ├── awareness.js            # Module rendering, filtering, and modal viewer
│       └── quiz.js                 # Quiz engine, radar scoring, and recommendations
│
├── awareness/
│   ├── modules.json                # 15 detailed educational awareness modules
│   └── quiz_questions.json         # 32 scenario-based quiz questions with explanations
│
├── data/
│   ├── generate_threat_data.py     # Deterministic synthetic threat generator
│   ├── threat_intelligence_dataset.csv # 2,500+ sanitized defensive threat records
│   └── vulnerabilities.csv         # 59 contextual defensive vulnerability records
│
├── tests/
│   ├── __init__.py
│   ├── test_suite.py               # 35 automated pytest unit and integration tests
│   └── run_tests_report.py         # Tabular test report execution utility
│
├── .env.example                    # Environment variable template
├── .gitignore                      # Git exclusion rules
├── requirements.txt                # Production and development dependencies
└── README.md                       # Comprehensive architectural documentation
```

---

## Safe Demonstration Scenario: `THR-2026-0001`

The platform includes a pre-configured safe demonstration scenario illustrating a complete SOC analyst investigation workflow:

- **Threat ID:** `THR-2026-0001`
- **Threat Name:** Synthetic Credential Phishing Campaign
- **Category:** `PHISHING`
- **Indicator Type:** `DOMAIN`
- **Indicator Value:** `login-check.invalid` *(RFC 2606 reserved domain)*
- **Correlated IP:** `198.51.100.25` *(RFC 5737 documentation address)*
- **Severity:** `HIGH`
- **Risk Score:** `78/100` *(High Risk Tier)*
- **Confidence Score:** `85/100` *(High Confidence)*
- **Source:** Internal SOC (A – Highly Reliable)
- **Status:** `MONITORING`
- **MITRE ATT&CK Mapping:** Initial Access &rarr; Phishing: Spearphishing Link (`T1566.002`)
- **Recorded Sightings:** 142 aggregated observations
- **Analyst Note:** *"Indicator appears in multiple synthetic phishing observations. Correlated with infrastructure cluster CAMP-2026-PHISH-A."*
- **Recommended Actions:**
  1. Review email gateway logs for incoming sender domains.
  2. Audit user sign-ins; force credential resets if credentials were submitted.
  3. Place indicator on defensive firewall blocklists in monitoring mode.
  4. Assign targeted phishing awareness training to affected departments.

---

## Local Execution Guide

Follow these exact steps to run the complete platform locally on Windows, macOS, or Linux:

### Step 1: Clone or Navigate to Project Folder
```bash
git clone https://github.com/<your-username>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

### Step 2: Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Generate Synthetic Threat Dataset (2,500+ Records)
```bash
python data/generate_threat_data.py
```

### Step 5: Initialize and Seed SQLite Database
```bash
python backend/models/database.py
```

### Step 6: Start the Application Server
```bash
python backend/app.py
```
*The server will start at `http://127.0.0.1:5000`.*

### Step 7: Open the User Interface
Open your web browser and navigate to:
- **Executive Summary & Home:** [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **SOC Threat Dashboard:** [http://127.0.0.1:5000/threat-dashboard](http://127.0.0.1:5000/threat-dashboard)
- **Investigation View (Demo Scenario):** [http://127.0.0.1:5000/threat-details?id=THR-2026-0001](http://127.0.0.1:5000/threat-details?id=THR-2026-0001)
- **Cybersecurity Awareness Center:** [http://127.0.0.1:5000/awareness](http://127.0.0.1:5000/awareness)
- **Security Awareness Quiz:** [http://127.0.0.1:5000/quiz](http://127.0.0.1:5000/quiz)

---

## REST API Documentation

| Method | Endpoint | Description | Status Code |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status and safety mode check | `200 OK` |
| `GET` | `/api/threats` | Filtered, sorted, and paginated threat records | `200 OK` |
| `GET` | `/api/threats/<id>` | Full threat details, indicators, and notes | `200 OK` |
| `POST` | `/api/threats` | Ingest and validate a new defensive threat | `201 Created` |
| `PUT` | `/api/threats/<id>` | Update operational triage status | `200 OK` |
| `POST` | `/api/threats/<id>/notes` | Append analyst investigation note | `201 Created` |
| `GET` | `/api/threats/<id>/timeline` | Lifecycle milestones for specific threat | `200 OK` |
| `GET` | `/api/indicators/validate?q=` | Syntactic format validation check | `200 OK` |
| `GET` | `/api/indicators/search?q=` | Passive local lookup and enrichment | `200 OK` |
| `GET` | `/api/dashboard/stats` | KPI metrics and data for 10 SOC charts | `200 OK` |
| `GET` | `/api/dashboard/trends` | Correlated threat clusters and campaigns | `200 OK` |
| `GET` | `/api/dashboard/executive` | High-level executive summary metrics | `200 OK` |
| `GET` | `/api/alerts` | Active alert queue with deduplicated sightings | `200 OK` |
| `PUT` | `/api/alerts/<id>/status` | Update alert triage state | `200 OK` |
| `GET` | `/api/vulnerabilities` | Contextual prioritized vulnerability list | `200 OK` |
| `POST`| `/api/vulnerabilities/prioritize` | Calculate custom priority score | `200 OK` |
| `GET` | `/api/awareness/modules` | Retrieve all 15 educational modules | `200 OK` |
| `GET` | `/api/awareness/quiz` | Retrieve 32 scenario quiz questions | `200 OK` |
| `POST`| `/api/awareness/quiz/submit` | Grade submission, compute radar scores & recs | `200 OK` |

---

## Testing & Verification

The project includes 35 comprehensive automated tests covering syntactic validation, scoring logic, enrichment, correlation, alert deduplication, API endpoints, and database persistence.

### Run Automated Pytest Suite
```bash
pytest -v tests/test_suite.py
```

### Run Formatted Tabular Report
```bash
python tests/run_tests_report.py
```

### Test Results Summary

```text
===================================================================================================================
ID   | Scenario                           | Input                     | Expected Result           | Status
===================================================================================================================
1    | Valid IPv4 syntax                  | 198.51.100.25             | Valid True, Type IPv4     | PASS
2    | Invalid IPv4 out-of-range octets   | 999.12.34.56              | Valid False, Malformed    | PASS
3    | Valid IPv6 address                 | 2001:0db8:85a3::8a2e:0... | Valid True, Type IPv6     | PASS
4    | Valid domain name                  | login-check.invalid       | Valid True, Type DOMAIN   | PASS
5    | Invalid domain with whitespace     | malicious domain.com      | Valid False, Malformed    | PASS
6    | Valid HTTP/HTTPS URL               | https://example.org/path  | Valid True, Type URL      | PASS
7    | Valid MD5 hash (32 hex)            | 44d88612fea8a8f36de82e... | Valid True, Type MD5      | PASS
8    | Valid SHA-1 hash (40 hex)          | da39a3ee5e6b4b0d3255bf... | Valid True, Type SHA-1    | PASS
9    | Valid SHA-256 hash (64 hex)        | e3b0c44298fc1c14... (6... | Valid True, Type SHA-256  | PASS
10   | Valid CVE ID                       | CVE-2026-1045             | Valid True, Type CVE ID   | PASS
11   | Invalid CVE format                 | CVE-INVALID-FORMAT        | Valid False, Malformed    | PASS
12   | Threat Ingestion & Creation        | JSON payload with vali... | 201 Created, Threat ID... | PASS
13   | Multi-factor Risk Scoring          | High Sev, 85 Conf, 100... | Risk 70-95, Tier HIGH/... | PASS
14   | Confidence vs Risk interpretation  | Critical Sev, 20 Confi... | Weak evidence quality ... | PASS
15   | Source Reliability Scoring         | Admiralty levels A to D   | Weighted 40 to 100        | PASS
16   | Local Threat Enrichment            | login-check.invalid       | Enriched metadata, Kno... | PASS
17   | Indicator Search endpoint          | 198.51.100.25             | HTTP 200, Local lookup... | PASS
18   | Threat Correlation Clustering      | Shared campaign identi... | Clusters list > 0 items   | PASS
19   | Duplicate Observation Deduplication | Repeated sightings of ... | Alert deduplicated; co... | PASS
20   | Alert Generation Engine            | High risk threat record   | Alert created with sta... | PASS
21   | Alert Correlation Logic            | Existing active alert ID  | Observation count incr... | PASS
22   | Alert Status Update                | Status = INVESTIGATING    | Status updated success... | PASS
23   | Analyst Notes logging              | Analyst text observation  | Appended to threat record | PASS
24   | ATT&CK Mapping Retrieval           | Technique ID T1566        | Matching threats returned | PASS
25   | Vulnerability Prioritization       | CVSS 9.8 + Internet Fa... | Priority >= 85, Urgenc... | PASS
26   | Dashboard Statistics Calculation   | Aggregation across 2,5... | 7 KPI cards & 10 chart... | PASS
27   | Threat Severity Filtering          | Severity = CRITICAL       | Only CRITICAL records ... | PASS
28   | Threat Category Filtering          | Category = PHISHING       | Only PHISHING records ... | PASS
29   | Threat Record Sorting              | Sort By = highest_risk    | Strict descending order   | PASS
30   | Awareness Modules Retrieval        | GET /api/awareness/mod... | 15 educational modules... | PASS
31   | Quiz Scoring Engine                | Sample question responses | Graded 0-100, category... | PASS
32   | Targeted Recommendations           | Category score < 70%      | Matching module assigned  | PASS
33   | Empty Dataset / Unknown Indicator  | nonexistent-indicator.... | Known False, Threat ID... | PASS
34   | REST API Input Validation          | Malformed POST body       | HTTP 400 Bad Request r... | PASS
35   | Database State Persistence         | Threat status update t... | Persists in SQLite table  | PASS
===================================================================================================================
TEST SUMMARY: Total: 35 | Passed: 35 | Failed: 0 (100% Pass Rate)
===================================================================================================================
```

---

## Security, Privacy & False Positive Limitations

### 1. Defensive Design Principles
- **Passive Analysis Only:** The platform never establishes TCP/UDP sockets to queried IP addresses or domains.
- **Input Sanitization:** All user inputs (threat names, search terms, analyst notes) are sanitized through HTML entity escaping and regex stripping to prevent Cross-Site Scripting (XSS) and injection attacks.
- **Traffic Light Protocol (TLP 2.0):** Automatically attaches sharing restrictions (`TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`) based on source reliability and threat severity.

### 2. Threat Intelligence Limitations
- **Shared Infrastructure:** An IP address or cloud hosting provider may host hundreds of legitimate services alongside a single transient malicious host.
- **Stale Indicators:** Threat indicators possess limited operational lifespans. A domain observed 45 days ago may have been reclaimed or sinkholed.
- **Correlation ≠ Attribution:** Observing shared command-and-control infrastructure suggests campaign linkage, but does not provide incontrovertible nation-state or actor attribution.
- **Decision Support:** Threat intelligence is intended to empower human analyst decisions rather than act as an unquestioned automated blocklist.

---

## GitHub Upload & Proof of Work Strategy

To showcase this project effectively on GitHub and LinkedIn:

### Recommended Git Commit Sequence
```bash
git init
git add .
git commit -m "Initialize cybersecurity threat intelligence dashboard"
git commit -m "Add synthetic threat intelligence dataset generator (2,500+ records)"
git commit -m "Implement syntactic IOC validation engine"
git commit -m "Add local threat enrichment engine and risk scoring"
git commit -m "Implement threat correlation and alert deduplication"
git commit -m "Add MITRE ATT&CK mapping and vulnerability prioritization"
git commit -m "Create SOC threat dashboard with 10 interactive Chart.js visualizations"
git commit -m "Build threat investigation view with timeline and analyst triage notes"
git commit -m "Create cybersecurity awareness center with 15 educational modules"
git commit -m "Add 32-question awareness quiz with radar scoring and recommendations"
git commit -m "Implement automated test suite with 35 passed unit tests"
git commit -m "Complete comprehensive README documentation and deployment guide"
```

### Repository Details
- **Repository Name:** `Cybersecurity-Awareness-Threat-Intelligence-Dashboard`
- **Description:** *"Defensive cybersecurity platform combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability prioritization, SOC triage workflows, and interactive workforce cybersecurity awareness training."*
- **GitHub Topics:** `cybersecurity`, `threat-intelligence`, `cti`, `soc`, `ioc`, `mitre-attack`, `security-awareness`, `python`, `flask`, `vulnerability-management`, `incident-response`, `defensive-security`.

---

## Author & Educational Context

- **Author:** Cybersecurity Student & Defensive Engineering Practitioner
- **Project Purpose:** Academic Course Capstone & Industry Proof-of-Work Portfolio
- **Standards Referenced:** NIST SP 800-61 (Incident Handling), NIST SP 800-50 (Security Awareness), NIST SP 800-63B (Authentication & Passwords), MITRE ATT&CK Enterprise Matrix v15, RFC 5737 / RFC 3849 (Documentation IPs), RFC 2606 (Reserved Domains).
- Abhishek Basu — Embedded Systems Student GitHub: [DevAbhay2003](https://github.com/DevAbhay2003?tab=repositories) · LinkedIn: [Abhishek Basu](https://www.linkedin.com/in/abhishek-basu-68b1b1342/)
