"""
Database Layer for Cybersecurity Threat Intelligence Platform
SQLite implementation with relational schemas, foreign keys, and indexes.
"""

import os
import sqlite3
import csv
import json
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel.db")

def get_db_connection(db_path=None):
    if db_path is None:
        db_path = DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path=None, force_reseed=False):
    """
    Initializes tables, creates indexes, and seeds dataset if empty or force_reseed is True.
    """
    if db_path is None:
        db_path = DB_PATH

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Threats Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        threat_name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence_score INTEGER NOT NULL,
        status TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        source_name TEXT NOT NULL,
        source_reliability TEXT NOT NULL,
        campaign_id TEXT DEFAULT 'NONE',
        related_indicators TEXT,
        analyst_notes TEXT,
        observation_count INTEGER DEFAULT 1
    );
    """)

    # 2. Indicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id) ON DELETE CASCADE
    );
    """)

    # 3. Sources Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sources (
        source_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_name TEXT UNIQUE NOT NULL,
        reliability TEXT NOT NULL,
        description TEXT
    );
    """)

    # 4. MITRE ATT&CK Mappings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_mappings (
        mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        tactic TEXT NOT NULL,
        technique TEXT NOT NULL,
        technique_id TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id) ON DELETE CASCADE
    );
    """)

    # 5. Vulnerabilities Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vulnerability_id TEXT PRIMARY KEY,
        cve_id TEXT UNIQUE NOT NULL,
        product_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        published_date TEXT NOT NULL,
        patch_available TEXT NOT NULL,
        exploitation_status TEXT NOT NULL,
        asset_criticality TEXT NOT NULL,
        exposure TEXT NOT NULL,
        priority_score INTEGER NOT NULL,
        description TEXT
    );
    """)

    # 6. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        threat_id TEXT NOT NULL,
        indicator_value TEXT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence_score INTEGER NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        observation_count INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id) ON DELETE CASCADE
    );
    """)

    # 7. Analyst Notes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        author TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id) ON DELETE CASCADE
    );
    """)

    # 8. Awareness Modules Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS awareness_modules (
        module_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        content_json TEXT NOT NULL
    );
    """)

    # 9. Quiz Results Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quiz_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        anonymous_user_id TEXT,
        overall_score INTEGER NOT NULL,
        category_scores_json TEXT NOT NULL,
        weak_areas_json TEXT NOT NULL,
        recommendations_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 10. Correlated Clusters Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correlated_clusters (
        cluster_id TEXT PRIMARY KEY,
        cluster_name TEXT NOT NULL,
        campaign_id TEXT NOT NULL,
        category TEXT NOT NULL,
        threat_ids_json TEXT NOT NULL,
        indicator_count INTEGER NOT NULL,
        average_risk REAL NOT NULL
    );
    """)

    # Performance Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_category ON threats (category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats (severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_status ON threats (status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_risk ON threats (risk_score);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_campaign ON threats (campaign_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators (indicator_value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators (indicator_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities (cve_id);")

    conn.commit()

    # Check if threats table needs seeding
    cursor.execute("SELECT COUNT(*) as count FROM threats")
    threat_count = cursor.fetchone()["count"]

    if threat_count == 0 or force_reseed:
        if force_reseed:
            cursor.execute("DELETE FROM threats")
            cursor.execute("DELETE FROM indicators")
            cursor.execute("DELETE FROM sources")
            cursor.execute("DELETE FROM attack_mappings")
            cursor.execute("DELETE FROM vulnerabilities")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM analyst_notes")
            cursor.execute("DELETE FROM awareness_modules")
            cursor.execute("DELETE FROM correlated_clusters")
            conn.commit()
        seed_database(conn)

    conn.close()

def seed_database(conn):
    """Populates SQLite database with CSV and JSON defensive datasets."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    threat_csv = os.path.join(base_dir, "data", "threat_intelligence_dataset.csv")
    vuln_csv = os.path.join(base_dir, "data", "vulnerabilities.csv")
    modules_json = os.path.join(base_dir, "awareness", "modules.json")

    cursor = conn.cursor()

    # Sources
    sources_data = [
        ("Internal SOC", "A – Highly Reliable", "Primary enterprise telemetry, SIEM, and EDR detection rules"),
        ("Security Vendor", "A – Highly Reliable", "Commercial threat feeds with verified threat telemetry"),
        ("Research Report", "B – Usually Reliable", "Curated whitepapers, threat actor research, and sandbox analysis"),
        ("Public Threat Feed", "C – Fairly Reliable", "Open-source community OSINT feeds with potential noise"),
        ("Community Submission", "C – Fairly Reliable", "Defensive practitioner submissions and honeypot hits"),
        ("Unknown Source", "D – Reliability Unknown", "Unverified external tips requiring validation and enrichment")
    ]
    cursor.executemany("INSERT OR IGNORE INTO sources (source_name, reliability, description) VALUES (?, ?, ?)", sources_data)

    # 1. Ingest Threats
    if os.path.exists(threat_csv):
        with open(threat_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            threat_batch = []
            indicator_batch = []
            attack_batch = []
            notes_batch = []

            for row in reader:
                t_id = row["threat_id"]
                threat_batch.append((
                    t_id,
                    row["timestamp"],
                    row["threat_name"],
                    row["threat_category"],
                    row["description"],
                    row["severity"],
                    int(row["risk_score"]),
                    int(row["confidence_score"]),
                    row["status"],
                    row["first_seen"],
                    row["last_seen"],
                    row["source_name"],
                    row["source_reliability"],
                    row.get("campaign_id", "NONE"),
                    row.get("related_indicators", ""),
                    row.get("analyst_notes", ""),
                    int(row.get("observation_count", 1))
                ))

                # Primary indicator
                indicator_batch.append((
                    t_id,
                    row["indicator_type"],
                    row["indicator_value"],
                    row["first_seen"],
                    row["last_seen"]
                ))

                # ATT&CK mapping if present
                if row.get("mitre_tactic_optional") and row.get("mitre_technique_optional"):
                    tech_full = row["mitre_technique_optional"]
                    tech_id = ""
                    if "(" in tech_full and ")" in tech_full:
                        tech_id = tech_full.split("(")[-1].replace(")", "").strip()
                    attack_batch.append((
                        t_id,
                        row["mitre_tactic_optional"],
                        tech_full,
                        tech_id
                    ))

                # Seed initial analyst note
                if row.get("analyst_notes"):
                    notes_batch.append((
                        t_id,
                        "Lead SOC Analyst",
                        row["analyst_notes"],
                        row["last_seen"]
                    ))

            cursor.executemany("""
            INSERT OR REPLACE INTO threats (
                threat_id, timestamp, threat_name, category, description,
                severity, risk_score, confidence_score, status, first_seen,
                last_seen, source_name, source_reliability, campaign_id,
                related_indicators, analyst_notes, observation_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, threat_batch)

            cursor.executemany("""
            INSERT INTO indicators (threat_id, indicator_type, indicator_value, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            """, indicator_batch)

            cursor.executemany("""
            INSERT INTO attack_mappings (threat_id, tactic, technique, technique_id)
            VALUES (?, ?, ?, ?)
            """, attack_batch)

            cursor.executemany("""
            INSERT INTO analyst_notes (threat_id, author, note, created_at)
            VALUES (?, ?, ?, ?)
            """, notes_batch)

    # 2. Ingest Vulnerabilities
    if os.path.exists(vuln_csv):
        with open(vuln_csv, mode="r", encoding="utf-8") as vf:
            vreader = csv.DictReader(vf)
            vuln_batch = []
            for vrow in vreader:
                vuln_batch.append((
                    vrow["vulnerability_id"],
                    vrow["cve_id"],
                    vrow["product_category"],
                    vrow["severity"],
                    float(vrow["cvss_score"]),
                    vrow["published_date"],
                    vrow["patch_available"],
                    vrow["exploitation_status_demo"],
                    vrow["asset_criticality"],
                    vrow["exposure"],
                    int(vrow["priority_score"]),
                    vrow["description"]
                ))
            cursor.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (
                vulnerability_id, cve_id, product_category, severity,
                cvss_score, published_date, patch_available, exploitation_status,
                asset_criticality, exposure, priority_score, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, vuln_batch)

    # 3. Ingest Awareness Modules
    if os.path.exists(modules_json):
        with open(modules_json, mode="r", encoding="utf-8") as mf:
            modules_list = json.load(mf)
            module_batch = []
            for mod in modules_list:
                module_batch.append((
                    mod["id"],
                    mod["title"],
                    mod["category"],
                    mod["description"],
                    json.dumps(mod)
                ))
            cursor.executemany("""
            INSERT OR REPLACE INTO awareness_modules (
                module_id, title, category, description, content_json
            ) VALUES (?, ?, ?, ?, ?)
            """, module_batch)

    # 4. Generate Initial High/Critical Correlated Alerts (Deduplicated)
    cursor.execute("""
    SELECT threat_id, threat_name, category, severity, risk_score, confidence_score,
           last_seen, description, observation_count, campaign_id
    FROM threats
    WHERE risk_score >= 70 OR severity IN ('HIGH', 'CRITICAL')
    ORDER BY risk_score DESC
    LIMIT 100
    """)
    top_threats = cursor.fetchall()
    alerts_batch = []
    for idx, t in enumerate(top_threats, start=1):
        alert_type = f"{t['category']} Risk Elevation"
        status = "INVESTIGATING" if idx <= 20 else ("MONITORING" if idx <= 60 else "NEW")
        alerts_batch.append((
            f"ALT-2026-{idx:04d}",
            t["threat_id"],
            t["threat_id"],
            alert_type,
            t["severity"],
            t["risk_score"],
            t["confidence_score"],
            f"Automated defensive alert triggered for {t['threat_name']} with risk score {t['risk_score']}/100 and {t['observation_count']} sightings.",
            status,
            t["observation_count"],
            t["last_seen"]
        ))
    cursor.executemany("""
    INSERT OR REPLACE INTO alerts (
        alert_id, threat_id, indicator_value, alert_type, severity,
        risk_score, confidence_score, description, status, observation_count, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts_batch)

    conn.commit()
    print("Database schema created and successfully seeded with synthetic threat records!")

if __name__ == "__main__":
    init_db(force_reseed=True)
