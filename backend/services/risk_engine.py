"""
Threat Risk & Confidence Scoring Engine
Module: backend.services.risk_engine

Implements multi-factor risk scoring, confidence grading, and source reliability evaluation.

IMPORTANT DEFENSIVE PRINCIPLE:
High risk does NOT automatically mean confirmed compromise. Risk scores represent
potential exposure and priority for analyst triage, while confidence represents the
provenance, consistency, and fidelity of the supporting intelligence.
"""

def get_source_reliability_score(reliability_level: str) -> int:
    """
    Maps Admiralty System intelligence source reliability grading to a 0-100 numeric factor.
    A – Highly Reliable: 100
    B – Usually Reliable: 80
    C – Fairly Reliable: 60
    D – Reliability Unknown: 40
    """
    if not reliability_level:
        return 40
    level = reliability_level.strip().upper()
    if level.startswith("A"):
        return 100
    elif level.startswith("B"):
        return 80
    elif level.startswith("C"):
        return 60
    elif level.startswith("D"):
        return 40
    return 50

def get_severity_score(severity: str) -> int:
    """Maps qualitative severity to 0-100 base score."""
    mapping = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFORMATIONAL": 10
    }
    return mapping.get(severity.upper().strip(), 30)

def classify_risk_score(score: int) -> str:
    """
    Categorizes numeric risk score (0-100) into standardized tiers:
    0–20: INFORMATIONAL
    21–40: LOW
    41–60: MEDIUM
    61–80: HIGH
    81–100: CRITICAL
    """
    if score >= 81:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 41:
        return "MEDIUM"
    elif score >= 21:
        return "LOW"
    else:
        return "INFORMATIONAL"

def calculate_recency_score(days_old: int) -> int:
    """
    Recent activity poses immediate operational concern.
    <= 1 day: 100
    <= 7 days: 85
    <= 30 days: 60
    <= 60 days: 40
    > 60 days: 20
    """
    if days_old <= 1:
        return 100
    elif days_old <= 7:
        return 85
    elif days_old <= 30:
        return 60
    elif days_old <= 60:
        return 40
    else:
        return 20

def calculate_frequency_score(observation_count: int) -> int:
    """Higher observation counts signify persistent or widespread campaign presence."""
    if observation_count > 100:
        return 100
    elif observation_count > 50:
        return 80
    elif observation_count > 20:
        return 60
    elif observation_count > 5:
        return 40
    elif observation_count > 1:
        return 25
    return 15

def calculate_threat_risk(
    severity: str,
    confidence: int,
    recency_days: int = 3,
    observation_count: int = 1,
    source_reliability: str = "A",
    correlated_alerts_count: int = 0
) -> dict:
    """
    Calculates multi-factor risk score (0-100) using weighted defensive telemetry:
    - Severity Weight: 30%
    - Confidence Weight: 25%
    - Recency Weight: 15%
    - Observation Frequency: 10%
    - Source Reliability: 10%
    - Context / Correlation: 10%
    """
    sev_val = get_severity_score(severity)
    conf_val = max(0, min(100, int(confidence)))
    recency_val = calculate_recency_score(recency_days)
    freq_val = calculate_frequency_score(observation_count)
    src_val = get_source_reliability_score(source_reliability)
    
    # Correlation factor (more correlated alerts = higher context)
    correlation_val = min(100, correlated_alerts_count * 25 + (20 if correlated_alerts_count > 0 else 0))

    weighted_score = (
        (sev_val * 0.30) +
        (conf_val * 0.25) +
        (recency_val * 0.15) +
        (freq_val * 0.10) +
        (src_val * 0.10) +
        (correlation_val * 0.10)
    )

    final_score = int(round(max(0, min(100, weighted_score))))
    classification = classify_risk_score(final_score)
    interpretation = interpret_intelligence_posture(final_score, conf_val)

    return {
        "risk_score": final_score,
        "classification": classification,
        "severity_component": sev_val,
        "confidence_component": conf_val,
        "recency_component": recency_val,
        "frequency_component": freq_val,
        "source_reliability_component": src_val,
        "correlation_component": correlation_val,
        "interpretation": interpretation
    }

def interpret_intelligence_posture(risk_score: int, confidence_score: int) -> str:
    """
    Provides analyst narrative contrasting Risk vs Confidence.
    """
    if risk_score >= 60 and confidence_score >= 70:
        return "High-confidence intelligence with acute defensive risk. Priority for SOC triage."
    elif risk_score >= 50 and confidence_score < 50:
        return "Potentially serious impact, but supporting evidence quality is weak or unverified."
    elif risk_score < 40 and confidence_score >= 80:
        return "High-confidence benign or informational indicator. Low immediate defensive risk."
    elif risk_score >= 40 and confidence_score >= 50:
        return "Moderate risk supported by credible intelligence. Continue defensive monitoring."
    else:
        return "Low-to-moderate concern with preliminary intelligence. Standard monitoring recommended."

if __name__ == "__main__":
    test_1 = calculate_threat_risk("HIGH", 85, recency_days=2, observation_count=142, source_reliability="A", correlated_alerts_count=2)
    print("Scenario 1 (THR-2026-0001):", test_1)
    test_2 = calculate_threat_risk("CRITICAL", 25, recency_days=1, observation_count=3, source_reliability="D")
    print("Scenario 2 (High Risk, Low Confidence):", test_2)
