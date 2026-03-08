"""Example: Analyze a single security alert through the triage pipeline."""

from datetime import datetime, timezone

from src.analyzers.correlation import SecurityAlert
from src.config import TriageConfig
from src.triage_engine import TriageEngine


def main() -> None:
    config = TriageConfig.from_env()
    config.enable_auto_response = False

    engine = TriageEngine(config)

    alert = SecurityAlert(
        alert_id="ALERT-2026-001",
        source="splunk",
        title="Multiple Failed Login Attempts from External IP",
        description=(
            "Detected 47 failed login attempts from IP 203.0.113.42 targeting "
            "user accounts admin@corp.com and svc-backup@corp.com over a 5-minute "
            "window. Source IP is located in an unexpected geography. The IP has "
            "been observed in previous brute force campaigns."
        ),
        timestamp=datetime.now(timezone.utc),
        severity="high",
        raw_data={
            "src_ip": "203.0.113.42",
            "dest_ip": "10.0.1.50",
            "dest_port": 443,
            "failed_attempts": 47,
            "targeted_accounts": ["admin@corp.com", "svc-backup@corp.com"],
            "rule_name": "Brute Force Detection",
        },
        metadata={
            "src_ip": "203.0.113.42",
            "dest_ip": "10.0.1.50",
            "user": "admin@corp.com",
        },
    )

    print(f"Triaging alert: {alert.title}")
    print(f"Alert ID: {alert.alert_id}")
    print(f"Source: {alert.source}")
    print("-" * 60)

    result = engine.triage(alert)

    print(f"\nClassification:")
    print(f"  Severity: {result.classification.severity.value}")
    print(f"  Category: {result.classification.category.value}")
    print(f"  Confidence: {result.classification.confidence:.0%}")
    print(f"  False Positive Likelihood: {result.classification.false_positive_likelihood:.0%}")
    print(f"\nReasoning: {result.classification.reasoning}")

    print(f"\nMITRE ATT&CK Techniques:")
    for tech in result.classification.mitre_techniques:
        print(f"  - {tech}")

    print(f"\nRecommended Actions:")
    for action in result.classification.recommended_actions:
        print(f"  - {action}")

    print(f"\nIOCs Found: {len(result.alert.iocs)}")
    for ioc in result.alert.iocs:
        print(f"  [{ioc.ioc_type.value}] {ioc.value}")

    print(f"\nThreat Intel Results: {len(result.threat_intel_results)}")
    for ti in result.threat_intel_results:
        status = "MALICIOUS" if ti.is_malicious else "clean"
        print(f"  {ti.ioc.value}: {status} (score: {ti.risk_score:.2f})")

    print(f"\nCorrelated Alerts: {result.correlated_alert_count}")
    print(f"Actionable: {result.is_actionable}")


if __name__ == "__main__":
    main()
