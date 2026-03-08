"""Example: Batch triage of multiple security alerts from a SIEM connector."""

from datetime import datetime, timezone

from src.analyzers.correlation import SecurityAlert
from src.config import SIEMConfig, SIEMProvider, TriageConfig
from src.triage_engine import TriageEngine


def create_sample_alerts() -> list[SecurityAlert]:
    """Generate sample alerts for demonstration."""
    return [
        SecurityAlert(
            alert_id="ALERT-001",
            source="elastic",
            title="Suspicious PowerShell Execution",
            description=(
                "PowerShell process launched with encoded command on endpoint "
                "WS-FINANCE-03. Command decodes to a download cradle fetching "
                "payload from hxxp://malware-c2.evil.com/stage2.ps1. "
                "File hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
            ),
            timestamp=datetime.now(timezone.utc),
            severity="critical",
            raw_data={
                "hostname": "WS-FINANCE-03",
                "process": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell -enc SQBFAFgA...",
                "user": "jdoe",
            },
        ),
        SecurityAlert(
            alert_id="ALERT-002",
            source="splunk",
            title="Phishing Email Detected",
            description=(
                "Email from spoofed sender hr-department@cornpany.com (typosquat) "
                "with subject 'Urgent: Update Your Benefits' containing URL "
                "https://cornpany-hr-portal.com/login and attachment benefits.docm. "
                "Sent to 15 recipients in the finance department."
            ),
            timestamp=datetime.now(timezone.utc),
            severity="high",
            raw_data={
                "sender": "hr-department@cornpany.com",
                "recipients_count": 15,
                "url": "https://cornpany-hr-portal.com/login",
                "attachment": "benefits.docm",
                "department": "finance",
            },
        ),
        SecurityAlert(
            alert_id="ALERT-003",
            source="sentinel",
            title="Unusual Data Transfer to External Storage",
            description=(
                "User svc-admin uploaded 2.3 GB of data to external cloud storage "
                "service at 2:47 AM local time. The service account does not normally "
                "access external storage. Source IP: 10.0.5.22, destination: "
                "storage.exfil-service.net"
            ),
            timestamp=datetime.now(timezone.utc),
            severity="high",
            raw_data={
                "user": "svc-admin",
                "bytes_transferred": 2_469_000_000,
                "destination": "storage.exfil-service.net",
                "src_ip": "10.0.5.22",
                "time_of_day": "02:47",
            },
        ),
    ]


def main() -> None:
    config = TriageConfig.from_env()
    config.enable_auto_response = False

    engine = TriageEngine(config)
    alerts = create_sample_alerts()

    print(f"Batch triaging {len(alerts)} alerts...")
    print("=" * 60)

    results = engine.triage_batch(alerts)

    for i, result in enumerate(results, 1):
        print(f"\n[{i}/{len(results)}] {result.alert.title}")
        print(f"  Severity: {result.classification.severity.value.upper()}")
        print(f"  Category: {result.classification.category.value}")
        print(f"  Confidence: {result.classification.confidence:.0%}")
        print(f"  Actionable: {result.is_actionable}")
        print(f"  IOCs: {len(result.alert.iocs)}")
        if result.classification.recommended_actions:
            print(f"  Top action: {result.classification.recommended_actions[0]}")
        print()

    stats = engine.get_statistics()
    print("=" * 60)
    print("SESSION STATISTICS")
    print(f"  Total triaged: {stats['total']}")
    print(f"  Actionable: {stats['actionable']}")
    print(f"  Severity breakdown: {stats['severity_breakdown']}")
    print(f"  Category breakdown: {stats['category_breakdown']}")


if __name__ == "__main__":
    main()
