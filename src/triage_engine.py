"""Main triage engine that orchestrates alert analysis and response."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from src.analyzers.alert_classifier import AlertClassifier, ClassificationResult, Severity
from src.analyzers.correlation import EventCorrelator, SecurityAlert
from src.analyzers.ioc_extractor import IOCExtractor
from src.analyzers.threat_intel import ThreatIntelLookup, ThreatIntelResult
from src.config import TriageConfig
from src.responders.notifier import Notifier
from src.responders.playbook_runner import PlaybookRunner, PlaybookResult
from src.responders.ticket_creator import TicketCreator, TicketResult

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Complete result of triaging a security alert."""

    alert: SecurityAlert
    classification: ClassificationResult
    threat_intel_results: list[ThreatIntelResult] = field(default_factory=list)
    playbook_result: Optional[PlaybookResult] = None
    ticket_result: Optional[TicketResult] = None
    notification_results: dict[str, bool] = field(default_factory=dict)
    correlated_alert_count: int = 0

    @property
    def is_actionable(self) -> bool:
        """Whether this alert requires human action."""
        return (
            self.classification.severity in (Severity.CRITICAL, Severity.HIGH)
            and self.classification.false_positive_likelihood < 0.5
        )


class TriageEngine:
    """Orchestrates the full SOC triage workflow.

    Pipeline:
        1. Extract IOCs from alert data
        2. Classify alert severity and category using LLM
        3. Look up IOCs against threat intelligence feeds
        4. Correlate with other recent alerts
        5. Execute response playbook (if auto-response enabled)
        6. Create incident ticket
        7. Send notifications

    Usage:
        config = TriageConfig.from_env()
        engine = TriageEngine(config)
        result = engine.triage(alert)
    """

    SEVERITY_ORDER = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1,
    }

    def __init__(self, config: Optional[TriageConfig] = None) -> None:
        self.config = config or TriageConfig.from_env()

        self.ioc_extractor = IOCExtractor()
        self.classifier = AlertClassifier(config=self.config.llm)
        self.threat_intel = ThreatIntelLookup(config=self.config.threat_intel)
        self.correlator = EventCorrelator(
            time_window_minutes=self.config.max_correlation_window_minutes,
        )
        self.playbook_runner = PlaybookRunner(
            playbook_directory=self.config.playbook_directory,
        )
        self.ticket_creator = TicketCreator(config=self.config.ticket)
        self.notifier = Notifier(config=self.config.notification)

        self._triage_history: list[TriageResult] = []

    def triage(self, alert: SecurityAlert) -> TriageResult:
        """Run the full triage pipeline on a security alert.

        Args:
            alert: The security alert to triage.

        Returns:
            TriageResult with classification, threat intel, and response outcomes.
        """
        logger.info("Starting triage for alert: %s (%s)", alert.title, alert.alert_id)

        # Step 1: Extract IOCs
        if not alert.iocs:
            alert.iocs = self.ioc_extractor.extract_from_alert(alert.raw_data)
            logger.info("Extracted %d IOCs from alert", len(alert.iocs))

        # Step 2: Classify the alert
        alert_data = {
            "source": alert.source,
            "title": alert.title,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity,
            "raw_log": str(alert.raw_data),
            "metadata": alert.metadata,
        }
        classification = self.classifier.classify(alert_data)
        logger.info(
            "Classification: severity=%s, category=%s, confidence=%.2f",
            classification.severity.value,
            classification.category.value,
            classification.confidence,
        )

        # Step 3: Threat intelligence lookup
        ti_results: list[ThreatIntelResult] = []
        if alert.iocs:
            ti_results = self.threat_intel.lookup_batch(alert.iocs)
            malicious_count = sum(1 for r in ti_results if r.is_malicious)
            logger.info(
                "Threat intel: %d/%d IOCs flagged as malicious",
                malicious_count,
                len(ti_results),
            )

        # Step 4: Correlation
        self.correlator.add_alert(alert)
        groups = self.correlator.correlate()
        correlated_count = sum(g.alert_count for g in groups) - 1 if groups else 0

        # Step 5: Execute playbook (if auto-response enabled and threshold met)
        playbook_result = None
        if self.config.enable_auto_response:
            threshold_rank = self.SEVERITY_ORDER.get(
                Severity(self.config.auto_respond_threshold), 3
            )
            alert_rank = self.SEVERITY_ORDER.get(classification.severity, 0)
            if alert_rank >= threshold_rank:
                playbook_result = self.playbook_runner.run(alert, classification)
                if playbook_result:
                    logger.info(
                        "Playbook '%s' executed: %d/%d steps",
                        playbook_result.playbook_name,
                        playbook_result.steps_executed,
                        playbook_result.steps_total,
                    )

        # Step 6: Create ticket for high/critical alerts
        ticket_result = None
        if classification.severity in (Severity.CRITICAL, Severity.HIGH):
            ticket_result = self.ticket_creator.create_ticket(
                alert=alert,
                classification=classification,
                additional_context=self._build_context(ti_results, correlated_count),
            )
            if ticket_result.success:
                logger.info("Created ticket: %s", ticket_result.ticket_id)

        # Step 7: Send notifications
        notification_results: dict[str, bool] = {}
        if classification.severity in (Severity.CRITICAL, Severity.HIGH):
            notification_results = self.notifier.notify(
                alert=alert,
                classification=classification,
            )

        result = TriageResult(
            alert=alert,
            classification=classification,
            threat_intel_results=ti_results,
            playbook_result=playbook_result,
            ticket_result=ticket_result,
            notification_results=notification_results,
            correlated_alert_count=correlated_count,
        )

        self._triage_history.append(result)
        logger.info("Triage complete for alert %s", alert.alert_id)
        return result

    def triage_batch(self, alerts: list[SecurityAlert]) -> list[TriageResult]:
        """Triage multiple alerts, sorted by severity (most severe first).

        Args:
            alerts: List of alerts to triage.

        Returns:
            List of TriageResult objects.
        """
        sorted_alerts = sorted(
            alerts,
            key=lambda a: self.SEVERITY_ORDER.get(Severity(a.severity), 0),
            reverse=True,
        )
        return [self.triage(alert) for alert in sorted_alerts]

    def get_statistics(self) -> dict[str, Any]:
        """Return triage statistics from the current session."""
        if not self._triage_history:
            return {"total": 0}

        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        actionable = 0

        for result in self._triage_history:
            sev = result.classification.severity.value
            cat = result.classification.category.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1
            if result.is_actionable:
                actionable += 1

        return {
            "total": len(self._triage_history),
            "actionable": actionable,
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
        }

    def _build_context(self, ti_results: list[ThreatIntelResult], correlated_count: int) -> str:
        """Build additional context string for ticket creation."""
        parts = []
        if correlated_count > 0:
            parts.append(f"Correlated with {correlated_count} other recent alert(s).")

        malicious_iocs = [r for r in ti_results if r.is_malicious]
        if malicious_iocs:
            parts.append(f"{len(malicious_iocs)} IOC(s) flagged by threat intelligence:")
            for r in malicious_iocs[:5]:
                parts.append(f"  - {r.ioc.value} (score: {r.risk_score:.2f}, sources: {', '.join(r.sources)})")

        return "\n".join(parts)
