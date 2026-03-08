"""Event correlation engine for linking related security alerts."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from src.analyzers.ioc_extractor import IOC, IOCExtractor

logger = logging.getLogger(__name__)


@dataclass
class SecurityAlert:
    """A normalized security alert."""

    alert_id: str
    source: str
    title: str
    description: str
    timestamp: datetime
    severity: str = "medium"
    raw_data: dict[str, Any] = field(default_factory=dict)
    iocs: list[IOC] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = str(uuid4())


@dataclass
class CorrelationGroup:
    """A group of correlated alerts that may represent a single incident."""

    group_id: str
    alerts: list[SecurityAlert]
    shared_iocs: list[IOC]
    correlation_reasons: list[str]
    earliest_timestamp: datetime
    latest_timestamp: datetime
    combined_severity: str

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def time_span_minutes(self) -> float:
        delta = self.latest_timestamp - self.earliest_timestamp
        return delta.total_seconds() / 60.0


class EventCorrelator:
    """Correlates security alerts to identify related incidents.

    Uses IOC overlap, temporal proximity, and source similarity to group
    alerts that likely belong to the same attack or incident.
    """

    SEVERITY_RANK = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_ioc_overlap: int = 1,
    ) -> None:
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_ioc_overlap = min_ioc_overlap
        self.ioc_extractor = IOCExtractor()
        self._alert_store: list[SecurityAlert] = []

    def add_alert(self, alert: SecurityAlert) -> None:
        """Add an alert to the correlation store.

        If the alert has no IOCs extracted yet, the extractor runs automatically.

        Args:
            alert: The security alert to add.
        """
        if not alert.iocs:
            alert.iocs = self.ioc_extractor.extract(
                f"{alert.title} {alert.description} {alert.raw_data}"
            )
        self._alert_store.append(alert)

    def correlate(self) -> list[CorrelationGroup]:
        """Run correlation across all stored alerts.

        Returns:
            List of CorrelationGroup objects representing related alert clusters.
        """
        if not self._alert_store:
            return []

        sorted_alerts = sorted(self._alert_store, key=lambda a: a.timestamp)
        visited: set[str] = set()
        groups: list[CorrelationGroup] = []

        for alert in sorted_alerts:
            if alert.alert_id in visited:
                continue

            related = self._find_related(alert, sorted_alerts, visited)
            if related:
                all_alerts = [alert] + related
                visited.update(a.alert_id for a in all_alerts)

                shared_iocs = self._find_shared_iocs(all_alerts)
                reasons = self._build_reasons(alert, related)
                timestamps = [a.timestamp for a in all_alerts]

                group = CorrelationGroup(
                    group_id=str(uuid4()),
                    alerts=all_alerts,
                    shared_iocs=shared_iocs,
                    correlation_reasons=reasons,
                    earliest_timestamp=min(timestamps),
                    latest_timestamp=max(timestamps),
                    combined_severity=self._max_severity(all_alerts),
                )
                groups.append(group)
            else:
                visited.add(alert.alert_id)

        return groups

    def _find_related(
        self,
        target: SecurityAlert,
        all_alerts: list[SecurityAlert],
        visited: set[str],
    ) -> list[SecurityAlert]:
        """Find alerts related to the target alert."""
        related = []
        target_ioc_values = {ioc.value for ioc in target.iocs}

        for alert in all_alerts:
            if alert.alert_id == target.alert_id or alert.alert_id in visited:
                continue

            time_delta = abs((alert.timestamp - target.timestamp).total_seconds())
            if time_delta > self.time_window.total_seconds():
                continue

            alert_ioc_values = {ioc.value for ioc in alert.iocs}
            overlap = target_ioc_values & alert_ioc_values

            if len(overlap) >= self.min_ioc_overlap:
                related.append(alert)
            elif alert.source == target.source and time_delta < 300:
                related.append(alert)

        return related

    def _find_shared_iocs(self, alerts: list[SecurityAlert]) -> list[IOC]:
        """Find IOCs that appear in multiple alerts."""
        ioc_counts: dict[str, tuple[IOC, int]] = {}
        for alert in alerts:
            for ioc in alert.iocs:
                key = f"{ioc.ioc_type.value}:{ioc.value}"
                if key not in ioc_counts:
                    ioc_counts[key] = (ioc, 0)
                ioc_counts[key] = (ioc, ioc_counts[key][1] + 1)

        return [ioc for ioc, count in ioc_counts.values() if count > 1]

    def _build_reasons(self, target: SecurityAlert, related: list[SecurityAlert]) -> list[str]:
        """Build human-readable correlation reasons."""
        reasons = []
        target_ioc_values = {ioc.value for ioc in target.iocs}

        for alert in related:
            alert_ioc_values = {ioc.value for ioc in alert.iocs}
            overlap = target_ioc_values & alert_ioc_values
            if overlap:
                reasons.append(
                    f"Shared IOCs between '{target.title}' and '{alert.title}': "
                    f"{', '.join(list(overlap)[:3])}"
                )
            if alert.source == target.source:
                reasons.append(
                    f"Same source ({alert.source}) within time window"
                )
        return reasons

    def _max_severity(self, alerts: list[SecurityAlert]) -> str:
        """Return the highest severity among a list of alerts."""
        max_rank = 0
        max_sev = "informational"
        for alert in alerts:
            rank = self.SEVERITY_RANK.get(alert.severity.lower(), 0)
            if rank > max_rank:
                max_rank = rank
                max_sev = alert.severity
        return max_sev

    def clear(self) -> None:
        """Clear all stored alerts."""
        self._alert_store.clear()
