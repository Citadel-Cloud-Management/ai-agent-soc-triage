"""Create tickets in Jira or ServiceNow for triaged security incidents."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import requests

from src.analyzers.alert_classifier import ClassificationResult
from src.analyzers.correlation import SecurityAlert
from src.config import TicketConfig, TicketProvider

logger = logging.getLogger(__name__)


@dataclass
class TicketResult:
    """Result of ticket creation."""

    ticket_id: str
    ticket_url: str
    provider: str
    success: bool
    error: Optional[str] = None


class TicketCreator:
    """Creates incident tickets in Jira or ServiceNow.

    Generates structured ticket content from alert data and classification
    results, including IOCs, severity, MITRE ATT&CK references, and
    recommended response actions.
    """

    def __init__(self, config: Optional[TicketConfig] = None) -> None:
        self.config = config or TicketConfig()
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    def create_ticket(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        additional_context: str = "",
    ) -> TicketResult:
        """Create a ticket for a triaged security alert.

        Args:
            alert: The security alert.
            classification: LLM classification result.
            additional_context: Extra context to include.

        Returns:
            TicketResult with ticket ID and URL.
        """
        if self.config.provider == TicketProvider.JIRA:
            return self._create_jira_ticket(alert, classification, additional_context)
        elif self.config.provider == TicketProvider.SERVICENOW:
            return self._create_servicenow_ticket(alert, classification, additional_context)
        else:
            return TicketResult(
                ticket_id="", ticket_url="", provider=self.config.provider.value,
                success=False, error=f"Unsupported provider: {self.config.provider}",
            )

    def _create_jira_ticket(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        additional_context: str,
    ) -> TicketResult:
        """Create a Jira issue for the security incident."""
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Lowest",
        }

        description = self._build_description(alert, classification, additional_context)

        payload = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": f"[{classification.severity.value.upper()}] {alert.title}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(classification.severity.value, "Medium")},
                "labels": [
                    "security-incident",
                    classification.category.value,
                    classification.severity.value,
                ],
            }
        }

        try:
            auth = (self.config.username or "", self.config.api_key or "")
            resp = self._session.post(
                f"{self.config.base_url}/rest/api/2/issue",
                json=payload,
                auth=auth,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            ticket_key = data.get("key", "")

            return TicketResult(
                ticket_id=ticket_key,
                ticket_url=f"{self.config.base_url}/browse/{ticket_key}",
                provider="jira",
                success=True,
            )
        except requests.RequestException as e:
            logger.error("Failed to create Jira ticket: %s", e)
            return TicketResult(
                ticket_id="", ticket_url="", provider="jira",
                success=False, error=str(e),
            )

    def _create_servicenow_ticket(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        additional_context: str,
    ) -> TicketResult:
        """Create a ServiceNow security incident."""
        urgency_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
        description = self._build_description(alert, classification, additional_context)

        payload = {
            "short_description": f"[{classification.severity.value.upper()}] {alert.title}",
            "description": description,
            "urgency": urgency_map.get(classification.severity.value, "3"),
            "category": "Security",
            "subcategory": classification.category.value,
            "assignment_group": "SOC",
        }

        try:
            auth = (self.config.username or "", self.config.api_key or "")
            resp = self._session.post(
                f"{self.config.base_url}/api/now/table/sn_si_incident",
                json=payload,
                auth=auth,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("result", {})
            sys_id = data.get("sys_id", "")

            return TicketResult(
                ticket_id=data.get("number", sys_id),
                ticket_url=f"{self.config.base_url}/sn_si_incident.do?sys_id={sys_id}",
                provider="servicenow",
                success=True,
            )
        except requests.RequestException as e:
            logger.error("Failed to create ServiceNow ticket: %s", e)
            return TicketResult(
                ticket_id="", ticket_url="", provider="servicenow",
                success=False, error=str(e),
            )

    def _build_description(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        additional_context: str,
    ) -> str:
        """Build a structured ticket description."""
        ioc_lines = ""
        if alert.iocs:
            ioc_lines = "\n".join(f"  - [{ioc.ioc_type.value}] {ioc.value}" for ioc in alert.iocs)

        mitre_lines = ", ".join(classification.mitre_techniques) if classification.mitre_techniques else "N/A"
        actions = "\n".join(f"  - {a}" for a in classification.recommended_actions) if classification.recommended_actions else "N/A"

        return (
            f"SECURITY INCIDENT\n"
            f"{'=' * 40}\n\n"
            f"Alert Source: {alert.source}\n"
            f"Alert ID: {alert.alert_id}\n"
            f"Timestamp: {alert.timestamp.isoformat()}\n"
            f"Severity: {classification.severity.value.upper()}\n"
            f"Category: {classification.category.value}\n"
            f"Confidence: {classification.confidence:.0%}\n"
            f"False Positive Likelihood: {classification.false_positive_likelihood:.0%}\n\n"
            f"DESCRIPTION\n{'-' * 40}\n{alert.description}\n\n"
            f"CLASSIFICATION REASONING\n{'-' * 40}\n{classification.reasoning}\n\n"
            f"INDICATORS OF COMPROMISE\n{'-' * 40}\n{ioc_lines or 'None extracted'}\n\n"
            f"MITRE ATT&CK\n{'-' * 40}\n{mitre_lines}\n\n"
            f"RECOMMENDED ACTIONS\n{'-' * 40}\n{actions}\n\n"
            f"{f'ADDITIONAL CONTEXT{chr(10)}{additional_context}' if additional_context else ''}"
        )
