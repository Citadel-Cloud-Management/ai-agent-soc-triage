"""Send notifications via Slack, Teams, PagerDuty, or email."""

from __future__ import annotations

import json
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

import requests

from src.analyzers.alert_classifier import ClassificationResult
from src.analyzers.correlation import SecurityAlert
from src.config import NotificationChannel, NotificationConfig

logger = logging.getLogger(__name__)


class Notifier:
    """Send alert notifications to configured channels.

    Supports Slack webhooks, Microsoft Teams webhooks, PagerDuty Events API v2,
    and SMTP email notifications.
    """

    def __init__(self, config: Optional[NotificationConfig] = None) -> None:
        self.config = config or NotificationConfig()
        self._session = requests.Session()

    def notify(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        message: str = "",
    ) -> dict[str, bool]:
        """Send notifications to all configured channels.

        Args:
            alert: The security alert.
            classification: LLM classification result.
            message: Optional custom message.

        Returns:
            Dictionary mapping channel names to success status.
        """
        results: dict[str, bool] = {}
        for channel in self.config.channels:
            try:
                if channel == NotificationChannel.SLACK:
                    results["slack"] = self._send_slack(alert, classification, message)
                elif channel == NotificationChannel.TEAMS:
                    results["teams"] = self._send_teams(alert, classification, message)
                elif channel == NotificationChannel.PAGERDUTY:
                    results["pagerduty"] = self._send_pagerduty(alert, classification)
                elif channel == NotificationChannel.EMAIL:
                    results["email"] = self._send_email(alert, classification, message)
            except Exception:
                logger.exception("Failed to send %s notification", channel.value)
                results[channel.value] = False
        return results

    def _send_slack(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        message: str,
    ) -> bool:
        """Send a Slack notification via incoming webhook."""
        if not self.config.slack_webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        severity_emoji = {
            "critical": ":red_circle:",
            "high": ":large_orange_circle:",
            "medium": ":large_yellow_circle:",
            "low": ":large_blue_circle:",
            "informational": ":white_circle:",
        }
        emoji = severity_emoji.get(classification.severity.value, ":question:")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Alert: {alert.title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{classification.severity.value.upper()}"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{classification.category.value}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{classification.confidence:.0%}"},
                    {"type": "mrkdwn", "text": f"*Source:*\n{alert.source}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reasoning:*\n{classification.reasoning[:500]}"},
            },
        ]

        if classification.recommended_actions:
            actions_text = "\n".join(f"  {i+1}. {a}" for i, a in enumerate(classification.recommended_actions[:5]))
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended Actions:*\n{actions_text}"},
            })

        payload = {"blocks": blocks}
        if message:
            payload["text"] = message

        resp = self._session.post(
            self.config.slack_webhook_url,
            json=payload,
            timeout=10,
        )
        return resp.status_code == 200

    def _send_teams(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        message: str,
    ) -> bool:
        """Send a Microsoft Teams notification via incoming webhook."""
        if not self.config.teams_webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False

        color_map = {"critical": "FF0000", "high": "FF8C00", "medium": "FFD700", "low": "4169E1"}
        color = color_map.get(classification.severity.value, "808080")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Security Alert: {alert.title}",
            "sections": [
                {
                    "activityTitle": f"Security Alert: {alert.title}",
                    "facts": [
                        {"name": "Severity", "value": classification.severity.value.upper()},
                        {"name": "Category", "value": classification.category.value},
                        {"name": "Source", "value": alert.source},
                        {"name": "Confidence", "value": f"{classification.confidence:.0%}"},
                        {"name": "Timestamp", "value": alert.timestamp.isoformat()},
                    ],
                    "text": classification.reasoning[:500],
                }
            ],
        }

        resp = self._session.post(
            self.config.teams_webhook_url,
            json=payload,
            timeout=10,
        )
        return resp.status_code == 200

    def _send_pagerduty(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
    ) -> bool:
        """Send a PagerDuty event via the Events API v2."""
        if not self.config.pagerduty_api_key:
            logger.warning("PagerDuty API key not configured")
            return False

        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "informational": "info",
        }

        payload = {
            "routing_key": self.config.pagerduty_api_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[{classification.severity.value.upper()}] {alert.title}",
                "severity": severity_map.get(classification.severity.value, "warning"),
                "source": alert.source,
                "component": "soc-triage-agent",
                "group": classification.category.value,
                "custom_details": {
                    "reasoning": classification.reasoning,
                    "confidence": classification.confidence,
                    "mitre_techniques": classification.mitre_techniques,
                    "recommended_actions": classification.recommended_actions,
                },
            },
        }

        resp = self._session.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10,
        )
        return resp.status_code == 202

    def _send_email(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
        message: str,
    ) -> bool:
        """Send an email notification via SMTP."""
        if not self.config.email_smtp_host or not self.config.email_from:
            logger.warning("Email SMTP not configured")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{classification.severity.value.upper()}] SOC Alert: {alert.title}"
        msg["From"] = self.config.email_from
        msg["To"] = self.config.email_from

        body = (
            f"Security Alert: {alert.title}\n\n"
            f"Severity: {classification.severity.value.upper()}\n"
            f"Category: {classification.category.value}\n"
            f"Source: {alert.source}\n"
            f"Timestamp: {alert.timestamp.isoformat()}\n\n"
            f"Reasoning:\n{classification.reasoning}\n\n"
            f"Recommended Actions:\n"
        )
        for action in classification.recommended_actions:
            body += f"  - {action}\n"

        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.config.email_smtp_host) as server:
                server.send_message(msg)
            return True
        except smtplib.SMTPException as e:
            logger.error("SMTP send failed: %s", e)
            return False
