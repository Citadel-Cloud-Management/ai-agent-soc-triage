"""Configuration management for the SOC triage agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SIEMProvider(str, Enum):
    """Supported SIEM platforms."""

    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    ELASTIC = "elastic"


class TicketProvider(str, Enum):
    """Supported ticketing platforms."""

    JIRA = "jira"
    SERVICENOW = "servicenow"


class NotificationChannel(str, Enum):
    """Supported notification channels."""

    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    provider: str = "openai"
    model: str = "gpt-4o"
    temperature: float = 0.0
    max_tokens: int = 4096
    api_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.api_key is None:
            env_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
            }
            self.api_key = os.environ.get(env_map.get(self.provider, ""), "")


@dataclass
class SIEMConfig:
    """SIEM connection configuration."""

    provider: SIEMProvider = SIEMProvider.SPLUNK
    host: str = ""
    port: int = 8089
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True
    workspace_id: Optional[str] = None
    index: str = "main"

    def __post_init__(self) -> None:
        if not self.host:
            env_prefix = self.provider.value.upper()
            self.host = os.environ.get(f"{env_prefix}_HOST", "localhost")
            self.api_key = os.environ.get(f"{env_prefix}_API_KEY")
            self.username = os.environ.get(f"{env_prefix}_USERNAME")
            self.password = os.environ.get(f"{env_prefix}_PASSWORD")


@dataclass
class ThreatIntelConfig:
    """Threat intelligence feed configuration."""

    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.virustotal_api_key = self.virustotal_api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.abuseipdb_api_key = self.abuseipdb_api_key or os.environ.get("ABUSEIPDB_API_KEY")
        self.otx_api_key = self.otx_api_key or os.environ.get("OTX_API_KEY")


@dataclass
class TicketConfig:
    """Ticketing system configuration."""

    provider: TicketProvider = TicketProvider.JIRA
    base_url: str = ""
    api_key: Optional[str] = None
    project_key: str = "SOC"
    username: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = os.environ.get("TICKET_BASE_URL", "")
            self.api_key = os.environ.get("TICKET_API_KEY")
            self.username = os.environ.get("TICKET_USERNAME")


@dataclass
class NotificationConfig:
    """Notification channel configuration."""

    channels: list[NotificationChannel] = field(
        default_factory=lambda: [NotificationChannel.SLACK]
    )
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None
    pagerduty_api_key: Optional[str] = None
    email_smtp_host: str = ""
    email_from: str = ""

    def __post_init__(self) -> None:
        self.slack_webhook_url = self.slack_webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.teams_webhook_url = self.teams_webhook_url or os.environ.get("TEAMS_WEBHOOK_URL")
        self.pagerduty_api_key = self.pagerduty_api_key or os.environ.get("PAGERDUTY_API_KEY")


@dataclass
class TriageConfig:
    """Top-level triage engine configuration."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    siem: SIEMConfig = field(default_factory=SIEMConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    ticket: TicketConfig = field(default_factory=TicketConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    playbook_directory: str = "./playbooks"
    auto_respond_threshold: str = "high"
    max_correlation_window_minutes: int = 60
    enable_auto_response: bool = False

    @classmethod
    def from_env(cls) -> "TriageConfig":
        """Create configuration from environment variables."""
        return cls(
            llm=LLMConfig(),
            siem=SIEMConfig(
                provider=SIEMProvider(os.environ.get("SIEM_PROVIDER", "splunk")),
            ),
            threat_intel=ThreatIntelConfig(),
            ticket=TicketConfig(),
            notification=NotificationConfig(),
        )
