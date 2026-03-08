"""LLM-based alert severity classifier."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from src.config import LLMConfig

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertCategory(str, Enum):
    """Alert category classifications."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Result of alert classification."""

    severity: Severity
    category: AlertCategory
    confidence: float
    reasoning: str
    recommended_actions: list[str]
    mitre_techniques: list[str]
    false_positive_likelihood: float


class AlertClassifier:
    """Classifies security alerts using an LLM to determine severity and category.

    The classifier analyzes alert data including source, description, raw logs,
    and contextual information to produce a structured classification.
    """

    CLASSIFICATION_PROMPT = (
        "You are an expert SOC analyst. Analyze the following security alert and classify it.\n\n"
        "Provide your analysis as a JSON object with these fields:\n"
        "- severity: one of [critical, high, medium, low, informational]\n"
        "- category: one of [malware, phishing, brute_force, data_exfiltration, "
        "insider_threat, lateral_movement, privilege_escalation, denial_of_service, "
        "reconnaissance, unknown]\n"
        "- confidence: float 0.0-1.0\n"
        "- reasoning: brief explanation of your classification\n"
        "- recommended_actions: list of recommended response actions\n"
        "- mitre_techniques: list of relevant MITRE ATT&CK technique IDs (e.g., T1566.001)\n"
        "- false_positive_likelihood: float 0.0-1.0\n\n"
        "Consider:\n"
        "- The source system and its reliability\n"
        "- Whether the indicators match known attack patterns\n"
        "- The potential impact on the organization\n"
        "- Historical false positive rates for similar alerts\n\n"
        "Respond with ONLY the JSON object, no other text."
    )

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        llm_config = config or LLMConfig()
        self.llm = ChatOpenAI(
            model=llm_config.model,
            temperature=llm_config.temperature,
            max_tokens=llm_config.max_tokens,
            api_key=llm_config.api_key,
        )

    def classify(self, alert: dict[str, Any]) -> ClassificationResult:
        """Classify a security alert.

        Args:
            alert: Dictionary containing alert data with keys like
                   'source', 'title', 'description', 'raw_log', 'timestamp'.

        Returns:
            ClassificationResult with severity, category, and recommendations.
        """
        alert_text = self._format_alert(alert)
        messages = [
            SystemMessage(content=self.CLASSIFICATION_PROMPT),
            HumanMessage(content=f"Alert data:\n{alert_text}"),
        ]

        response = self.llm.invoke(messages)
        content = response.content if isinstance(response.content, str) else str(response.content)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(content[start:end])
            else:
                logger.error("Failed to parse LLM classification response")
                return self._default_classification()

        return ClassificationResult(
            severity=Severity(parsed.get("severity", "medium")),
            category=AlertCategory(parsed.get("category", "unknown")),
            confidence=float(parsed.get("confidence", 0.5)),
            reasoning=parsed.get("reasoning", ""),
            recommended_actions=parsed.get("recommended_actions", []),
            mitre_techniques=parsed.get("mitre_techniques", []),
            false_positive_likelihood=float(parsed.get("false_positive_likelihood", 0.5)),
        )

    def _format_alert(self, alert: dict[str, Any]) -> str:
        """Format alert data into a readable string for the LLM."""
        parts = []
        for key in ["source", "title", "description", "timestamp", "severity", "raw_log"]:
            if key in alert:
                parts.append(f"{key.upper()}: {alert[key]}")
        if "metadata" in alert and isinstance(alert["metadata"], dict):
            for k, v in alert["metadata"].items():
                parts.append(f"  {k}: {v}")
        return "\n".join(parts)

    def _default_classification(self) -> ClassificationResult:
        """Return a default classification when parsing fails."""
        return ClassificationResult(
            severity=Severity.MEDIUM,
            category=AlertCategory.UNKNOWN,
            confidence=0.0,
            reasoning="Classification failed - manual review required.",
            recommended_actions=["Escalate to senior analyst for manual review"],
            mitre_techniques=[],
            false_positive_likelihood=0.5,
        )
