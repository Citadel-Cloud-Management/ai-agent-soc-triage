"""Indicator of Compromise (IOC) extractor using regex and LLM enrichment."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    CVE = "cve"


@dataclass
class IOC:
    """A single Indicator of Compromise."""

    ioc_type: IOCType
    value: str
    context: str = ""
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)


class IOCExtractor:
    """Extracts Indicators of Compromise from alert text and log data.

    Uses regular expressions for high-confidence extraction of IPs, domains,
    hashes, URLs, email addresses, file paths, and CVE identifiers.
    """

    PATTERNS: dict[IOCType, re.Pattern] = {
        IOCType.IPV4: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
        ),
        IOCType.IPV6: re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        ),
        IOCType.DOMAIN: re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
            r"+[a-zA-Z]{2,}\b"
        ),
        IOCType.URL: re.compile(
            r"https?://[^\s<>\"']+|hxxps?://[^\s<>\"']+"
        ),
        IOCType.EMAIL: re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        IOCType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
        IOCType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
        IOCType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
        IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    }

    PRIVATE_IP_RANGES = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
    ]

    WHITELISTED_DOMAINS = {
        "microsoft.com", "google.com", "amazonaws.com", "azure.com",
        "windows.net", "office365.com", "office.com",
    }

    def __init__(self, filter_private_ips: bool = True, filter_whitelisted: bool = True) -> None:
        self.filter_private_ips = filter_private_ips
        self.filter_whitelisted = filter_whitelisted

    def extract(self, text: str) -> list[IOC]:
        """Extract all IOCs from the given text.

        Args:
            text: Raw text (alert description, log entry, etc.) to scan.

        Returns:
            List of extracted IOC objects, deduplicated.
        """
        iocs: list[IOC] = []
        seen: set[tuple[str, str]] = set()

        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group().strip()

                if ioc_type == IOCType.URL:
                    value = value.replace("hxxp", "http")

                if (ioc_type.value, value) in seen:
                    continue

                if not self._should_include(ioc_type, value):
                    continue

                context = self._extract_context(text, match.start(), match.end())
                iocs.append(IOC(ioc_type=ioc_type, value=value, context=context))
                seen.add((ioc_type.value, value))

        return iocs

    def extract_from_alert(self, alert: dict[str, Any]) -> list[IOC]:
        """Extract IOCs from a structured alert dictionary.

        Args:
            alert: Alert data with fields like 'description', 'raw_log', etc.

        Returns:
            Deduplicated list of IOCs from all text fields.
        """
        text_parts = []
        for key in ["title", "description", "raw_log", "message", "details"]:
            if key in alert and isinstance(alert[key], str):
                text_parts.append(alert[key])

        if "metadata" in alert and isinstance(alert["metadata"], dict):
            for v in alert["metadata"].values():
                if isinstance(v, str):
                    text_parts.append(v)

        combined_text = "\n".join(text_parts)
        return self.extract(combined_text)

    def _should_include(self, ioc_type: IOCType, value: str) -> bool:
        """Check whether an IOC should be included based on filters."""
        if ioc_type == IOCType.IPV4 and self.filter_private_ips:
            for pattern in self.PRIVATE_IP_RANGES:
                if pattern.match(value):
                    return False

        if ioc_type == IOCType.DOMAIN and self.filter_whitelisted:
            for domain in self.WHITELISTED_DOMAINS:
                if value.endswith(domain):
                    return False

        return True

    def _extract_context(self, text: str, start: int, end: int, window: int = 80) -> str:
        """Extract surrounding context for an IOC match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].replace("\n", " ").strip()

    def summarize(self, iocs: list[IOC]) -> dict[str, list[str]]:
        """Group IOCs by type for summary reporting.

        Args:
            iocs: List of IOC objects.

        Returns:
            Dictionary mapping IOC type names to lists of values.
        """
        summary: dict[str, list[str]] = {}
        for ioc in iocs:
            key = ioc.ioc_type.value
            if key not in summary:
                summary[key] = []
            summary[key].append(ioc.value)
        return summary
