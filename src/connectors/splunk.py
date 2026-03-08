"""Splunk SIEM connector for retrieving security alerts."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from src.analyzers.correlation import SecurityAlert
from src.config import SIEMConfig

logger = logging.getLogger(__name__)


class SplunkConnector:
    """Connect to Splunk via the REST API to retrieve security alerts.

    Supports both Splunk Enterprise and Splunk Cloud. Uses the search/jobs
    endpoint to run SPL queries and retrieve results.

    Reference:
        https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
    """

    def __init__(self, config: SIEMConfig) -> None:
        self.base_url = f"https://{config.host}:{config.port}"
        self.auth = (config.username or "", config.password or "")
        self.verify_ssl = config.verify_ssl
        self.index = config.index
        self._session = requests.Session()
        self._session.auth = self.auth
        self._session.verify = self.verify_ssl

    def search(
        self,
        query: str,
        earliest_time: str = "-1h",
        latest_time: str = "now",
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute a Splunk SPL search query.

        Args:
            query: SPL search query string.
            earliest_time: Search time range start (e.g., '-1h', '-24h@h').
            latest_time: Search time range end.
            max_results: Maximum number of results.

        Returns:
            List of result dictionaries.
        """
        search_query = query if query.startswith("search") else f"search {query}"

        job_data = {
            "search": search_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
            "max_count": max_results,
        }

        resp = self._session.post(
            f"{self.base_url}/services/search/jobs",
            data=job_data,
            timeout=30,
        )
        resp.raise_for_status()
        job_sid = resp.json().get("sid")

        return self._wait_for_results(job_sid, max_results)

    def get_notable_events(
        self,
        earliest_time: str = "-1h",
        severity_filter: Optional[str] = None,
    ) -> list[SecurityAlert]:
        """Retrieve notable events from Splunk Enterprise Security.

        Args:
            earliest_time: How far back to search.
            severity_filter: Minimum severity to include.

        Returns:
            List of SecurityAlert objects.
        """
        query = f'search index=notable | head 100'
        if severity_filter:
            query += f' | where urgency>="{severity_filter}"'

        raw_results = self.search(query, earliest_time=earliest_time)
        return [self._to_alert(r) for r in raw_results]

    def get_alerts_by_rule(self, rule_name: str, earliest_time: str = "-24h") -> list[SecurityAlert]:
        """Retrieve alerts triggered by a specific correlation rule.

        Args:
            rule_name: Name of the Splunk correlation search / alert.
            earliest_time: Search time range.

        Returns:
            List of SecurityAlert objects.
        """
        query = (
            f'search index=notable search_name="{rule_name}" '
            f'| sort -_time | head 50'
        )
        raw_results = self.search(query, earliest_time=earliest_time)
        return [self._to_alert(r) for r in raw_results]

    def _wait_for_results(self, job_sid: str, max_results: int) -> list[dict[str, Any]]:
        """Poll a Splunk search job until completion and retrieve results."""
        status_url = f"{self.base_url}/services/search/jobs/{job_sid}"
        for _ in range(120):
            resp = self._session.get(
                status_url,
                params={"output_mode": "json"},
                timeout=15,
            )
            resp.raise_for_status()
            entry = resp.json().get("entry", [{}])[0]
            content = entry.get("content", {})

            if content.get("isDone"):
                break
            time.sleep(1)
        else:
            logger.warning("Splunk search job %s timed out", job_sid)
            return []

        results_url = f"{status_url}/results"
        resp = self._session.get(
            results_url,
            params={"output_mode": "json", "count": max_results},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])

    def _to_alert(self, raw: dict[str, Any]) -> SecurityAlert:
        """Convert a raw Splunk result to a SecurityAlert."""
        timestamp_str = raw.get("_time", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        return SecurityAlert(
            alert_id=raw.get("event_id", raw.get("_cd", "")),
            source="splunk",
            title=raw.get("search_name", raw.get("rule_name", "Splunk Alert")),
            description=raw.get("description", raw.get("_raw", "")),
            timestamp=timestamp,
            severity=raw.get("urgency", raw.get("severity", "medium")),
            raw_data=raw,
            metadata={
                "src_ip": raw.get("src", ""),
                "dest_ip": raw.get("dest", ""),
                "user": raw.get("user", ""),
            },
        )
