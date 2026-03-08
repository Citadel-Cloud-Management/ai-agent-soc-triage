"""Elastic SIEM connector for retrieving security alerts and detections."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from src.analyzers.correlation import SecurityAlert
from src.config import SIEMConfig

logger = logging.getLogger(__name__)


class ElasticConnector:
    """Connect to Elastic Security (SIEM) via the Elasticsearch REST API.

    Queries the .siem-signals and .alerts indices to retrieve detection
    alerts and signals from Elastic Security rules.

    Reference:
        https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html
    """

    def __init__(self, config: SIEMConfig) -> None:
        scheme = "https" if config.verify_ssl else "http"
        self.base_url = f"{scheme}://{config.host}:{config.port}"
        self.verify_ssl = config.verify_ssl
        self._session = requests.Session()
        self._session.verify = self.verify_ssl

        if config.api_key:
            self._session.headers.update({"Authorization": f"ApiKey {config.api_key}"})
        elif config.username and config.password:
            self._session.auth = (config.username, config.password)

        self._session.headers.update({"Content-Type": "application/json"})

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 100,
        sort: Optional[list[dict]] = None,
    ) -> list[dict[str, Any]]:
        """Execute an Elasticsearch search query.

        Args:
            index: Index pattern to search.
            query: Elasticsearch query DSL body.
            size: Maximum number of results.
            sort: Sort specification.

        Returns:
            List of hit source documents.
        """
        body: dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort

        resp = self._session.post(
            f"{self.base_url}/{index}/_search",
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]

    def get_detection_alerts(
        self,
        time_range_minutes: int = 60,
        severity_filter: Optional[str] = None,
        max_results: int = 100,
    ) -> list[SecurityAlert]:
        """Retrieve Elastic Security detection alerts.

        Args:
            time_range_minutes: How far back to search.
            severity_filter: Minimum severity level.
            max_results: Maximum alerts to retrieve.

        Returns:
            List of SecurityAlert objects.
        """
        must_clauses: list[dict[str, Any]] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{time_range_minutes}m",
                        "lte": "now",
                    }
                }
            }
        ]

        if severity_filter:
            must_clauses.append(
                {"term": {"signal.rule.severity": severity_filter}}
            )

        query = {"bool": {"must": must_clauses}}
        sort = [{"@timestamp": {"order": "desc"}}]

        raw_results = self.search(
            index=".siem-signals-*",
            query=query,
            size=max_results,
            sort=sort,
        )

        return [self._to_alert(r) for r in raw_results]

    def get_alerts_by_rule_id(self, rule_id: str, max_results: int = 50) -> list[SecurityAlert]:
        """Retrieve alerts triggered by a specific detection rule.

        Args:
            rule_id: Elastic Security rule ID.
            max_results: Maximum number of alerts.

        Returns:
            List of SecurityAlert objects.
        """
        query = {"bool": {"must": [{"term": {"signal.rule.id": rule_id}}]}}
        raw_results = self.search(
            index=".siem-signals-*",
            query=query,
            size=max_results,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        return [self._to_alert(r) for r in raw_results]

    def _to_alert(self, raw: dict[str, Any]) -> SecurityAlert:
        """Convert a raw Elastic detection signal to a SecurityAlert."""
        signal = raw.get("signal", raw.get("kibana.alert", {}))
        rule = signal.get("rule", {})

        timestamp_str = raw.get("@timestamp", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        source_doc = signal.get("original_event", raw)

        return SecurityAlert(
            alert_id=signal.get("_id", raw.get("_id", "")),
            source="elastic",
            title=rule.get("name", "Elastic Detection"),
            description=rule.get("description", ""),
            timestamp=timestamp,
            severity=rule.get("severity", "medium"),
            raw_data=raw,
            metadata={
                "rule_id": rule.get("id", ""),
                "rule_type": rule.get("type", ""),
                "mitre_tactics": rule.get("threat", []),
                "src_ip": source_doc.get("source", {}).get("ip", ""),
                "dest_ip": source_doc.get("destination", {}).get("ip", ""),
                "hostname": source_doc.get("host", {}).get("name", ""),
            },
        )
