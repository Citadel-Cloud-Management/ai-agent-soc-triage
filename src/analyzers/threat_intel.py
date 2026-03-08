"""Threat intelligence lookup against multiple feeds."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from src.analyzers.ioc_extractor import IOC, IOCType
from src.config import ThreatIntelConfig

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence lookup."""

    ioc: IOC
    is_malicious: bool
    risk_score: float
    sources: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


class ThreatIntelLookup:
    """Query multiple threat intelligence feeds for IOC reputation data.

    Supports VirusTotal, AbuseIPDB, and AlienVault OTX. Falls back gracefully
    when API keys are not configured.
    """

    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
    OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, config: Optional[ThreatIntelConfig] = None) -> None:
        self.config = config or ThreatIntelConfig()
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        """Look up an IOC against all configured threat intelligence feeds.

        Args:
            ioc: The indicator of compromise to investigate.

        Returns:
            Aggregated threat intelligence result.
        """
        results: list[ThreatIntelResult] = []

        if self.config.virustotal_api_key:
            vt_result = self._lookup_virustotal(ioc)
            if vt_result:
                results.append(vt_result)

        if self.config.abuseipdb_api_key and ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            abuse_result = self._lookup_abuseipdb(ioc)
            if abuse_result:
                results.append(abuse_result)

        if self.config.otx_api_key:
            otx_result = self._lookup_otx(ioc)
            if otx_result:
                results.append(otx_result)

        return self._merge_results(ioc, results)

    def lookup_batch(self, iocs: list[IOC]) -> list[ThreatIntelResult]:
        """Look up multiple IOCs.

        Args:
            iocs: List of IOCs to investigate.

        Returns:
            List of threat intelligence results.
        """
        return [self.lookup(ioc) for ioc in iocs]

    def _lookup_virustotal(self, ioc: IOC) -> Optional[ThreatIntelResult]:
        """Query VirusTotal for IOC reputation."""
        endpoint_map = {
            IOCType.IPV4: f"/ip_addresses/{ioc.value}",
            IOCType.DOMAIN: f"/domains/{ioc.value}",
            IOCType.URL: f"/urls",
            IOCType.MD5: f"/files/{ioc.value}",
            IOCType.SHA1: f"/files/{ioc.value}",
            IOCType.SHA256: f"/files/{ioc.value}",
        }

        endpoint = endpoint_map.get(ioc.ioc_type)
        if not endpoint:
            return None

        try:
            headers = {"x-apikey": self.config.virustotal_api_key}
            resp = self._session.get(
                f"{self.VT_BASE_URL}{endpoint}",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 1

            risk_score = malicious / max(total, 1)
            return ThreatIntelResult(
                ioc=ioc,
                is_malicious=risk_score > 0.3,
                risk_score=risk_score,
                sources=["virustotal"],
                details={"vt_stats": stats, "vt_reputation": attributes.get("reputation", 0)},
                tags=attributes.get("tags", []),
            )
        except requests.RequestException as e:
            logger.warning("VirusTotal lookup failed for %s: %s", ioc.value, e)
            return None

    def _lookup_abuseipdb(self, ioc: IOC) -> Optional[ThreatIntelResult]:
        """Query AbuseIPDB for IP reputation."""
        try:
            headers = {"Key": self.config.abuseipdb_api_key, "Accept": "application/json"}
            resp = self._session.get(
                f"{self.ABUSEIPDB_BASE_URL}/check",
                headers=headers,
                params={"ipAddress": ioc.value, "maxAgeInDays": "90"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0) / 100.0
            return ThreatIntelResult(
                ioc=ioc,
                is_malicious=score > 0.5,
                risk_score=score,
                sources=["abuseipdb"],
                details={
                    "abuse_score": data.get("abuseConfidenceScore"),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                },
            )
        except requests.RequestException as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ioc.value, e)
            return None

    def _lookup_otx(self, ioc: IOC) -> Optional[ThreatIntelResult]:
        """Query AlienVault OTX for IOC reputation."""
        section_map = {
            IOCType.IPV4: f"/indicators/IPv4/{ioc.value}/general",
            IOCType.DOMAIN: f"/indicators/domain/{ioc.value}/general",
            IOCType.MD5: f"/indicators/file/{ioc.value}/general",
            IOCType.SHA1: f"/indicators/file/{ioc.value}/general",
            IOCType.SHA256: f"/indicators/file/{ioc.value}/general",
        }

        endpoint = section_map.get(ioc.ioc_type)
        if not endpoint:
            return None

        try:
            headers = {"X-OTX-API-KEY": self.config.otx_api_key}
            resp = self._session.get(
                f"{self.OTX_BASE_URL}{endpoint}",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            risk_score = min(pulse_count / 10.0, 1.0)

            return ThreatIntelResult(
                ioc=ioc,
                is_malicious=pulse_count > 2,
                risk_score=risk_score,
                sources=["otx"],
                details={
                    "pulse_count": pulse_count,
                    "reputation": data.get("reputation", 0),
                },
                tags=[p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
            )
        except requests.RequestException as e:
            logger.warning("OTX lookup failed for %s: %s", ioc.value, e)
            return None

    def _merge_results(self, ioc: IOC, results: list[ThreatIntelResult]) -> ThreatIntelResult:
        """Merge results from multiple feeds into a single result."""
        if not results:
            return ThreatIntelResult(
                ioc=ioc, is_malicious=False, risk_score=0.0,
                sources=[], details={"note": "No threat intel feeds configured or available"},
            )

        max_score = max(r.risk_score for r in results)
        all_sources = []
        all_details: dict[str, Any] = {}
        all_tags: list[str] = []
        for r in results:
            all_sources.extend(r.sources)
            all_details.update(r.details)
            all_tags.extend(r.tags)

        return ThreatIntelResult(
            ioc=ioc,
            is_malicious=any(r.is_malicious for r in results),
            risk_score=max_score,
            sources=all_sources,
            details=all_details,
            tags=list(set(all_tags)),
        )
