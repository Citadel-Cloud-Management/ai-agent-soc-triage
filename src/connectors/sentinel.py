"""Microsoft Sentinel connector for retrieving security incidents and alerts."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from src.analyzers.correlation import SecurityAlert
from src.config import SIEMConfig

logger = logging.getLogger(__name__)


class SentinelConnector:
    """Connect to Microsoft Sentinel via the Azure REST API.

    Uses Azure AD authentication (client credentials flow) to query
    the Sentinel incidents and alerts APIs.

    Reference:
        https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources
    """

    MANAGEMENT_URL = "https://management.azure.com"
    LOGIN_URL = "https://login.microsoftonline.com"

    def __init__(
        self,
        config: SIEMConfig,
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        subscription_id: str = "",
        resource_group: str = "",
        workspace_name: str = "",
    ) -> None:
        self.config = config
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.workspace_id = config.workspace_id or ""
        self._session = requests.Session()
        self._access_token: Optional[str] = None

    def authenticate(self) -> None:
        """Obtain an access token using OAuth2 client credentials flow."""
        token_url = f"{self.LOGIN_URL}/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{self.MANAGEMENT_URL}/.default",
        }
        resp = self._session.post(token_url, data=data, timeout=15)
        resp.raise_for_status()
        self._access_token = resp.json()["access_token"]
        self._session.headers.update({"Authorization": f"Bearer {self._access_token}"})

    def get_incidents(
        self,
        severity_filter: Optional[str] = None,
        status_filter: str = "New",
        top: int = 50,
    ) -> list[SecurityAlert]:
        """Retrieve Sentinel incidents.

        Args:
            severity_filter: Filter by severity (High, Medium, Low, Informational).
            status_filter: Filter by status (New, Active, Closed).
            top: Maximum number of incidents.

        Returns:
            List of SecurityAlert objects.
        """
        if not self._access_token:
            self.authenticate()

        base_path = (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/incidents"
        )

        params: dict[str, Any] = {
            "api-version": "2023-11-01",
            "$top": top,
            "$orderby": "properties/createdTimeUtc desc",
        }

        filters = []
        if severity_filter:
            filters.append(f"properties/severity eq '{severity_filter}'")
        if status_filter:
            filters.append(f"properties/status eq '{status_filter}'")
        if filters:
            params["$filter"] = " and ".join(filters)

        url = f"{self.MANAGEMENT_URL}{base_path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()

        incidents = resp.json().get("value", [])
        return [self._incident_to_alert(inc) for inc in incidents]

    def get_incident_alerts(self, incident_id: str) -> list[dict[str, Any]]:
        """Retrieve alerts associated with a specific incident.

        Args:
            incident_id: The Sentinel incident ID.

        Returns:
            List of raw alert dictionaries.
        """
        if not self._access_token:
            self.authenticate()

        base_path = (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
            f"/incidents/{incident_id}/alerts"
        )

        url = f"{self.MANAGEMENT_URL}{base_path}"
        resp = self._session.post(
            url,
            params={"api-version": "2023-11-01"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("value", [])

    def _incident_to_alert(self, incident: dict[str, Any]) -> SecurityAlert:
        """Convert a Sentinel incident to a SecurityAlert."""
        props = incident.get("properties", {})

        timestamp_str = props.get("createdTimeUtc", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        return SecurityAlert(
            alert_id=incident.get("name", ""),
            source="sentinel",
            title=props.get("title", "Sentinel Incident"),
            description=props.get("description", ""),
            timestamp=timestamp,
            severity=props.get("severity", "Medium").lower(),
            raw_data=incident,
            metadata={
                "incident_number": props.get("incidentNumber"),
                "status": props.get("status"),
                "owner": props.get("owner", {}).get("userPrincipalName", ""),
                "tactics": props.get("additionalData", {}).get("tactics", []),
            },
        )
