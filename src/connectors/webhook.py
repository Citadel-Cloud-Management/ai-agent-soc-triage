"""Generic webhook receiver for ingesting alerts from any source."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.analyzers.correlation import SecurityAlert

logger = logging.getLogger(__name__)


class WebhookReceiver:
    """HTTP webhook receiver for ingesting security alerts from arbitrary sources.

    Provides a WSGI-compatible application that can be mounted in any
    web framework (Flask, FastAPI, etc.) to receive alert webhooks.
    """

    def __init__(
        self,
        secret: Optional[str] = None,
        alert_transformer: Optional[Callable[[dict[str, Any]], SecurityAlert]] = None,
    ) -> None:
        self.secret = secret
        self._transformer = alert_transformer or self._default_transformer
        self._handlers: list[Callable[[SecurityAlert], None]] = []
        self._received_alerts: list[SecurityAlert] = []

    def on_alert(self, handler: Callable[[SecurityAlert], None]) -> None:
        """Register a callback for incoming alerts.

        Args:
            handler: Function to call when an alert is received.
        """
        self._handlers.append(handler)

    def process_webhook(
        self,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, dict[str, str]]:
        """Process an incoming webhook request.

        Args:
            body: Raw request body bytes.
            headers: Request headers.

        Returns:
            Tuple of (status_code, response_body_dict).
        """
        if self.secret:
            signature = headers.get("X-Signature-256", headers.get("x-signature-256", ""))
            if not self._verify_signature(body, signature):
                logger.warning("Webhook signature verification failed")
                return 401, {"error": "Invalid signature"}

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            logger.error("Failed to parse webhook JSON payload")
            return 400, {"error": "Invalid JSON"}

        alert = self._transformer(payload)
        self._received_alerts.append(alert)

        for handler in self._handlers:
            try:
                handler(alert)
            except Exception:
                logger.exception("Webhook handler failed for alert %s", alert.alert_id)

        return 200, {"status": "accepted", "alert_id": alert.alert_id}

    def get_received_alerts(self) -> list[SecurityAlert]:
        """Return all alerts received so far."""
        return list(self._received_alerts)

    def create_flask_blueprint(self, url_prefix: str = "/webhook"):
        """Create a Flask blueprint for the webhook receiver.

        Args:
            url_prefix: URL prefix for the webhook endpoint.

        Returns:
            Flask Blueprint object.
        """
        from flask import Blueprint, request, jsonify

        bp = Blueprint("webhook_receiver", __name__, url_prefix=url_prefix)

        @bp.route("/alert", methods=["POST"])
        def receive_alert():
            status, response = self.process_webhook(
                body=request.get_data(),
                headers=dict(request.headers),
            )
            return jsonify(response), status

        return bp

    def _verify_signature(self, body: bytes, signature: str) -> bool:
        """Verify HMAC-SHA256 signature of the webhook payload."""
        if not self.secret:
            return True
        expected = hmac.new(
            self.secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        provided = signature.replace("sha256=", "")
        return hmac.compare_digest(expected, provided)

    def _default_transformer(self, payload: dict[str, Any]) -> SecurityAlert:
        """Default transformation from webhook payload to SecurityAlert."""
        timestamp_str = payload.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        return SecurityAlert(
            alert_id=payload.get("id", payload.get("alert_id", "")),
            source=payload.get("source", "webhook"),
            title=payload.get("title", payload.get("name", "Webhook Alert")),
            description=payload.get("description", payload.get("message", "")),
            timestamp=timestamp,
            severity=payload.get("severity", "medium"),
            raw_data=payload,
            metadata=payload.get("metadata", {}),
        )
