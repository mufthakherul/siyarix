# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook Notification Dispatcher for Siyarix."""

import logging
import os
import httpx
from typing import Any

from siyarix.events import get_event_bus, EventType

logger = logging.getLogger(__name__)

class NotificationDispatcher:
    """Dispatches notifications to Slack/Discord webhooks."""

    def __init__(self) -> None:
        self.webhook_url = os.environ.get("SIYARIX_WEBHOOK_URL")
        if self.webhook_url:
            self.bus = get_event_bus()
            self.bus.on(EventType.CUSTOM, self._on_finding)

    async def _on_finding(self, event: Any) -> None:
        finding = event.data.get("finding", {})
        severity = finding.get("severity", "info").upper()

        # Only notify on HIGH or CRITICAL findings to avoid spam
        if severity not in ("HIGH", "CRITICAL"):
            return

        message = f"🚨 **{severity} Finding Discovered** 🚨\n\n"
        message += f"**Type:** {finding.get('type')}\n"
        message += f"**Target:** {finding.get('target')}\n"
        message += f"**Description:** {finding.get('description')}\n"

        await self.dispatch(message)

    async def dispatch(self, message: str) -> None:
        if not self.webhook_url:
            return

        payload: dict[str, Any] = {"content": message}

        # Format for Slack if it's a Slack webhook
        if "slack.com" in self.webhook_url:
            payload = {"text": message}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.webhook_url, json=payload)
                response.raise_for_status()
                logger.info("Notification dispatched successfully.")
        except Exception as e:
            logger.error("Failed to dispatch notification: %s", e)
