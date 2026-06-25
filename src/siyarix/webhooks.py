# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook and Auto-Remediation dispatching for Siyarix.

This module pushes real-time alerts to SIEMs or team chats (Slack/Discord)
and generates auto-remediation scripts for Blue Teams.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
import os
from typing import Any

from siyarix.events import get_event_bus, Event, EventType

logger = logging.getLogger(__name__)


class WebhookDispatcher:
    """Dispatches alerts and remediation scripts to external services."""

    def __init__(self) -> None:
        self.webhook_url = os.getenv("SIYARIX_WEBHOOK_URL")
        self.bus = get_event_bus()
        self.bus.on(None, self._on_event)

    async def _on_event(self, event: Event) -> None:
        if event.type != EventType.CUSTOM:
            return
        if event.data.get("sub_type") == "finding":
            finding = event.data.get("finding", {})
            severity = finding.get("severity", "info").lower()
            if severity in ("high", "critical"):
                await self._dispatch_alert(finding)

    async def _dispatch_alert(self, finding: dict[str, Any]) -> None:
        """Async alert dispatch."""
        await self.dispatch_alert(finding)

    async def dispatch_alert(self, finding: dict[str, Any]) -> None:
        """Send an alert to the configured webhook."""
        if not self.webhook_url:
            logger.debug("No SIYARIX_WEBHOOK_URL configured. Skipping alert.")
            return

        remediation = self.generate_remediation(finding)

        payload = {
            "text": f"🚨 **CRITICAL VULNERABILITY DETECTED** 🚨\n"
            f"**Target:** {finding.get('target', 'Unknown')}\n"
            f"**Type:** {finding.get('type', finding.get('title', 'Unknown'))}\n"
            f"**Auto-Remediation Script:**\n```bash\n{remediation}\n```"
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
            logger.info("Webhook alert dispatched for %s", finding.get("id", "vuln"))
        except urllib.error.URLError as e:
            logger.error("Failed to dispatch webhook: %s", e)

    def generate_remediation(self, finding: dict[str, Any]) -> str:
        """Generate a basic auto-remediation script based on the finding type."""
        f_type = str(finding.get("type", finding.get("title", ""))).lower()

        if "sql injection" in f_type:
            return "# Remediation: Use parameterized queries (Prepared Statements) in your application code."
        elif "xss" in f_type or "cross-site scripting" in f_type:
            return "# Remediation: Implement strict Content Security Policy (CSP) and sanitize HTML inputs."
        elif "open port" in f_type or "ssh" in f_type:
            return "sudo ufw deny 22/tcp\n# Or configure iptables to drop unauthorized SSH traffic."
        elif "outdated" in f_type or "cve-" in f_type:
            return (
                "sudo apt-get update && sudo apt-get upgrade -y\n# Ensure all packages are patched."
            )
        else:
            return "# Remediation script generation requires manual review for this vulnerability."


# Global singleton
webhook_dispatcher = WebhookDispatcher()
