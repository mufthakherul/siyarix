"""Phalanx Notification System — In-terminal alerts, severity indicators, webhook forwarding.

Provides:
  • NotificationCenter — central hub for all notifications
  • Rich terminal rendering with severity-coloured panels
  • Optional async webhook forwarding (Slack, Teams, Discord)
  • Notification history with search/filter

Usage::

    from phalanx.notifications import notification_center
    notification_center.finding("nmap", "high", "Open port 22 SSH", target="10.0.0.1")
    notification_center.success("Scan complete", "All 5 tools finished")
    notification_center.critical("Blocked", "Dangerous command detected")
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.panel import Panel

__all__ = [
    "NotificationLevel",
    "Notification",
    "NotificationCenter",
    "notification_center",
]

logger = logging.getLogger(__name__)


class NotificationLevel(StrEnum):
    """Severity/type of a notification."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    FINDING = "finding"
    SUCCESS = "success"
    ERROR = "error"
    PROGRESS = "progress"


@dataclass
class Notification:
    """A single notification event."""

    level: NotificationLevel
    title: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "phalanx"
    metadata: dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "title": self.title,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "metadata": self.metadata,
            "acknowledged": self.acknowledged,
        }


# Rendering config per level
_LEVEL_CONFIG: dict[str, dict[str, str]] = {
    "debug": {"icon": "🔧", "border": "dim", "style": "dim"},
    "info": {"icon": "ℹ️ ", "border": "cyan", "style": "cyan"},
    "warning": {"icon": "⚠️ ", "border": "yellow", "style": "yellow"},
    "critical": {"icon": "🔴", "border": "bold bright_red", "style": "bold bright_red"},
    "error": {"icon": "❌", "border": "red", "style": "red"},
    "finding": {"icon": "🔍", "border": "magenta", "style": "bright_magenta"},
    "success": {"icon": "✅", "border": "green", "style": "bold green"},
    "progress": {"icon": "⏳", "border": "blue", "style": "blue"},
}


class NotificationCenter:
    """Central notification hub — renders, stores, and forwards notifications."""

    def __init__(
        self,
        console: Console | None = None,
        max_history: int = 500,
        quiet: bool = False,
    ) -> None:
        self._console = console or Console()
        self._history: deque[Notification] = deque(maxlen=max_history)
        self._quiet = quiet
        self._webhooks: list[str] = []
        self._muted_levels: set[NotificationLevel] = set()

    # ── Public API ─────────────────────────────────────────────────────

    def notify(
        self,
        level: NotificationLevel,
        title: str,
        message: str = "",
        source: str = "phalanx",
        **meta: Any,
    ) -> Notification:
        """Create, render, store, and optionally forward a notification."""
        n = Notification(
            level=level,
            title=title,
            message=message,
            source=source,
            metadata=meta,
        )
        self._history.append(n)

        if not self._quiet and level not in self._muted_levels:
            self._render(n)

        # Async webhook forwarding (fire-and-forget)
        if self._webhooks and level in (
            NotificationLevel.CRITICAL,
            NotificationLevel.FINDING,
            NotificationLevel.ERROR,
        ):
            for url in self._webhooks:
                try:
                    asyncio.get_event_loop().create_task(self._forward_webhook(n, url))
                except RuntimeError:
                    pass  # No event loop — skip forwarding

        return n

    def finding(
        self,
        tool: str,
        severity: str,
        description: str,
        target: str = "",
    ) -> None:
        """Shorthand for a new security finding notification."""
        self.notify(
            NotificationLevel.FINDING,
            title=f"[{severity.upper()}] {tool}",
            message=description,
            source=tool,
            severity=severity,
            target=target,
        )

    def success(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.SUCCESS, title, message)

    def warning(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.WARNING, title, message)

    def critical(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.CRITICAL, title, message)

    def error(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.ERROR, title, message)

    def info(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.INFO, title, message)

    def progress(self, title: str, message: str = "") -> None:
        self.notify(NotificationLevel.PROGRESS, title, message)

    # ── History ────────────────────────────────────────────────────────

    def list_recent(self, limit: int = 10) -> list[Notification]:
        """Return the most recent notifications."""
        items = list(self._history)
        return items[-limit:]

    def search(self, query: str, limit: int = 20) -> list[Notification]:
        """Search notification history by keyword."""
        query_lower = query.lower()
        results = [
            n for n in self._history
            if query_lower in n.title.lower() or query_lower in n.message.lower()
        ]
        return results[-limit:]

    def unacknowledged(self) -> list[Notification]:
        """Return all unacknowledged notifications."""
        return [n for n in self._history if not n.acknowledged]

    def acknowledge_all(self) -> int:
        """Mark all notifications as acknowledged. Return count."""
        count = 0
        for n in self._history:
            if not n.acknowledged:
                n.acknowledged = True
                count += 1
        return count

    def clear(self) -> None:
        """Clear notification history."""
        self._history.clear()

    # ── Configuration ──────────────────────────────────────────────────

    def add_webhook(self, url: str) -> None:
        """Register a webhook URL for forwarding critical notifications."""
        if url not in self._webhooks:
            self._webhooks.append(url)

    def mute(self, level: NotificationLevel) -> None:
        """Mute a notification level."""
        self._muted_levels.add(level)

    def unmute(self, level: NotificationLevel) -> None:
        """Unmute a notification level."""
        self._muted_levels.discard(level)

    # ── Rendering ──────────────────────────────────────────────────────

    def _render(self, n: Notification) -> None:
        """Render a notification to the Rich console."""
        cfg = _LEVEL_CONFIG.get(n.level.value, _LEVEL_CONFIG["info"])
        icon = cfg["icon"]
        border = cfg["border"]
        style = cfg["style"]

        # Build body
        body_parts: list[str] = []
        if n.message:
            body_parts.append(n.message)
        if n.metadata.get("target"):
            body_parts.append(f"[dim]Target: {n.metadata['target']}[/dim]")
        if n.metadata.get("severity"):
            body_parts.append(f"[dim]Severity: {n.metadata['severity']}[/dim]")
        body = "\n".join(body_parts) if body_parts else ""

        ts = n.timestamp.strftime("%H:%M:%S")

        self._console.print(
            Panel(
                body or "[dim]—[/dim]",
                title=f"[{style}]{icon} {n.title}[/{style}]",
                subtitle=f"[dim]{ts} · {n.source}[/dim]",
                border_style=border,
                padding=(0, 1),
            )
        )

    # ── Webhook Forwarding ─────────────────────────────────────────────

    async def _forward_webhook(self, n: Notification, webhook_url: str) -> None:
        """Forward a notification to a webhook endpoint (Slack/Teams/Discord)."""
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not available — skipping webhook forwarding")
            return

        payload = {
            "text": f"*{n.title}*\n{n.message}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{_LEVEL_CONFIG.get(n.level.value, {}).get('icon', '')} "
                            f"Phalanx — {n.level.value.upper()}*\n"
                            f"*{n.title}*\n{n.message}"
                        ),
                    },
                }
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code not in (200, 204):
                    logger.warning("Webhook POST failed (%d): %s", resp.status_code, resp.text[:200])
        except Exception as exc:
            logger.warning("Webhook forwarding failed: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singleton
# ═══════════════════════════════════════════════════════════════════════════

notification_center = NotificationCenter()
