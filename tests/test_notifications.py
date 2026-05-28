# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from siyarix.notifications import (
    Notification,
    NotificationCenter,
    NotificationLevel,
    notification_center,
)


@pytest.fixture
def center():
    return NotificationCenter(console=Console(), quiet=True)


class TestNotificationCenter:
    def test_init(self, center):
        assert len(center._history) == 0
        assert center._quiet is True

    def test_notify_basic(self, center):
        n = center.notify(NotificationLevel.INFO, "Test Title", "Test Message", source="test")
        assert n.level == NotificationLevel.INFO
        assert n.title == "Test Title"
        assert n.message == "Test Message"
        assert n.source == "test"
        assert len(center._history) == 1

    def test_notify_with_metadata(self, center):
        n = center.notify(NotificationLevel.FINDING, "Finding", "details", target="10.0.0.1", severity="high")
        assert n.metadata["target"] == "10.0.0.1"
        assert n.metadata["severity"] == "high"

    def test_finding_shorthand(self, center):
        center.finding("nmap", "high", "Open port 22", target="10.0.0.1")
        assert len(center._history) == 1
        n = center._history[0]
        assert n.level == NotificationLevel.FINDING
        assert "[HIGH]" in n.title

    def test_success_shorthand(self, center):
        center.success("Scan complete", "All done")
        assert center._history[0].level == NotificationLevel.SUCCESS

    def test_warning_shorthand(self, center):
        center.warning("Disk full", "Low space")
        assert center._history[0].level == NotificationLevel.WARNING

    def test_critical_shorthand(self, center):
        center.critical("Intrusion detected", "Immediate action")
        assert center._history[0].level == NotificationLevel.CRITICAL

    def test_error_shorthand(self, center):
        center.error("Failed", "Scan error")
        assert center._history[0].level == NotificationLevel.ERROR

    def test_info_shorthand(self, center):
        center.info("Info", "Some info")
        assert center._history[0].level == NotificationLevel.INFO

    def test_progress_shorthand(self, center):
        center.progress("Loading", "50%")
        assert center._history[0].level == NotificationLevel.PROGRESS

    def test_list_recent(self, center):
        for i in range(5):
            center.notify(NotificationLevel.INFO, f"Title {i}")
        recent = center.list_recent(limit=3)
        assert len(recent) == 3
        assert recent[-1].title == "Title 4"

    def test_search(self, center):
        center.notify(NotificationLevel.INFO, "Alpha")
        center.notify(NotificationLevel.WARNING, "Beta")
        center.notify(NotificationLevel.INFO, "Alpha again")
        results = center.search("Alpha")
        assert len(results) == 2

    def test_search_no_results(self, center):
        center.notify(NotificationLevel.INFO, "Hello")
        assert center.search("Nonexistent") == []

    def test_unacknowledged(self, center):
        center.notify(NotificationLevel.INFO, "Unacked")
        n2 = center.notify(NotificationLevel.INFO, "Acked")
        n2.acknowledged = True
        unacked = center.unacknowledged()
        assert len(unacked) == 1
        assert unacked[0].title == "Unacked"

    def test_acknowledge_all(self, center):
        center.notify(NotificationLevel.INFO, "N1")
        center.notify(NotificationLevel.INFO, "N2")
        count = center.acknowledge_all()
        assert count == 2
        assert center.unacknowledged() == []

    def test_clear(self, center):
        center.notify(NotificationLevel.INFO, "Test")
        center.clear()
        assert len(center._history) == 0

    def test_add_webhook(self, center):
        center.add_webhook("https://hooks.slack.com/xyz")
        assert "https://hooks.slack.com/xyz" in center._webhooks

    def test_add_webhook_duplicate(self, center):
        center.add_webhook("https://example.com/hook")
        center.add_webhook("https://example.com/hook")
        assert len(center._webhooks) == 1

    def test_mute_unmute(self, center):
        center.mute(NotificationLevel.INFO)
        assert NotificationLevel.INFO in center._muted_levels
        center.unmute(NotificationLevel.INFO)
        assert NotificationLevel.INFO not in center._muted_levels

    def test_render_with_target_and_severity(self, center):
        center._quiet = False
        n = Notification(
            level=NotificationLevel.FINDING,
            title="Test",
            message="Issue found",
            metadata={"target": "10.0.0.1", "severity": "high"},
        )
        center._render(n)

    def test_render_without_body(self, center):
        center._quiet = False
        n = Notification(level=NotificationLevel.INFO, title="Minimal", message="")
        center._render(n)

    def test_notify_non_quiet_renders(self, center):
        center._quiet = False
        mock_print = MagicMock()
        center._console.print = mock_print
        center.notify(NotificationLevel.INFO, "Visible")
        assert mock_print.called

    def test_notify_muted_level(self, center):
        center._quiet = False
        center.mute(NotificationLevel.INFO)
        mock_print = MagicMock()
        center._console.print = mock_print
        center.notify(NotificationLevel.INFO, "Should not render")
        assert not mock_print.called

    @patch("asyncio.get_event_loop")
    def test_webhook_fire_and_forget(self, mock_loop, center):
        mock_loop.return_value.create_task = MagicMock()
        center.add_webhook("https://hooks.example.com")
        center.notify(NotificationLevel.CRITICAL, "Critical!", "Urgent")
        assert mock_loop.return_value.create_task.called

    @patch("asyncio.get_event_loop", side_effect=RuntimeError("no loop"))
    def test_webhook_no_event_loop(self, mock_loop, center):
        center.add_webhook("https://hooks.example.com")
        center.notify(NotificationLevel.CRITICAL, "Critical!", "Urgent")

    def test_forward_webhook_import_error(self, center):
        n = Notification(level=NotificationLevel.INFO, title="Test", message="Msg")
        with patch.dict("sys.modules", {"httpx": None}):
            asyncio.run(center._forward_webhook(n, "https://example.com"))

    @patch("httpx.AsyncClient")
    def test_forward_webhook_success(self, mock_client, center):
        mock_post = AsyncMock()
        mock_post.status_code = 200
        mock_post.text = "OK"
        mock_instance = MagicMock()
        mock_instance.__aenter__.return_value.post = AsyncMock(return_value=mock_post)
        mock_client.return_value = mock_instance
        n = Notification(level=NotificationLevel.CRITICAL, title="Alert", message="Urgent")
        asyncio.run(center._forward_webhook(n, "https://hooks.example.com"))

    @patch("httpx.AsyncClient")
    def test_forward_webhook_failure(self, mock_client, center):
        mock_post = AsyncMock()
        mock_post.status_code = 500
        mock_post.text = "Server Error"
        mock_instance = MagicMock()
        mock_instance.__aenter__.return_value.post = AsyncMock(return_value=mock_post)
        mock_client.return_value = mock_instance
        n = Notification(level=NotificationLevel.CRITICAL, title="Alert", message="Urgent")
        asyncio.run(center._forward_webhook(n, "https://hooks.example.com"))

    @patch("httpx.AsyncClient")
    def test_forward_webhook_exception(self, mock_client, center):
        mock_instance = MagicMock()
        mock_instance.__aenter__.return_value.post = AsyncMock(side_effect=ConnectionError("network down"))
        mock_client.return_value = mock_instance
        n = Notification(level=NotificationLevel.ERROR, title="Alert", message="Urgent")
        asyncio.run(center._forward_webhook(n, "https://hooks.example.com"))

    def test_notification_to_dict(self):
        from datetime import datetime
        n = Notification(
            level=NotificationLevel.WARNING,
            title="Warning!",
            message="Be careful",
            source="test",
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            metadata={"key": "val"},
            acknowledged=True,
        )
        d = n.to_dict()
        assert d["level"] == "warning"
        assert d["title"] == "Warning!"
        assert d["acknowledged"] is True

    def test_module_singleton(self):
        assert notification_center is not None
        assert isinstance(notification_center, NotificationCenter)

    def test_unknown_level_renders_as_info(self, center):
        center._quiet = False
        n = Notification(level="unknown_level", title="Test", message="")  # type: ignore
        center._render(n)
