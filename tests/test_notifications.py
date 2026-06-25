"""Tests for siyarix.notifications - Webhook Notification Dispatcher."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.events import EventType, reset_event_bus
from siyarix.notifications import NotificationDispatcher


@pytest.fixture(autouse=True)
def reset_singletons():
    reset_event_bus()
    yield
    reset_event_bus()


class TestNotificationDispatcher:
    def test_init_without_webhook(self):
        with patch.dict(os.environ, {}, clear=True):
            nd = NotificationDispatcher()
            assert nd.webhook_url is None

    def test_init_with_webhook(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            assert nd.webhook_url == "https://hooks.example.com/webhook"
            assert nd.bus is not None

    def test_init_registers_custom_handler(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            assert EventType.CUSTOM in nd.bus._handlers
            assert nd._on_finding in nd.bus._handlers[EventType.CUSTOM]

    @pytest.mark.asyncio
    async def test_on_finding_high_severity(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(
                type=EventType.CUSTOM,
                data={
                    "finding": {
                        "severity": "HIGH",
                        "type": "vuln",
                        "target": "10.0.0.1",
                        "description": "Critical exploit detected",
                    }
                },
            )
            await nd._on_finding(event)
            nd.dispatch.assert_awaited_once()
            call_args = nd.dispatch.await_args[0][0]
            assert "HIGH" in call_args
            assert "vuln" in call_args
            assert "10.0.0.1" in call_args
            assert "Critical exploit detected" in call_args

    @pytest.mark.asyncio
    async def test_on_finding_critical_severity(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(
                type=EventType.CUSTOM,
                data={
                    "finding": {
                        "severity": "CRITICAL",
                        "type": "rce",
                        "target": "10.0.0.2",
                        "description": "Remote code execution",
                    }
                },
            )
            await nd._on_finding(event)
            nd.dispatch.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_finding_low_severity_skipped(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(
                type=EventType.CUSTOM,
                data={
                    "finding": {
                        "severity": "LOW",
                        "type": "info",
                        "target": "10.0.0.3",
                        "description": "Low severity finding",
                    }
                },
            )
            await nd._on_finding(event)
            nd.dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_finding_medium_severity_skipped(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(
                type=EventType.CUSTOM,
                data={
                    "finding": {
                        "severity": "MEDIUM",
                        "type": "notice",
                        "target": "10.0.0.4",
                        "description": "Medium severity finding",
                    }
                },
            )
            await nd._on_finding(event)
            nd.dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_finding_missing_finding(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(type=EventType.CUSTOM, data={})
            await nd._on_finding(event)
            nd.dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_finding_missing_severity(self):
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/webhook"}):
            nd = NotificationDispatcher()
            nd.dispatch = AsyncMock()
            from siyarix.events import Event, EventType

            event = Event(
                type=EventType.CUSTOM,
                data={"finding": {"type": "test", "target": "x", "description": "desc"}},
            )
            await nd._on_finding(event)
            nd.dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_no_webhook(self):
        with patch.dict(os.environ, {}, clear=True):
            nd = NotificationDispatcher()
            result = await nd.dispatch("test message")
            assert result is None

    @pytest.mark.asyncio
    async def test_dispatch_slack_webhook(self):
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = MagicMock()
                mock_client.post.return_value.raise_for_status = MagicMock()
                await nd.dispatch("test message")
                mock_client.post.assert_called_once_with(url, json={"text": "test message"})

    @pytest.mark.asyncio
    async def test_dispatch_discord_webhook(self):
        url = "https://discord.com/api/webhooks/xxx/yyy"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = MagicMock()
                mock_client.post.return_value.raise_for_status = MagicMock()
                await nd.dispatch("test message")
                mock_client.post.assert_called_once_with(url, json={"content": "test message"})

    @pytest.mark.asyncio
    async def test_dispatch_generic_webhook(self):
        url = "https://hooks.example.com/webhook"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = MagicMock()
                mock_client.post.return_value.raise_for_status = MagicMock()
                await nd.dispatch("test message")
                mock_client.post.assert_called_once_with(url, json={"content": "test message"})

    @pytest.mark.asyncio
    async def test_dispatch_http_error(self, caplog):
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.side_effect = Exception("HTTP 500")
                await nd.dispatch("test message")
                assert "Failed to dispatch notification" in caplog.text

    @pytest.mark.asyncio
    async def test_dispatch_raise_for_status_error(self, caplog):
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_response = MagicMock()
                mock_response.raise_for_status.side_effect = Exception("status error")
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = mock_response
                await nd.dispatch("test message")
                assert "Failed to dispatch notification" in caplog.text

    @pytest.mark.asyncio
    async def test_on_finding_sends_through_dispatch(self):
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        with patch.dict(os.environ, {"SIYARIX_WEBHOOK_URL": url}):
            nd = NotificationDispatcher()
            with patch("siyarix.notifications.httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = MagicMock()
                mock_client.post.return_value.raise_for_status = MagicMock()
                from siyarix.events import Event

                event = Event(
                    type=EventType.CUSTOM,
                    data={
                        "finding": {
                            "severity": "HIGH",
                            "type": "exploit",
                            "target": "10.0.0.1",
                            "description": "Critical vuln",
                        }
                    },
                )
                await nd._on_finding(event)
                mock_client.post.assert_called_once()

    def test_init_does_not_register_handler_without_url(self):
        with patch.dict(os.environ, {}, clear=True):
            nd = NotificationDispatcher()
            assert not hasattr(nd, "bus")
