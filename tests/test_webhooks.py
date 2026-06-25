"""Tests for src/siyarix/webhooks.py — 100% coverage."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import urllib.error
import urllib.request

from siyarix.events import Event, EventType, get_event_bus, reset_event_bus
from siyarix.webhooks import WebhookDispatcher, webhook_dispatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_bus() -> None:
    reset_event_bus()


@pytest.fixture
def dispatcher_with_url() -> WebhookDispatcher:
    with patch.dict(
        os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com/alerts"}, clear=True
    ):
        reset_event_bus()
        return WebhookDispatcher()


@pytest.fixture
def dispatcher_without_url() -> WebhookDispatcher:
    with patch.dict(os.environ, {}, clear=True):
        reset_event_bus()
        return WebhookDispatcher()


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_reads_webhook_url_from_env(self) -> None:
        with patch.dict(
            os.environ, {"SIYARIX_WEBHOOK_URL": "https://discord.example.com"}, clear=True
        ):
            reset_event_bus()
            d = WebhookDispatcher()
            assert d.webhook_url == "https://discord.example.com"

    def test_no_webhook_url(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            reset_event_bus()
            d = WebhookDispatcher()
            assert d.webhook_url is None

    def test_subscribes_to_event_bus(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            reset_event_bus()
            bus = get_event_bus()
            with patch.object(bus, "on") as mock_on:
                d = WebhookDispatcher()
                mock_on.assert_called_once_with(None, d._on_event)


# ---------------------------------------------------------------------------
# _on_event
# ---------------------------------------------------------------------------


class TestOnEvent:
    @pytest.mark.asyncio
    async def test_custom_event_high_severity_dispatches(
        self, dispatcher_with_url: WebhookDispatcher
    ) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={
                    "sub_type": "finding",
                    "finding": {"severity": "high", "target": "example.com"},
                },
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_awaited_once_with({"severity": "high", "target": "example.com"})

    @pytest.mark.asyncio
    async def test_custom_event_critical_severity_dispatches(
        self, dispatcher_with_url: WebhookDispatcher
    ) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={
                    "sub_type": "finding",
                    "finding": {"severity": "critical", "target": "example.com"},
                },
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_custom_event_low_severity_ignored(
        self, dispatcher_with_url: WebhookDispatcher
    ) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={
                    "sub_type": "finding",
                    "finding": {"severity": "low"},
                },
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_custom_event_ignored(self, dispatcher_with_url: WebhookDispatcher) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.HEARTBEAT,
                data={"sub_type": "finding", "finding": {"severity": "critical"}},
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_sub_type_ignored(self, dispatcher_with_url: WebhookDispatcher) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={"sub_type": "other", "finding": {"severity": "critical"}},
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_severity_defaults_to_info(
        self, dispatcher_with_url: WebhookDispatcher
    ) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={"sub_type": "finding", "finding": {}},
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_finding_key(self, dispatcher_with_url: WebhookDispatcher) -> None:
        with patch.object(dispatcher_with_url, "dispatch_alert", AsyncMock()) as mock_dispatch:
            event = Event(
                type=EventType.CUSTOM,
                data={"sub_type": "finding"},
            )
            await dispatcher_with_url._on_event(event)
            mock_dispatch.assert_not_called()


# ---------------------------------------------------------------------------
# dispatch_alert
# ---------------------------------------------------------------------------


class TestDispatchAlert:
    @pytest.mark.asyncio
    async def test_dispatches_with_url(self) -> None:
        with patch.dict(
            os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com"}, clear=True
        ):
            reset_event_bus()
            d = WebhookDispatcher()
            fake_response = MagicMock()
            fake_response.__enter__.return_value = fake_response

            with patch.object(
                urllib.request, "urlopen", return_value=fake_response
            ) as mock_urlopen:
                finding = {"id": "vuln-1", "target": "example.com", "type": "sql injection"}
                await d.dispatch_alert(finding)

            mock_urlopen.assert_called_once()
            req = mock_urlopen.call_args[0][0]
            assert req.get_method() == "POST"
            sent = json.loads(req.data)
            assert "CRITICAL VULNERABILITY" in sent["text"]

    @pytest.mark.asyncio
    async def test_no_url_configured(self, dispatcher_without_url: WebhookDispatcher) -> None:
        with patch.object(urllib.request, "urlopen") as mock_urlopen:
            await dispatcher_without_url.dispatch_alert({"target": "x"})
            mock_urlopen.assert_not_called()

    @pytest.mark.asyncio
    async def test_urlerror_on_dispatch(self) -> None:
        with patch.dict(
            os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com"}, clear=True
        ):
            reset_event_bus()
            d = WebhookDispatcher()
            with patch.object(
                urllib.request, "urlopen", side_effect=urllib.error.URLError("connection failed")
            ):
                await d.dispatch_alert({"id": "vuln-1", "target": "x", "type": "open port"})

    @pytest.mark.asyncio
    async def test_finding_with_title_fallback(self) -> None:
        with patch.dict(
            os.environ, {"SIYARIX_WEBHOOK_URL": "https://hooks.example.com"}, clear=True
        ):
            reset_event_bus()
            d = WebhookDispatcher()
            fake_response = MagicMock()
            fake_response.__enter__.return_value = fake_response
            with patch.object(urllib.request, "urlopen", return_value=fake_response):
                await d.dispatch_alert(
                    {"id": "vuln-1", "title": "XSS Vulnerability", "target": "x"}
                )


# ---------------------------------------------------------------------------
# generate_remediation
# ---------------------------------------------------------------------------


class TestGenerateRemediation:
    def test_sql_injection(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "SQL Injection"})
        assert "parameterized queries" in result

    def test_xss_type(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "XSS"})
        assert "CSP" in result

    def test_cross_site_scripting_type(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "Cross-Site Scripting"})
        assert "CSP" in result

    def test_open_port(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "open port"})
        assert "ufw" in result

    def test_ssh(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "SSH"})
        assert "ufw" in result

    def test_outdated(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "outdated package"})
        assert "apt-get" in result

    def test_cve_in_title(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"title": "CVE-2024-1234"})
        assert "apt-get" in result

    def test_generic(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"type": "unknown_type"})
        assert "manual review" in result

    def test_finding_with_title_fallback(self, dispatcher_with_url: WebhookDispatcher) -> None:
        result = dispatcher_with_url.generate_remediation({"title": "custom issue"})
        assert "manual review" in result


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------


class TestGlobalSingleton:
    def test_webhook_dispatcher_is_singleton(self) -> None:
        assert isinstance(webhook_dispatcher, WebhookDispatcher)
