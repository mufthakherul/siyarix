"""Tests for the Telemetry SIEM connectors."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from siyarix.telemetry.siem import (
    SIEMConnector,
    SplunkHECConnector,
    ElasticSIEMConnector,
    TelemetryForwarder,
)


class TestSIEMConnector:
    """Test SIEMConnector base class."""

    def test_base_forward_raises(self):
        conn = SIEMConnector()
        with pytest.raises(NotImplementedError):
            import asyncio

            asyncio.run(conn.forward_event({}))


class TestSplunkHECConnector:
    """Test SplunkHECConnector."""

    def test_init_requires_httpx(self):
        with patch("siyarix.telemetry.siem.HAS_HTTPX", False):
            with pytest.raises(ImportError, match="httpx is required"):
                SplunkHECConnector("http://localhost:8088", "test-token")

    @patch("siyarix.telemetry.siem.HAS_HTTPX", True)
    @patch("siyarix.telemetry.siem.httpx.AsyncClient")
    def test_forward_event_success(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
        mock_client_class.return_value = mock_client

        conn = SplunkHECConnector("http://localhost:8088", "test-token")
        import asyncio

        result = asyncio.run(conn.forward_event({"event": "test"}))
        assert result is True

    @patch("siyarix.telemetry.siem.HAS_HTTPX", True)
    @patch("siyarix.telemetry.siem.httpx.AsyncClient")
    def test_forward_event_failure(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=500))
        mock_client_class.return_value = mock_client

        conn = SplunkHECConnector("http://localhost:8088", "test-token")
        import asyncio

        result = asyncio.run(conn.forward_event({"event": "test"}))
        assert result is False


class TestElasticSIEMConnector:
    """Test ElasticSIEMConnector."""

    def test_init_requires_httpx(self):
        with patch("siyarix.telemetry.siem.HAS_HTTPX", False):
            with pytest.raises(ImportError, match="httpx is required"):
                ElasticSIEMConnector("http://localhost:9200", "test-key")

    @patch("siyarix.telemetry.siem.HAS_HTTPX", True)
    @patch("siyarix.telemetry.siem.httpx.AsyncClient")
    def test_forward_event_success(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=201))
        mock_client_class.return_value = mock_client

        conn = ElasticSIEMConnector("http://localhost:9200", "test-key")
        import asyncio

        result = asyncio.run(conn.forward_event({"event": "test"}))
        assert result is True

    def test_index_format(self):
        with patch("siyarix.telemetry.siem.HAS_HTTPX", True):
            conn = ElasticSIEMConnector("http://localhost:9200", "test-key", index="custom-index")
            assert "custom-index/_doc" in conn.endpoint


class TestTelemetryForwarder:
    """Test TelemetryForwarder."""

    def test_init_no_connectors(self):
        with patch.dict("os.environ", {}, clear=True):
            fwd = TelemetryForwarder()
            assert len(fwd.connectors) == 0

    def test_init_with_splunk_env(self):
        env = {
            "SIYARIX_SPLUNK_URL": "http://splunk:8088",
            "SIYARIX_SPLUNK_TOKEN": "splunk-token",
        }
        with patch.dict("os.environ", env, clear=True):
            with patch("siyarix.telemetry.siem.HAS_HTTPX", True):
                fwd = TelemetryForwarder()
                assert len(fwd.connectors) == 1
                assert isinstance(fwd.connectors[0], SplunkHECConnector)

    def test_init_with_elastic_env(self):
        env = {
            "SIYARIX_ELASTIC_URL": "http://elastic:9200",
            "SIYARIX_ELASTIC_KEY": "elastic-key",
        }
        with patch.dict("os.environ", env, clear=True):
            with patch("siyarix.telemetry.siem.HAS_HTTPX", True):
                fwd = TelemetryForwarder()
                assert len(fwd.connectors) == 1
                assert isinstance(fwd.connectors[0], ElasticSIEMConnector)

    def test_dispatch_no_connectors(self):
        fwd = TelemetryForwarder()
        fwd.dispatch({"test": "event"})  # Should not raise

    def test_dispatch_with_connectors(self):
        with patch("siyarix.telemetry.siem.HAS_HTTPX", True):
            mock_conn = MagicMock(spec=SIEMConnector)
            mock_conn.forward_event = AsyncMock(return_value=True)
            fwd = TelemetryForwarder()
            fwd.connectors = [mock_conn]
            fwd.dispatch({"test": "event"})
            mock_conn.forward_event.assert_called_once()

    def test_close_all(self):
        with patch("siyarix.telemetry.siem.HAS_HTTPX", True):
            mock_conn = MagicMock(spec=SplunkHECConnector)
            mock_conn.close = AsyncMock()
            fwd = TelemetryForwarder()
            fwd.connectors = [mock_conn]
            fwd.close_all()
            mock_conn.close.assert_called_once()
