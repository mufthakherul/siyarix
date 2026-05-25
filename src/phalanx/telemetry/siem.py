"""Enterprise SIEM & Telemetry Connectors.

Provides async connectors for forwarding audit events to:
  • Splunk (HTTP Event Collector)
  • ElasticSearch
  • Generic Webhooks (e.g., Slack, Teams)
"""

import asyncio
import logging
import os
from typing import Any

httpx: Any = None

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


class SIEMConnector:
    """Base class for SIEM connectors."""

    async def forward_event(self, event: dict[str, Any]) -> bool:
        """Forward an event to the SIEM. Returns True if successful."""
        raise NotImplementedError

    async def close(self) -> None:
        """Close the connector. Subclasses may override."""
        pass


class SplunkHECConnector(SIEMConnector):
    """Splunk HTTP Event Collector connector."""

    def __init__(self, endpoint: str, token: str) -> None:
        if not HAS_HTTPX:
            raise ImportError(
                "httpx is required for SplunkHECConnector. Install with: pip install siyarix[siem]"
            )
        self.endpoint = endpoint
        self.headers = {"Authorization": f"Splunk {token}"}
        # Use an async client pool for efficiency
        self.client = httpx.AsyncClient(headers=self.headers, verify=False)  # nosec B501

    async def forward_event(self, event: dict[str, Any]) -> bool:
        payload = {
            "time": event.get("timestamp"),
            "host": event.get("source_ip", "localhost"),
            "source": "siyarix",
            "sourcetype": "_json",
            "event": event,
        }
        try:
            resp = await self.client.post(self.endpoint, json=payload, timeout=5.0)
            return resp.status_code in (200, 201)
        except Exception as exc:
            logger.debug(f"Splunk HEC forwarding failed: {exc}")
            return False

    async def close(self) -> None:
        await self.client.aclose()


class ElasticSIEMConnector(SIEMConnector):
    """ElasticSearch connector."""

    def __init__(self, endpoint: str, api_key: str, index: str = "siyarix-audit") -> None:
        if not HAS_HTTPX:
            raise ImportError(
                "httpx is required for ElasticSIEMConnector. Install with: pip install siyarix[siem]"
            )
        self.endpoint = f"{endpoint.rstrip('/')}/{index}/_doc"
        self.headers = {"Authorization": f"ApiKey {api_key}"}
        self.client = httpx.AsyncClient(headers=self.headers)

    async def forward_event(self, event: dict[str, Any]) -> bool:
        try:
            resp = await self.client.post(self.endpoint, json=event, timeout=5.0)
            return resp.status_code in (200, 201)
        except Exception as exc:
            logger.debug(f"Elastic forwarding failed: {exc}")
            return False

    async def close(self) -> None:
        await self.client.aclose()


class TelemetryForwarder:
    """Manages multiple SIEM connectors and forwards events asynchronously without blocking."""

    def __init__(self) -> None:
        self.connectors: list[SIEMConnector] = []
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Initialize connectors based on environment variables."""
        splunk_url = os.getenv("SIYARIX_SPLUNK_URL")
        splunk_token = os.getenv("SIYARIX_SPLUNK_TOKEN")
        if splunk_url and splunk_token:
            self.connectors.append(SplunkHECConnector(splunk_url, splunk_token))

        elastic_url = os.getenv("SIYARIX_ELASTIC_URL")
        elastic_key = os.getenv("SIYARIX_ELASTIC_KEY")
        if elastic_url and elastic_key:
            self.connectors.append(ElasticSIEMConnector(elastic_url, elastic_key))

    def dispatch(self, event: dict[str, Any]) -> None:
        """Dispatch event to all configured connectors. Fire-and-forget."""
        if not self.connectors:
            return

        async def _send_all() -> None:
            tasks = [conn.forward_event(event) for conn in self.connectors]
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            # If there's an active running event loop, create a task
            loop = asyncio.get_running_loop()
            loop.create_task(_send_all())
        except RuntimeError:
            # No running event loop (e.g., sync context), run it synchronously
            asyncio.run(_send_all())

    def close_all(self) -> None:
        """Close all connector clients."""
        for conn in self.connectors:
            if hasattr(conn, "close"):
                try:
                    asyncio.run(conn.close())
                except RuntimeError:
                    pass


siem_forwarder = TelemetryForwarder()
