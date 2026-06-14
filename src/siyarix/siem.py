# SPDX-License-Identifier: AGPL-3.0-or-later
"""SIEM Export Adapters for Siyarix."""

from __future__ import annotations

import json
import logging

import httpx

from siyarix.audit_log import AuditEvent

logger = logging.getLogger(__name__)

class SIEMAdapter:
    """Base class for SIEM adapters."""
    def __init__(self, url: str) -> None:
        self.url = url
        self._client = httpx.AsyncClient()

    async def ship(self, event: AuditEvent) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        await self._client.aclose()


class ElasticAdapter(SIEMAdapter):
    """Adapter for Elasticsearch."""
    def __init__(self, url: str, api_key: str) -> None:
        super().__init__(url)
        self.api_key = api_key

    async def ship(self, event: AuditEvent) -> None:
        try:
            payload = event.__dict__.copy()
            response = await self._client.post(
                f"{self.url}/_doc",
                json=payload,
                headers={"Authorization": f"ApiKey {self.api_key}"}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to Elastic: %s", e)


class SplunkHECAdapter(SIEMAdapter):
    """Adapter for Splunk HTTP Event Collector."""
    def __init__(self, url: str, hec_token: str) -> None:
        super().__init__(url)
        self.hec_token = hec_token

    async def ship(self, event: AuditEvent) -> None:
        try:
            payload = event.__dict__.copy()
            response = await self._client.post(
                f"{self.url}/services/collector/event",
                json={"event": payload, "sourcetype": "siyarix"},
                headers={"Authorization": f"Splunk {self.hec_token}"}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to Splunk: %s", e)


class QRadarAdapter(SIEMAdapter):
    """Adapter for IBM QRadar (Ariel REST API)."""
    def __init__(self, url: str, auth_token: str) -> None:
        super().__init__(url)
        self.auth_token = auth_token

    async def ship(self, event: AuditEvent) -> None:
        try:
            # Note: A real QRadar implementation usually sends syslog.
            # Here we demonstrate a REST approach.
            payload = event.__dict__.copy()
            response = await self._client.post(
                f"{self.url}/api/ariel/searches",
                json={"query_expression": json.dumps(payload)},
                headers={"SEC": self.auth_token}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to QRadar: %s", e)
