# SPDX-License-Identifier: AGPL-3.0-or-later
"""SIEM Export Adapters for Siyarix."""

from __future__ import annotations

import json
import logging
import socket

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
    """Adapter for Elasticsearch using Elastic Common Schema (ECS)."""
    def __init__(self, url: str, api_key: str) -> None:
        super().__init__(url)
        self.api_key = api_key

    async def ship(self, event: AuditEvent) -> None:
        try:
            # Format payload using Elastic Common Schema (ECS) v8.0
            ecs_payload = {
                "@timestamp": event.timestamp.isoformat(),
                "ecs": {"version": "8.0.0"},
                "event": {
                    "id": event.event_id,
                    "kind": "event",
                    "category": ["authentication"] if "auth" in event.event_type else ["intrusion_detection", "security"],
                    "type": ["info"] if event.severity == "info" else ["alert"],
                    "action": event.action,
                    "outcome": "success" if event.result.lower() == "success" else "failure",
                    "severity": self._map_severity(event.severity),
                },
                "user": {"name": event.user},
                "source": {"ip": event.source_ip},
                "destination": {"address": event.target},
                "siyarix": {
                    "session_id": event.session_id,
                    "event_type": event.event_type,
                    "hash": event.hash_current,
                    "details": event.details,
                }
            }
            response = await self._client.post(
                f"{self.url}/_doc",
                json=ecs_payload,
                headers={"Authorization": f"ApiKey {self.api_key}", "Content-Type": "application/json"}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to Elastic (ECS): %s", e)

    def _map_severity(self, sev: str) -> int:
        return {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 0}.get(sev.lower(), 0)


class SplunkHECAdapter(SIEMAdapter):
    """Adapter for Splunk HTTP Event Collector using Splunk CIM / JSON."""
    def __init__(self, url: str, hec_token: str) -> None:
        super().__init__(url)
        self.hec_token = hec_token

    async def ship(self, event: AuditEvent) -> None:
        try:
            # Format payload mapped to Splunk Common Information Model (CIM)
            cim_payload = {
                "time": event.timestamp.timestamp(),
                "host": socket.gethostname(),
                "source": "siyarix_audit_logger",
                "sourcetype": "_json",
                "event": {
                    "action": event.action,
                    "app": "siyarix",
                    "category": event.event_type,
                    "dest": event.target,
                    "severity": event.severity,
                    "src_ip": event.source_ip,
                    "user": event.user,
                    "status": event.result,
                    "session_id": event.session_id,
                    "signature_id": event.event_id,
                    "chain_hash": event.hash_current,
                    "custom_details": event.details
                }
            }
            response = await self._client.post(
                f"{self.url}/services/collector/event",
                json=cim_payload,
                headers={"Authorization": f"Splunk {self.hec_token}"}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to Splunk (CIM): %s", e)


class QRadarAdapter(SIEMAdapter):
    """Adapter for IBM QRadar using Log Event Extended Format (LEEF)."""
    def __init__(self, url: str, auth_token: str) -> None:
        super().__init__(url)
        self.auth_token = auth_token

    async def ship(self, event: AuditEvent) -> None:
        try:
            # Format payload using IBM QRadar LEEF 2.0
            # LEEF:2.0|Vendor|Product|Version|EventID|Key=Value...
            leef_header = f"LEEF:2.0|Siyarix|SecurityPlatform|1.0.0|{event.event_type}|"
            
            # Map attributes to LEEF standard keys
            leef_attrs = [
                f"cat={event.action}",
                f"sev={self._map_severity(event.severity)}",
                f"usrName={event.user}",
                f"src={event.source_ip}",
                f"dst={event.target}",
                f"identHostName={socket.gethostname()}",
                f"sessionid={event.session_id}",
                f"status={event.result}",
                f"eventid={event.event_id}",
            ]
            leef_payload = leef_header + "\t".join(leef_attrs)

            # In a real QRadar integration, LEEF is typically shipped via TCP/UDP Syslog.
            # For REST API, we send it to an Ariel or direct ingestion endpoint if supported.
            response = await self._client.post(
                f"{self.url}/api/ariel/searches",  # Adjust if direct ingestion API differs
                json={"query_expression": f"INSERT INTO events VALUES ('{leef_payload}')"},
                headers={"SEC": self.auth_token}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Failed to ship event to QRadar (LEEF): %s", e)
            
    def _map_severity(self, sev: str) -> int:
        return {"critical": 10, "high": 8, "medium": 6, "low": 4, "info": 1}.get(sev.lower(), 1)
