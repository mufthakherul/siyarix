"""WebSocket streaming client for the Siyarix cloud platform."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

from .offline_store import OfflineStore

logger = logging.getLogger(__name__)

_MAX_BACKOFF = 60.0


class AgentStreamClient:
    """Maintains a WebSocket connection to the Siyarix server.

    Automatically reconnects with exponential backoff and queues findings to
    the offline store when the connection is unavailable.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        agent_id: str,
        offline_store: OfflineStore,
    ) -> None:
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._agent_id = agent_id
        self._offline_store = offline_store
        self._ws: Any | None = None
        self._connected = False
        self._backoff = 1.0

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish the WebSocket connection with auth headers.

        Blocks until the connection succeeds; retries with exponential backoff.
        """
        import websockets

        ws_url = f"{self._server_url}/ws/agent/{self._agent_id}"
        while True:
            try:
                self._ws = await websockets.connect(
                    ws_url,
                    additional_headers={"X-API-Key": self._api_key},
                )
                self._connected = True
                self._backoff = 1.0
                logger.info("Connected to Siyarix server at %s", self._server_url)
                await self._flush_offline()
                return
            except Exception as exc:
                self._connected = False
                logger.warning(
                    "Connection failed (%s), retrying in %.0fs", exc, self._backoff
                )
                await asyncio.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, _MAX_BACKOFF)

    async def _flush_offline(self) -> None:
        """Send any unsynced offline findings to the server."""
        pending = self._offline_store.get_unsynced_findings()
        if not pending:
            return
        logger.info("Flushing %d offline finding(s) to server", len(pending))
        synced_ids: list[str] = []
        for finding in pending:
            try:
                await self._send_raw({"type": "finding", "payload": finding})
                synced_ids.append(finding["id"])
            except Exception as exc:
                logger.exception(
                    "Failed to flush finding %s: %s", finding.get("id"), exc
                )
                break  # stop flushing on first failure; will retry next reconnect
        if synced_ids:
            self._offline_store.mark_synced(synced_ids)

    async def _send_raw(self, data: dict) -> None:
        if self._ws is None or not self._connected:
            raise RuntimeError("Not connected")
        await self._ws.send(json.dumps(data))

    # ------------------------------------------------------------------
    # Public send helpers
    # ------------------------------------------------------------------

    async def send_finding(self, finding: dict) -> None:
        """Send a finding to the server; queues offline if disconnected."""
        if not self._connected or self._ws is None:
            self._offline_store.save_finding(finding, finding.get("scan_id", "unknown"))
            return
        try:
            await self._send_raw({"type": "finding", "payload": finding})
        except Exception as exc:
            logger.exception("Failed to send finding %s: %s", finding.get("id"), exc)
            self._connected = False
            self._offline_store.save_finding(finding, finding.get("scan_id", "unknown"))

    async def send_scan_complete(self, scan_id: str, summary: dict) -> None:
        """Notify the server that a scan has completed."""
        if not self._connected or self._ws is None:
            return
        try:
            await self._send_raw(
                {"type": "scan_complete", "scan_id": scan_id, "summary": summary}
            )
        except Exception as exc:
            logger.exception("Failed to send scan_complete for %s: %s", scan_id, exc)
            self._connected = False

    async def send_task_ack(
        self, task_id: str, accepted: bool, reason: str | None = None
    ) -> None:
        """Acknowledge task receipt/validation outcome to server."""
        if not self._connected or self._ws is None:
            return
        payload = {
            "type": "task_ack",
            "task_id": task_id,
            "accepted": accepted,
            "reason": reason,
        }
        try:
            await self._send_raw(payload)
        except Exception as exc:
            logger.exception("Failed to send task ack %s: %s", task_id, exc)
            self._connected = False

    async def send_task_progress(
        self,
        task_id: str,
        percent: int,
        message: str | None = None,
    ) -> None:
        """Send lightweight task progress updates (0-100)."""
        if not self._connected or self._ws is None:
            return
        payload = {
            "type": "task_progress",
            "task_id": task_id,
            "percent": max(0, min(percent, 100)),
            "message": message,
        }
        try:
            await self._send_raw(payload)
        except Exception as exc:
            logger.exception("Failed to send task progress %s: %s", task_id, exc)
            self._connected = False

    async def send_task_result(self, task_id: str, result: dict) -> None:
        """Send final task execution result payload."""
        if not self._connected or self._ws is None:
            return
        payload = {
            "type": "task_result",
            "task_id": task_id,
            "result": result,
        }
        try:
            await self._send_raw(payload)
        except Exception as exc:
            logger.exception("Failed to send task result %s: %s", task_id, exc)
            self._connected = False

    # ------------------------------------------------------------------
    # Receive
    # ------------------------------------------------------------------

    async def receive_tasks(self) -> AsyncGenerator[dict, None]:
        """Yield task assignment messages sent by the server."""
        if self._ws is None:
            return
        try:
            async for raw_msg in self._ws:
                try:
                    msg = json.loads(raw_msg)
                    yield msg
                except json.JSONDecodeError:
                    logger.warning("Received non-JSON message from server")
        except Exception as exc:
            self._connected = False
            logger.warning("WebSocket receive error: %s", exc)
