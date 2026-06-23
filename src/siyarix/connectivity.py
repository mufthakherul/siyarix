# SPDX-License-Identifier: AGPL-3.0-or-later
"""Connectivity monitoring and smart mode switching."""

from __future__ import annotations

import asyncio
import logging
from enum import StrEnum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ConnectionState(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ConnectivityMonitor:
    _TARGETS = [
        "https://1.1.1.1",
        "https://8.8.8.8",
        "https://google.com",
    ]

    def __init__(
        self,
        check_interval: float = 30.0,
        on_state_change: Callable[[ConnectionState, ConnectionState], Any] | None = None,
    ) -> None:
        self._state = ConnectionState.UNKNOWN
        self._check_interval = check_interval
        self._on_state_change = on_state_change
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_check_time = 0.0
        self._consecutive_failures = 0
        self._consecutive_successes = 0

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def is_online(self) -> bool:
        return self._state == ConnectionState.ONLINE

    @property
    def is_offline(self) -> bool:
        return self._state == ConnectionState.OFFLINE

    async def check_once(self) -> ConnectionState:
        import httpx

        for target in self._TARGETS:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(target, timeout=5.0)
                    if response.status_code < 500:
                        self._consecutive_successes += 1
                        self._consecutive_failures = 0
                        if self._consecutive_successes >= 2:
                            new_state = ConnectionState.ONLINE
                        else:
                            new_state = ConnectionState.DEGRADED
                        return self._update_state(new_state)

            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError, OSError):
                self._consecutive_failures += 1
                self._consecutive_successes = 0
                continue
            except Exception as exc:
                logger.debug("Connectivity check skipped: %s", exc)
                continue

        if self._consecutive_failures >= 3:
            new_state = ConnectionState.OFFLINE
        else:
            new_state = ConnectionState.DEGRADED
        return self._update_state(new_state)

    def _update_state(self, new_state: ConnectionState) -> ConnectionState:
        old_state = self._state
        if new_state != old_state:
            self._state = new_state
            logger.info("Connectivity state changed: %s -> %s", old_state, new_state)
            if self._on_state_change:
                try:
                    self._on_state_change(old_state, new_state)
                except Exception as exc:
                    logger.warning("State change callback failed: %s", exc)
        return self._state

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _monitor_loop(self) -> None:
        while self._running:
            await self.check_once()
            await asyncio.sleep(self._check_interval)

    def detect_provider_connectivity(self) -> dict[str, bool]:
        status: dict[str, bool] = {}
        providers = ["ollama", "lmstudio", "llamacpp", "vllm", "localai"]
        for prov in providers:
            try:
                from .provider_utils import check_provider_health
                status[prov] = check_provider_health(prov)
            except Exception:
                status[prov] = False
        return status


class SmartModeController:
    def __init__(
        self,
        get_current_mode: Callable[[], str],
        set_mode: Callable[[str], Any],
        monitor: ConnectivityMonitor | None = None,
    ) -> None:
        self._get_current_mode = get_current_mode
        self._set_mode = set_mode
        self._monitor = monitor or ConnectivityMonitor(on_state_change=self._on_connectivity_change)
        self._original_mode: str = "integrated"
        self._auto_offline_enabled = True

    @property
    def monitor(self) -> ConnectivityMonitor:
        return self._monitor

    async def _on_connectivity_change(self, old_state: ConnectionState, new_state: ConnectionState) -> None:
        if not self._auto_offline_enabled:
            return

        current = self._get_current_mode()
        if current == "offline" and new_state == ConnectionState.ONLINE:
            from .chat.console import console
            console.print("[green]Network connectivity restored. Consider /mode integrated for LLM features.[/green]")
        elif current != "offline" and new_state == ConnectionState.OFFLINE:
            from .chat.console import console
            console.print("[yellow]Network connectivity lost. Switching to offline mode automatically.[/yellow]")
            self._original_mode = current
            self._set_mode("offline")

    async def start(self) -> None:
        await self._monitor.start()

    async def stop(self) -> None:
        await self._monitor.stop()


__all__ = [
    "ConnectivityMonitor",
    "ConnectionState",
    "SmartModeController",
]
