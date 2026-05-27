"""
Emergency Stop (ESC) kill-switch for the Siyarix execution engine.
Wires into chat._running and engine._pool.cancel_pending().
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class KillSwitchState(Enum):
    ARMED = "armed"
    TRIGGERED = "triggered"
    DISARMED = "disarmed"


@dataclass
class KillSwitch:
    state: KillSwitchState = KillSwitchState.ARMED
    _callbacks: list = field(default_factory=list)

    def trigger(self) -> None:
        """Trigger the kill switch - cancels all pending work."""
        if self.state == KillSwitchState.DISARMED:
            return
        self.state = KillSwitchState.TRIGGERED
        for cb in self._callbacks:
            try:
                cb()
            except Exception as exc:
                logger.exception("Kill switch callback failed: %s", exc)

    def disarm(self) -> None:
        self.state = KillSwitchState.DISARMED

    def arm(self) -> None:
        self.state = KillSwitchState.ARMED

    def register(self, callback) -> None:
        self._callbacks.append(callback)

    @property
    def is_triggered(self) -> bool:
        return self.state == KillSwitchState.TRIGGERED


__all__ = ["KillSwitch", "KillSwitchState"]
