# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lightweight in-process event bus for operation-level signaling."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable


@dataclass
class Event:
    """Operation event payload."""

    topic: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


Subscriber = Callable[[Event], None]


class InMemoryEventBus:
    """Minimal synchronous in-memory event bus."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Subscriber) -> None:
        self._subscribers[topic].append(callback)

    def publish(self, event: Event) -> None:
        for callback in self._subscribers.get(event.topic, []):
            callback(event)
