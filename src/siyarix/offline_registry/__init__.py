# SPDX-License-Identifier: AGPL-3.0-or-later

"""Offline Response Registry — natural responses when no AI provider is available.

Usage::

    from siyarix.offline_registry import OfflineResponder

    responder = OfflineResponder()
    reply = responder.respond("hello")
    print(reply)
"""

from __future__ import annotations

from .registry import ResponseRegistry
from .matcher import best_match
from .resolver import resolve

__all__ = ["OfflineResponder"]


class OfflineResponder:
    """High-level API for the offline response system.

    Loads response packs, matches user input, and resolves variables.
    Supports hot-reloading via :meth:`reload_if_changed`.
    """

    def __init__(self, pack_dir: str | None = None) -> None:
        self._registry = ResponseRegistry(pack_dir=pack_dir)
        self._registry.load()

    def respond(self, text: str, threshold: float = 0.75) -> str:
        """Return the best matching response for *text*, or a fallback message."""
        self._registry.reload_if_changed()
        entry = best_match(text, self._registry.entries, threshold=threshold)
        if entry is not None:
            return resolve(entry.template)
        return resolve(
            "I don't have enough offline knowledge to answer that request.\n\n"
            "You can:\n\n"
            "* Connect an AI provider.\n"
            "* Search documentation.\n"
            "* Use available CLI commands.\n"
            "* Try a different question.\n\n"
            "Documentation:\n\n{docs_url}"
        )

    def reload_if_changed(self) -> bool:
        """Check for pack file changes and reload if needed. Returns True if reloaded."""
        return self._registry.reload_if_changed()
