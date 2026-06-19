# SPDX-License-Identifier: AGPL-3.0-or-later

"""Centralized logging configuration for Siyarix.

Provides a minimal, dependency-free JSON-style logger with UTC timestamps
and a helper to set sensible defaults for console and file handlers.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str | None = None, *, enable_console: bool = True) -> None:
    """Configure root logger.

    - `level`: optional string like "INFO"/"DEBUG". If None, defaults to INFO.
    - `enable_console`: whether to attach a console handler.
    """
    root = logging.getLogger()
    if level:
        lvl = getattr(logging, level.upper(), logging.INFO)
    else:
        lvl = logging.INFO
    root.setLevel(lvl)

    # Suppress noisy INFO-level logs from httpx and httpcore
    # These spam HTTP request/response lines that are debugging diagnostics
    for noisy in (
        "httpx",
        "httpx._client",
        "httpx._config",
        "httpcore",
        "httpcore._async",
        "httpcore._sync",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Suppress keyring backend debug spam at startup
    for noisy in ("keyring.backend", "keyring"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Update existing console handler levels so reconfiguration takes effect
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler):
            h.setLevel(lvl)

    if not enable_console:
        return

    # Only add a handler if none exists
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(lvl)
        ch.setFormatter(_JSONFormatter())
        root.addHandler(ch)


__all__ = ["configure_logging"]
