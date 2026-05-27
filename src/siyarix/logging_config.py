"""Centralized logging configuration for Siyarix.

Provides a minimal, dependency-free JSON-style logger with UTC timestamps
and a helper to set sensible defaults for console and file handlers.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional


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


def configure_logging(
    level: Optional[str] = None, *, enable_console: bool = True
) -> None:
    """Configure root logger.

    - `level`: optional string like "INFO"/"DEBUG". If None, defaults to INFO.
    - `enable_console`: whether to attach a console handler.
    """
    root = logging.getLogger()
    if level:
        try:
            lvl = getattr(logging, level.upper())
        except Exception:
            lvl = logging.INFO
    else:
        lvl = logging.INFO
    root.setLevel(lvl)

    # Prevent duplicate handlers when reloading in tests
    if any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        return

    if enable_console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(lvl)
        ch.setFormatter(_JSONFormatter())
        root.addHandler(ch)


__all__ = ["configure_logging"]
