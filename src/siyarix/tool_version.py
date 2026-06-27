# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool metadata lookup utility.

Provides access to the cyber_tools.json database for tool metadata
(category, personas, risk level, etc.).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

_DB: dict[str, Any] | None = None

_CYBER_TOOLS_PATH = Path(__file__).parent / "data" / "cyber_tools.json"


def _load_db() -> dict[str, Any]:
    global _DB
    if _DB is not None:
        return _DB
    if _CYBER_TOOLS_PATH.exists():
        try:
            _DB = json.loads(_CYBER_TOOLS_PATH.read_text())
        except Exception:
            logger.exception("Failed to load cyber_tools.json")
            _DB = {}
    else:
        _DB = {}
    return _DB


def get_tool_metadata(name: str) -> dict[str, Any]:
    db = _load_db()
    entry = db.get(name, {})
    if not entry:
        entry = db.get(_resolve_alias(name), {})
    return cast("dict[str, Any]", entry)


def _resolve_alias(name: str) -> str:
    db = _load_db()
    for tool_name, data in db.items():
        if name in data.get("aliases", []):
            return tool_name
    return ""


__all__ = [
    "get_tool_metadata",
    "_load_db",
]
