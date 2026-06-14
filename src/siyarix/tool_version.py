# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version detection utility for tools.

Uses the cyber_tools.json database to determine version arguments and
regex patterns for extracting version numbers from tool output.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

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
    return entry


def _resolve_alias(name: str) -> str:
    db = _load_db()
    for tool_name, data in db.items():
        if name in data.get("aliases", []):
            return tool_name
    return ""


def detect_version(name: str, binary_path: str | None = None) -> str:
    meta = get_tool_metadata(name)
    if not meta:
        return ""

    version_args = meta.get("version_args", ["--version"])
    version_pattern = meta.get("version_pattern", "")
    if not version_pattern:
        return ""

    binary = meta.get("binary", name)
    cmd = [binary_path or binary]
    cmd.extend(version_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            errors="replace",
        )
        output = result.stdout or result.stderr
        match = re.search(version_pattern, output)
        if match:
            return match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass
    except Exception:
        logger.debug("Version detection failed for %s", name, exc_info=True)
    return ""


def bulk_detect(tools: list[str]) -> dict[str, str]:
    return {t: detect_version(t) for t in tools}

__all__ = [
    "detect_version",
    "get_tool_metadata",
    "bulk_detect",
    "_load_db",
]
