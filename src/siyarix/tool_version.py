# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version detection utility for tools.

Uses the cyber_tools.json database to determine version arguments and
regex patterns for extracting version numbers from tool output.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DB: dict[str, Any] | None = None

_CYBER_TOOLS_PATH = Path(__file__).parent / "data" / "cyber_tools.json"

# Tools that should never be version-checked — GUI apps, Wine binaries,
# stateful tools, or anything that could capture the TTY or change directory.
_UNSAFE_VERSION_TOOLS: frozenset[str] = frozenset({
    "burpsuite",    # GUI Java app — may launch window
    "zaproxy",      # GUI Java app — may launch window
    "armitage",     # GUI app
    "cobalt-strike",# GUI app
    "maltego",      # GUI app
    "beef",         # Requires server startup
    "wireshark",    # GUI app
    "mimikatz",     # Wine binary — changes working directory, captures TTY
    "metasploit",   # Console app — slow startup, changes terminal state
})


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


def _is_safe_tool(binary_path: str) -> bool:
    """Check if the binary is safe to run for version detection.

    Skips shell scripts that invoke ``sudo``, change directory (``cd``), or
    otherwise mutate process state — these could steal the TTY or change the
    working directory of the parent process.
    """
    try:
        with open(binary_path, "rb") as f:
            header = f.read(512)
        if not header.startswith(b"#!"):
            return True
        lower = header.lower()
        if b"sudo" in lower:
            logger.debug("Skipping %s: shell script wrapper calls sudo", binary_path)
            return False
        if b"\ncd " in lower or b"\ncd\t" in lower or b"\ncd/" in lower:
            logger.debug("Skipping %s: shell script changes directory", binary_path)
            return False
    except OSError:
        pass
    return True


def detect_version(name: str, binary_path: str | None = None) -> str:
    meta = get_tool_metadata(name)
    if not meta:
        return ""

    # Skip known unsafe/GUI/Wine tools
    if name in _UNSAFE_VERSION_TOOLS:
        return ""

    version_args = meta.get("version_args", ["--version"])
    version_pattern = meta.get("version_pattern", "")
    if not version_pattern:
        return ""

    binary = meta.get("binary", name)
    path = binary_path or binary

    if not _is_safe_tool(path):
        return ""

    cmd = [path]
    cmd.extend(version_args)

    # Save working directory in case the tool changes it
    orig_cwd = Path.cwd()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            stdin=subprocess.DEVNULL,
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
    finally:
        # Restore original working directory in case the tool changed it
        try:
            if Path.cwd() != orig_cwd:
                import os as _os
                _os.chdir(orig_cwd)
        except OSError:
            pass
    return ""


def bulk_detect(tools: list[str]) -> dict[str, str]:
    """Detect versions for a list of tool names sequentially."""
    return {t: detect_version(t) for t in tools}


def parallel_detect(tools: list[tuple[str, str]], max_workers: int = 10) -> dict[str, str]:
    """Detect versions for (name, binary_path) pairs in parallel.

    Uses a thread pool since version detection is I/O-bound (subprocess
    execution with 15s timeout per tool).

    Args:
        tools: List of ``(name, binary_path)`` tuples.
        max_workers: Maximum concurrent version checks (default 10).

    Returns:
        Dict mapping tool name to detected version string.
    """
    if not tools:
        return {}
    versions: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(detect_version, name, path): name for name, path in tools}
        for fut in concurrent.futures.as_completed(fut_map):
            name = fut_map[fut]
            try:
                version = fut.result()
                if version:
                    versions[name] = version
            except Exception:
                pass
    return versions


__all__ = [
    "detect_version",
    "get_tool_metadata",
    "bulk_detect",
    "parallel_detect",
    "_load_db",
]
