# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dynamic variable resolution for offline response templates."""

from __future__ import annotations

import getpass
import platform
import re
import socket
from datetime import datetime as _datetime
from typing import Callable
from typing import Final

REPO_URL: Final[str] = "https://github.com/mufthakherul/siyarix"
DOCS_URL: Final[str] = "https://github.com/mufthakherul/siyarix/tree/main/docs"
CONTRIBUTE_URL: Final[str] = (
    "https://github.com/mufthakherul/siyarix/blob/main/CONTRIBUTING.md"
)

_VERSION: str | None = None


def _get_version() -> str:
    global _VERSION
    if _VERSION is None:
        try:
            from importlib.metadata import version as _v
            _VERSION = _v("siyarix")
        except Exception:
            _VERSION = "1.0.0"
    return _VERSION


def _time_of_day() -> str:
    hour = _datetime.now().hour
    if hour < 12:
        return "morning"
    if hour < 17:
        return "afternoon"
    if hour < 21:
        return "evening"
    return "night"


def _normalize_platform() -> str:
    raw = platform.system()
    if raw == "Linux":
        return "Linux"
    if raw == "Windows":
        return "Windows"
    if raw == "Darwin":
        return "macOS"
    return raw


_RESOLVERS: dict[str, Callable[[], str]] = {
    "username": lambda: getpass.getuser(),
    "hostname": lambda: socket.gethostname(),
    "platform": _normalize_platform,
    "time_of_day": _time_of_day,
    "current_time": lambda: _datetime.now().strftime("%H:%M"),
    "current_date": lambda: _datetime.now().strftime("%Y-%m-%d"),
    "version": _get_version,
    "repo_url": lambda: REPO_URL,
    "docs_url": lambda: DOCS_URL,
    "contribute_url": lambda: CONTRIBUTE_URL,
}


def resolve(text: str) -> str:
    """Replace all {variable} placeholders with their resolved values."""
    def _replacer(m: re.Match[str]) -> str:
        key = m.group(1).lower().strip()
        resolver = _RESOLVERS.get(key)
        if resolver is not None:
            val = resolver()
            return str(val) if val is not None else m.group(0)
        return m.group(0)
    return re.sub(r"\{(\w+)\}", _replacer, text)


def known_variables() -> frozenset[str]:
    """Return the set of recognised variable names."""
    return frozenset(_RESOLVERS.keys())
