# SPDX-License-Identifier: AGPL-3.0-or-later

"""Parser protocol, base utilities, and ParserRegistry for all tool output parsers.

All parsers implement the ``Parser`` protocol and should use the
``BaseParser`` mixin for consistent error handling, logging, and
finding field population.

The ``ParserRegistry`` auto-discovers all parsers in this module and
provides tool → parser lookup for registry-mode execution.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol — all parsers must implement ``parse``
# ---------------------------------------------------------------------------


@runtime_checkable
class Parser(Protocol):
    """Protocol for output parsers — all parsers must implement ``parse``."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        """Parse raw tool output into normalized finding dicts."""
        ...


# ---------------------------------------------------------------------------
# Base parser — provides consistent error handling, logging, and helpers
# ---------------------------------------------------------------------------


class BaseParser:
    """Mixin for parsers that provides consistent error handling & logging.

    Usage::

        class MyParser(BaseParser):
            def parse(self, output: str) -> list[dict[str, Any]]:
                ...
    """

    def _parse_safe(self, output: str) -> list[dict[str, Any]]:
        """Wrap ``parse`` in try/except so callers get empty list on failure."""
        try:
            result = self.parse(output)  # type: ignore
            if not isinstance(result, list):
                logger.warning("%s.parse returned non-list", type(self).__name__)
                return []
            return result
        except Exception:
            logger.exception(
                "Parser %s failed on %d-byte input",
                type(self).__name__,
                len(output),
            )
            return []

    def _ensure_fields(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Normalize finding fields with defaults for any missing keys."""
        defaults = {
            "title": "Unknown finding",
            "severity": "info",
            "description": "",
            "evidence": "",
            "tool": "unknown",
            "target": "",
            "timestamp": _now_iso(),
        }
        for k, v in defaults.items():
            finding.setdefault(k, v)
        return finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(tz=UTC).isoformat()


def build_finding(
    *,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    tool: str,
    target: str = "",
) -> dict[str, Any]:
    """Build a normalized finding dict with current timestamp."""
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "tool": tool,
        "target": target,
        "timestamp": _now_iso(),
    }


# ---------------------------------------------------------------------------
# ParserRegistry — auto-discover and look up parsers by tool name
# ---------------------------------------------------------------------------


class ParserRegistry:
    """Maps tool names to parser instances for structured finding extraction.

    Auto-discoverable: call ``discover()`` once at startup to populate the
    map from every parser class imported in this module.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, dict[str | None, Parser]] = {}

    def register(self, tool_name: str, parser: Parser, version: str | None = None) -> None:
        if tool_name not in self._parsers:
            self._parsers[tool_name] = {}
        self._parsers[tool_name][version] = parser
        # Set default parser if not explicitly set
        if version is not None and None not in self._parsers[tool_name]:
            self._parsers[tool_name][None] = parser

    def get(self, tool_name: str, version: str | None = None) -> Parser | None:
        versions = self._parsers.get(tool_name)
        if not versions:
            return None
        if version in versions:
            return versions[version]
        return versions.get(None)

    def parse(self, tool_name: str, output: str, version: str | None = None) -> list[dict[str, Any]]:
        parser = self.get(tool_name, version)
        if not parser:
            return []
        if isinstance(parser, BaseParser):
            return parser._parse_safe(output)
        try:
            result = parser.parse(output)
            return result if isinstance(result, list) else []
        except Exception:
            logger.exception("Parser failed for tool: %s", tool_name)
            return []

    def has_parser(self, tool_name: str, version: str | None = None) -> bool:
        if tool_name not in self._parsers:
            return False
        if version is None:
            return True
        return version in self._parsers[tool_name] or None in self._parsers[tool_name]

    def registered_tools(self) -> list[str]:
        return sorted(self._parsers)

    @property
    def count(self) -> int:
        return sum(len(v) for v in self._parsers.values())

    def discover(self) -> dict[str, dict[str | None, Parser]]:
        """Auto-discover all parser classes imported in this module and map
        them to their tool names by convention (e.g. ``NmapParser`` → ``nmap``)."""
        for name, obj in globals().items():
            if isinstance(obj, type) and issubclass(obj, BaseParser) and obj is not BaseParser:
                tool_name = _class_to_tool_name(name)
                instance = obj()
                if isinstance(instance, Parser):
                    version = getattr(instance, "version", None)
                    self.register(tool_name, instance, version)

        try:
            import siyarix_parsers
            if hasattr(siyarix_parsers, "NmapRustParser"):
                self.register("nmap", siyarix_parsers.NmapRustParser(), "rust")
            if hasattr(siyarix_parsers, "NucleiRustParser"):
                self.register("nuclei", siyarix_parsers.NucleiRustParser(), "rust")
        except ImportError:
            pass

        return self._parsers


def _class_to_tool_name(class_name: str) -> str:
    """Convert ``NmapParser`` → ``nmap``, ``WhatwebParser`` → ``whatweb``, etc."""
    if class_name.endswith("Parser"):
        stem = class_name[:-6]
    else:
        stem = class_name
    result = []
    for i, ch in enumerate(stem):
        if ch.isupper() and i > 0:
            result.append("-")
        result.append(ch.lower())
    return "".join(result)


# ---------------------------------------------------------------------------
# Auto-import all parser classes
# ---------------------------------------------------------------------------

from .aircrack_parser import AircrackParser  # noqa: F401, E402
from .amass_parser import AmassParser  # noqa: F401, E402
from .bettercap_parser import BettercapParser  # noqa: F401, E402
from .burpsuite_parser import BurpsuiteParser  # noqa: F401, E402
from .curl_parser import CurlParser  # noqa: F401, E402
from .dig_parser import DigParser  # noqa: F401, E402
from .ettercap_parser import EttercapParser  # noqa: F401, E402
from .ffuf_parser import FfufParser  # noqa: F401, E402
from .gobuster_parser import GobusterParser  # noqa: F401, E402
from .hashcat_parser import HashcatParser  # noqa: F401, E402
from .hydra_parser import HydraParser  # noqa: F401, E402
from .impacket_parser import ImpacketParser  # noqa: F401, E402
from .john_parser import JohnParser  # noqa: F401, E402
from .masscan_parser import MasscanParser  # noqa: F401, E402
from .metasploit_parser import MetasploitParser  # noqa: F401, E402
from .nikto_parser import NiktoParser  # noqa: F401, E402
from .nmap_parser import NmapParser  # noqa: F401, E402
from .nuclei_parser import NucleiParser  # noqa: F401, E402
from .shodan_parser import ShodanParser  # noqa: F401, E402
from .sqlmap_parser import SqlmapParser  # noqa: F401, E402
from .subfinder_parser import SubfinderParser  # noqa: F401, E402
from .whatweb_parser import WhatwebParser  # noqa: F401, E402
from .whois_parser import WhoisParser  # noqa: F401, E402
from .wpscan_parser import WpscanParser  # noqa: F401, E402
from .zaproxy_parser import ZaproxyParser  # noqa: F401, E402

__all__ = [
    "Parser",
    "BaseParser",
    "ParserRegistry",
    "build_finding",
    "_now_iso",
    "AircrackParser",
    "AmassParser",
    "BettercapParser",
    "BurpsuiteParser",
    "CurlParser",
    "DigParser",
    "EttercapParser",
    "FfufParser",
    "GobusterParser",
    "HashcatParser",
    "HydraParser",
    "ImpacketParser",
    "JohnParser",
    "MasscanParser",
    "MetasploitParser",
    "NiktoParser",
    "NmapParser",
    "NucleiParser",
    "ShodanParser",
    "SqlmapParser",
    "SubfinderParser",
    "WhatwebParser",
    "WhoisParser",
    "WpscanParser",
    "ZaproxyParser",
]
