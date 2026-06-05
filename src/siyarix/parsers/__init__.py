# SPDX-License-Identifier: AGPL-3.0-or-later

"""Parser protocol and base utilities for all tool output parsers.

All parsers implement the ``Parser`` protocol and should use the
``BaseParser`` mixin for consistent error handling, logging, and
finding field population.
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
# Auto-import all parser classes
# ---------------------------------------------------------------------------

from .aircrack_parser import AircrackParser  # noqa: F401, E402
from .amass_parser import AmassParser  # noqa: F401, E402
from .bettercap_parser import BettercapParser  # noqa: F401, E402
from .burpsuite_parser import BurpsuiteParser  # noqa: F401, E402
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
from .wpscan_parser import WpscanParser  # noqa: F401, E402
from .zaproxy_parser import ZaproxyParser  # noqa: F401, E402

__all__ = [
    "Parser",
    "BaseParser",
    "build_finding",
    "_now_iso",
    "AircrackParser",
    "AmassParser",
    "BettercapParser",
    "BurpsuiteParser",
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
    "WpscanParser",
    "ZaproxyParser",
]
