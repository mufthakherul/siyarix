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

    def parse(
        self, tool_name: str, output: str, version: str | None = None
    ) -> list[dict[str, Any]]:
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
        them to their tool names by convention (e.g. ``NmapParser`` → ``nmap``).

        Discovers both ``BaseParser`` subclasses and any class whose name
        ends with ``Parser`` and implements a ``parse`` method.
        """
        for name, obj in globals().items():
            if not isinstance(obj, type):
                continue
            if name in ("BaseParser", "Parser"):
                continue
            if not name.endswith("Parser") and not issubclass(obj, BaseParser):
                continue
            if issubclass(obj, BaseParser) and obj is BaseParser:
                continue
            if not hasattr(obj, "parse"):
                continue
            tool_name = _class_to_tool_name(name)
            instance = obj()
            if isinstance(instance, Parser):
                version = getattr(instance, "version", None)
                self.register(tool_name, instance, version)

        try:
            import siyarix_parsers  # type: ignore

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
from .aquatone_parser import AquatoneParser  # noqa: F401, E402
from .arachni_parser import ArachniParser  # noqa: F401, E402
from .arjun_parser import ArjunParser  # noqa: F401, E402
from .assetfinder_parser import AssetfinderParser  # noqa: F401, E402
from .aws_parser import AwsParser  # noqa: F401, E402
from .bandit_parser import BanditParser  # noqa: F401, E402
from .bettercap_parser import BettercapParser  # noqa: F401, E402
from .bloodhound_parser import BloodhoundParser  # noqa: F401, E402
from .bloodhound_python_parser import BloodhoundPythonParser  # noqa: F401, E402
from .burpsuite_parser import BurpsuiteParser  # noqa: F401, E402
from .certipy_parser import CertipyParser  # noqa: F401, E402
from .checkov_parser import CheckovParser  # noqa: F401, E402
from .commix_parser import CommixParser  # noqa: F401, E402
from .corsy_parser import CorsyParser  # noqa: F401, E402
from .crackmapexec_parser import CrackmapexecParser  # noqa: F401, E402
from .curl_parser import CurlParser  # noqa: F401, E402
from .dalfox_parser import DalfoxParser  # noqa: F401, E402
from .dig_parser import DigParser  # noqa: F401, E402
from .dirb_parser import DirbParser  # noqa: F401, E402
from .dirsearch_parser import DirsearchParser  # noqa: F401, E402
from .dmitry_parser import DmitryParser  # noqa: F401, E402
from .dnsenum_parser import DnsenumParser  # noqa: F401, E402
from .dnsmap_parser import DnsmapParser  # noqa: F401, E402
from .dnsrecon_parser import DnsreconParser  # noqa: F401, E402
from .dnstwist_parser import DnstwistParser  # noqa: F401, E402
from .dnsx_parser import DnsxParser  # noqa: F401, E402
from .enum4linux_parser import Enum4linuxParser  # noqa: F401, E402
from .ettercap_parser import EttercapParser  # noqa: F401, E402
from .evil_winrm_parser import EvilWinrmParser  # noqa: F401, E402
from .exiftool_parser import ExiftoolParser  # noqa: F401, E402
from .feroxbuster_parser import FeroxbusterParser  # noqa: F401, E402
from .ffuf_parser import FfufParser  # noqa: F401, E402
from .findomain_parser import FindomainParser  # noqa: F401, E402
from .finger_parser import FingerParser  # noqa: F401, E402
from .gau_parser import GauParser  # noqa: F401, E402
from .gitleaks_parser import GitleaksParser  # noqa: F401, E402
from .gobuster_parser import GobusterParser  # noqa: F401, E402
from .gospider_parser import GospiderParser  # noqa: F401, E402
from .gowitness_parser import GowitnessParser  # noqa: F401, E402
from .grype_parser import GrypeParser  # noqa: F401, E402
from .hakrawler_parser import HakrawlerParser  # noqa: F401, E402
from .hash_identifier_parser import HashIdentifierParser  # noqa: F401, E402
from .hashcat_parser import HashcatParser  # noqa: F401, E402
from .httpx_parser import HttpxParser  # noqa: F401, E402
from .hydra_parser import HydraParser  # noqa: F401, E402
from .ike_scan_parser import IkeScanParser  # noqa: F401, E402
from .impacket_parser import ImpacketParser  # noqa: F401, E402
from .interactsh_parser import InteractshParser  # noqa: F401, E402
from .john_parser import JohnParser  # noqa: F401, E402
from .jwt_tool_parser import JwtToolParser  # noqa: F401, E402
from .katana_parser import KatanaParser  # noqa: F401, E402
from .kerbrute_parser import KerbruteParser  # noqa: F401, E402
from .kiterunner_parser import KiterunnerParser  # noqa: F401, E402
from .kubectl_parser import KubectlParser  # noqa: F401, E402
from .kxss_parser import KxssParser  # noqa: F401, E402
from .ldapsearch_parser import LdapsearchParser  # noqa: F401, E402
from .lynis_parser import LynisParser  # noqa: F401, E402
from .masscan_parser import MasscanParser  # noqa: F401, E402
from .massdns_parser import MassdnsParser  # noqa: F401, E402
from .metasploit_parser import MetasploitParser  # noqa: F401, E402
from .mimikatz_parser import MimikatzParser  # noqa: F401, E402
from .naabu_parser import NaabuParser  # noqa: F401, E402
from .netcat_parser import NetcatParser  # noqa: F401, E402
from .nikto_parser import NiktoParser  # noqa: F401, E402
from .nmap_parser import NmapParser  # noqa: F401, E402
from .nuclei_parser import NucleiParser  # noqa: F401, E402
from .paramspider_parser import ParamspiderParser  # noqa: F401, E402
from .prowler_parser import ProwlerParser  # noqa: F401, E402
from .pypykatz_parser import PypykatzParser  # noqa: F401, E402
from .recon_ng_parser import ReconNgParser  # noqa: F401, E402
from .responder_parser import ResponderParser  # noqa: F401, E402
from .rustscan_parser import RustscanParser  # noqa: F401, E402
from .s3scanner_parser import S3scannerParser  # noqa: F401, E402
from .scoutsuite_parser import ScoutsuiteParser  # noqa: F401, E402
from .searchsploit_parser import SearchsploitParser  # noqa: F401, E402
from .seatbelt_parser import SeatbeltParser  # noqa: F401, E402
from .semgrep_parser import SemgrepParser  # noqa: F401, E402
from .sharphound_parser import SharphoundParser  # noqa: F401, E402
from .sherlock_parser import SherlockParser  # noqa: F401, E402
from .shodan_parser import ShodanParser  # noqa: F401, E402
from .shuffledns_parser import ShufflednsParser  # noqa: F401, E402
from .smbclient_parser import SmbclientParser  # noqa: F401, E402
from .smbmap_parser import SmbmapParser  # noqa: F401, E402
from .smtp_user_enum_parser import SmtpUserEnumParser  # noqa: F401, E402
from .sqlmap_parser import SqlmapParser  # noqa: F401, E402
from .ssh_audit_parser import SshAuditParser  # noqa: F401, E402
from .sslscan_parser import SslscanParser  # noqa: F401, E402
from .sslyze_parser import SslyzeParser  # noqa: F401, E402
from .subfinder_parser import SubfinderParser  # noqa: F401, E402
from .sublist3r_parser import Sublist3rParser  # noqa: F401, E402
from .syft_parser import SyftParser  # noqa: F401, E402
from .tcpdump_parser import TcpdumpParser  # noqa: F401, E402
from .testssl_parser import TestsslParser  # noqa: F401, E402
from .theharvester_parser import TheharvesterParser  # noqa: F401, E402
from .trivy_parser import TrivyParser  # noqa: F401, E402
from .trufflehog_parser import TrufflehogParser  # noqa: F401, E402
from .volatility_parser import VolatilityParser  # noqa: F401, E402
from .wafw00f_parser import Wafw00fParser  # noqa: F401, E402
from .wapiti_parser import WapitiParser  # noqa: F401, E402
from .waybackurls_parser import WaybackurlsParser  # noqa: F401, E402
from .wfuzz_parser import WfuzzParser  # noqa: F401, E402
from .wget_parser import WgetParser  # noqa: F401, E402
from .whatweb_parser import WhatwebParser  # noqa: F401, E402
from .whois_parser import WhoisParser  # noqa: F401, E402
from .wpscan_parser import WpscanParser  # noqa: F401, E402
from .xsstrike_parser import XsstrikeParser  # noqa: F401, E402
from .yara_parser import YaraParser  # noqa: F401, E402
from .zaproxy_parser import ZaproxyParser  # noqa: F401, E402
from .zgrab_parser import ZgrabParser  # noqa: F401, E402
from .zmap_parser import ZmapParser  # noqa: F401, E402

__all__ = [
    "Parser",
    "BaseParser",
    "ParserRegistry",
    "build_finding",
    "_now_iso",
    "AircrackParser",
    "AmassParser",
    "AquatoneParser",
    "ArachniParser",
    "ArjunParser",
    "AssetfinderParser",
    "AwsParser",
    "BanditParser",
    "BettercapParser",
    "BloodhoundParser",
    "BloodhoundPythonParser",
    "BurpsuiteParser",
    "CertipyParser",
    "CheckovParser",
    "CommixParser",
    "CorsyParser",
    "CrackmapexecParser",
    "CurlParser",
    "DalfoxParser",
    "DigParser",
    "DirbParser",
    "DirsearchParser",
    "DmitryParser",
    "DnsenumParser",
    "DnsmapParser",
    "DnsreconParser",
    "DnstwistParser",
    "DnsxParser",
    "Enum4linuxParser",
    "EttercapParser",
    "EvilWinrmParser",
    "ExiftoolParser",
    "FeroxbusterParser",
    "FfufParser",
    "FindomainParser",
    "FingerParser",
    "GauParser",
    "GitleaksParser",
    "GobusterParser",
    "GospiderParser",
    "GowitnessParser",
    "GrypeParser",
    "HakrawlerParser",
    "HashIdentifierParser",
    "HashcatParser",
    "HttpxParser",
    "HydraParser",
    "IkeScanParser",
    "ImpacketParser",
    "InteractshParser",
    "JohnParser",
    "JwtToolParser",
    "KatanaParser",
    "KerbruteParser",
    "KiterunnerParser",
    "KubectlParser",
    "KxssParser",
    "LdapsearchParser",
    "LynisParser",
    "MasscanParser",
    "MassdnsParser",
    "MetasploitParser",
    "MimikatzParser",
    "NaabuParser",
    "NetcatParser",
    "NiktoParser",
    "NmapParser",
    "NucleiParser",
    "ParamspiderParser",
    "ProwlerParser",
    "PypykatzParser",
    "ReconNgParser",
    "ResponderParser",
    "RustscanParser",
    "S3scannerParser",
    "ScoutsuiteParser",
    "SearchsploitParser",
    "SeatbeltParser",
    "SemgrepParser",
    "SharphoundParser",
    "SherlockParser",
    "ShodanParser",
    "ShufflednsParser",
    "SmbclientParser",
    "SmbmapParser",
    "SmtpUserEnumParser",
    "SqlmapParser",
    "SshAuditParser",
    "SslscanParser",
    "SslyzeParser",
    "SubfinderParser",
    "Sublist3rParser",
    "SyftParser",
    "TcpdumpParser",
    "TestsslParser",
    "TheharvesterParser",
    "TrivyParser",
    "TrufflehogParser",
    "VolatilityParser",
    "Wafw00fParser",
    "WapitiParser",
    "WaybackurlsParser",
    "WfuzzParser",
    "WgetParser",
    "WhatwebParser",
    "WhoisParser",
    "WpscanParser",
    "XsstrikeParser",
    "YaraParser",
    "ZaproxyParser",
    "ZgrabParser",
    "ZmapParser",
]
