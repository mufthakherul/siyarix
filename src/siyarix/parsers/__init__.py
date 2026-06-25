# SPDX-License-Identifier: AGPL-3.0-or-later

"""Parser protocol, base utilities, and ParserRegistry for all tool output parsers.

All parsers implement the ``Parser`` protocol and should use the
``BaseParser`` mixin for consistent error handling, logging, and
finding field population.

The ``ParserRegistry`` auto-discovers all parsers in this module and
provides tool → parser lookup for registry-mode execution.
"""

from __future__ import annotations

import importlib
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
            def parse(self, output: str) -> list[dict[str, Any]]: ...
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
        self,
        tool_name: str,
        output: str,
        version: str | None = None,
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
        _lazy_import_parsers()
        for name, obj in list(globals().items()):
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

            instance = obj()
            if isinstance(instance, Parser):
                version = getattr(instance, "version", None)

                # Smart discovery: Use explicitly defined tool aliases if present
                tool_names = []
                if hasattr(obj, "TOOL_ALIASES") and obj.TOOL_ALIASES:
                    aliases = obj.TOOL_ALIASES
                    if isinstance(aliases, list):
                        tool_names.extend(aliases)
                    elif isinstance(aliases, str):
                        tool_names.append(aliases)
                elif hasattr(obj, "TOOL_NAME") and obj.TOOL_NAME:
                    tool_names.append(obj.TOOL_NAME)
                else:
                    # Fallback to smart class name parsing and advanced overrides
                    tool_names.extend(_class_to_tool_names(name))

                # Register under all resolved aliases
                for tool_name in set(tool_names):
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


def _class_to_tool_names(class_name: str) -> list[str]:
    """Smartly convert parser class names to all probable tool aliases.
    E.g. ``AircrackParser`` → ``["aircrack-ng", "aircrack"]``.
    """
    stem = class_name.removesuffix("Parser")

    result = []
    for i, ch in enumerate(stem):
        if ch.isupper() and i > 0:
            result.append("-")
        result.append(ch.lower())

    base_name = "".join(result)
    names = [base_name]

    # Advanced intelligence: Map known mismatches and add common alias variations
    OVERRIDES = {
        "aircrack": ["aircrack-ng", "aircrack"],
        "netcat": ["nc", "netcat", "ncat"],
        "searchsploit": ["searchsploit", "exploitdb"],
        "waybackurls": ["waybackurls", "gau"],
        "finger": ["finger", "finger-enum"],
        "kiterunner": ["kr", "kiterunner"],
        "kxss": ["kxss", "ss"],
        "naabu": ["naabu", "port-scanner"],
        "pypykatz": ["pypykatz"],
        "smbclient": ["smbclient", "smb"],
        "hash-identifier": ["hash-identifier", "hashid"],
        "zmap": ["zmap", "zgrab"],
        "bloodhound-python": ["bloodhound-python"],
        "ike-scan": ["ike-scan", "ikescan"],
        "wfuzz": ["wfuzz", "fuzzer"],
    }

    if base_name in OVERRIDES:
        names.extend(OVERRIDES[base_name])

    # Also add standard variations (e.g. if name is foo-bar, also add foobar)
    if "-" in base_name:
        names.append(base_name.replace("-", ""))
        names.append(base_name.replace("-", "_"))

    return list(set(names))


# ---------------------------------------------------------------------------
# Lazy parser module loading — parsers are imported on first discover() call
# ---------------------------------------------------------------------------

_PARSER_MODULES: list[str] = [
    "aircrack_parser",
    "amass_parser",
    "aquatone_parser",
    "arachni_parser",
    "arjun_parser",
    "assetfinder_parser",
    "aws_parser",
    "bandit_parser",
    "bettercap_parser",
    "bloodhound_parser",
    "bloodhound_python_parser",
    "burpsuite_parser",
    "certipy_parser",
    "checkov_parser",
    "commix_parser",
    "corsy_parser",
    "crackmapexec_parser",
    "curl_parser",
    "dalfox_parser",
    "dig_parser",
    "dirb_parser",
    "dirsearch_parser",
    "dmitry_parser",
    "dnsenum_parser",
    "dnsmap_parser",
    "dnsrecon_parser",
    "dnstwist_parser",
    "dnsx_parser",
    "enum4linux_parser",
    "ettercap_parser",
    "evil_winrm_parser",
    "exiftool_parser",
    "feroxbuster_parser",
    "ffuf_parser",
    "findomain_parser",
    "finger_parser",
    "gau_parser",
    "gitleaks_parser",
    "gobuster_parser",
    "gospider_parser",
    "gowitness_parser",
    "grype_parser",
    "hakrawler_parser",
    "hash_identifier_parser",
    "hashcat_parser",
    "httpx_parser",
    "hydra_parser",
    "ike_scan_parser",
    "impacket_parser",
    "interactsh_parser",
    "john_parser",
    "jwt_tool_parser",
    "katana_parser",
    "kerbrute_parser",
    "kiterunner_parser",
    "kubectl_parser",
    "kxss_parser",
    "ldapsearch_parser",
    "lynis_parser",
    "masscan_parser",
    "massdns_parser",
    "metasploit_parser",
    "mimikatz_parser",
    "naabu_parser",
    "netcat_parser",
    "nikto_parser",
    "nmap_parser",
    "nuclei_parser",
    "paramspider_parser",
    "prowler_parser",
    "pypykatz_parser",
    "recon_ng_parser",
    "responder_parser",
    "rustscan_parser",
    "s3scanner_parser",
    "scoutsuite_parser",
    "searchsploit_parser",
    "seatbelt_parser",
    "semgrep_parser",
    "sharphound_parser",
    "sherlock_parser",
    "shodan_parser",
    "shuffledns_parser",
    "smbclient_parser",
    "smbmap_parser",
    "smtp_user_enum_parser",
    "sqlmap_parser",
    "ssh_audit_parser",
    "sslscan_parser",
    "sslyze_parser",
    "subfinder_parser",
    "sublist3r_parser",
    "syft_parser",
    "tcpdump_parser",
    "testssl_parser",
    "theharvester_parser",
    "trivy_parser",
    "trufflehog_parser",
    "volatility_parser",
    "wafw00f_parser",
    "wapiti_parser",
    "waybackurls_parser",
    "wfuzz_parser",
    "wget_parser",
    "whatweb_parser",
    "whois_parser",
    "wpscan_parser",
    "xsstrike_parser",
    "yara_parser",
    "zaproxy_parser",
    "zgrab_parser",
    "zmap_parser",
]

_parsers_loaded = False


def _lazy_import_parsers() -> None:
    global _parsers_loaded
    if _parsers_loaded:
        return
    _parsers_loaded = True
    for mod_name in _PARSER_MODULES:
        mod = importlib.import_module(f".{mod_name}", __package__)
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and attr_name.endswith("Parser")
                and attr_name not in ("BaseParser", "Parser")
            ):
                globals().setdefault(attr_name, obj)


__all__ = [
    "AircrackParser",
    "AmassParser",
    "AquatoneParser",
    "ArachniParser",
    "ArjunParser",
    "AssetfinderParser",
    "AwsParser",
    "BanditParser",
    "BaseParser",
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
    "Parser",
    "ParserRegistry",
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
    "_now_iso",
    "build_finding",
]
