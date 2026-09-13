# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enterprise Command & Intent Analyzer for Cyber Security Operations.

Provides:
- Multi-dimensional intent classification (recon, vuln scan, exploitation, reporting, etc.)
- Strict target entity extraction and normalization
- OPSEC risk assessment & noise level evaluation
- Platform-aware command sanitization and tuning
"""

from __future__ import annotations

import logging
import platform as _platform
import re
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse

from .nlp_engine import NaturalLanguageParser

logger = logging.getLogger(__name__)


class CommandIntent(StrEnum):
    """Classified intent of a cyber operations instruction."""

    RECONNAISSANCE = "reconnaissance"
    PORT_SCAN = "port_scan"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    DEFENSIVE_AUDIT = "defensive_audit"
    REPORTING = "reporting"
    CONVERSATIONAL = "conversational"
    UNKNOWN = "unknown"


class OpsecRisk(StrEnum):
    """Operational security risk rating for network and host activities."""

    PASSIVE = "passive"  # Zero or minimal direct packet contact
    LOW_NOISE = "low_noise"  # Single-target light probe
    ACTIVE_SCAN = "active_scan"  # Comprehensive port/service audit
    INTRUSIVE = "intrusive"  # High-rate fuzzing or payload injection
    HIGH_RISK = "high_risk"  # Exploit payloads or potentially destabilizing checks


@dataclass
class TargetEntity:
    """Normalized target identified in an instruction."""

    raw: str
    target_type: str  # 'ipv4', 'ipv6', 'cidr', 'domain', 'url'
    normalized: str
    host: str = ""
    port: int | None = None
    path: str = ""


@dataclass
class CommandAnalysis:
    """Complete pre-execution analysis of a user command or instruction."""

    raw_text: str
    intent: CommandIntent
    opsec_risk: OpsecRisk
    risk_score: int  # 0 to 10
    targets: list[TargetEntity] = field(default_factory=list)
    primary_target: str = ""
    suggested_tools: list[str] = field(default_factory=list)
    opsec_warnings: list[str] = field(default_factory=list)
    platform_notes: list[str] = field(default_factory=list)
    is_safe: bool = True


class CommandAnalyzer:
    """Enterprise-grade analyzer for security operator instructions."""

    def __init__(self, nlp_parser: NaturalLanguageParser | None = None) -> None:
        self._nlp = nlp_parser or NaturalLanguageParser()

    def analyze(self, text: str, default_target: str = "") -> CommandAnalysis:
        """Analyze natural language instruction for intent, targets, and OPSEC risk."""
        text_clean = text.strip()
        text_lower = text_clean.lower()

        # 1. Target Extraction & Normalization
        targets = self._extract_targets(text_clean)
        if not targets and default_target:
            targets = self._extract_targets(default_target)

        primary_target = targets[0].normalized if targets else default_target

        # 2. Intent Classification
        intent = self._classify_intent(text_lower)

        # 3. OPSEC Risk Assessment
        opsec_risk, risk_score, warnings = self._assess_opsec_risk(text_lower, intent)

        # 4. Tool Suggestions & Platform Sanitization
        suggested_tools = self._suggest_tools(intent, text_lower)
        platform_notes = self._check_platform(text_lower)

        return CommandAnalysis(
            raw_text=text_clean,
            intent=intent,
            opsec_risk=opsec_risk,
            risk_score=risk_score,
            targets=targets,
            primary_target=primary_target,
            suggested_tools=suggested_tools,
            opsec_warnings=warnings,
            platform_notes=platform_notes,
            is_safe=risk_score < 9,
        )

    def _extract_targets(self, text: str) -> list[TargetEntity]:
        """Extract and normalize all IP addresses, domains, and URLs."""
        results: list[TargetEntity] = []
        seen: set[str] = set()

        # URL matching
        urls = re.findall(r"https?://[^\s/$.?#].[^\s]*", text, re.IGNORECASE)
        for u in urls:
            u_clean = u.rstrip(".,;)'\"")
            if u_clean.lower() in seen:
                continue
            seen.add(u_clean.lower())
            parsed = urlparse(u_clean)
            results.append(
                TargetEntity(
                    raw=u_clean,
                    target_type="url",
                    normalized=u_clean,
                    host=parsed.hostname or "",
                    port=parsed.port,
                    path=parsed.path or "/",
                )
            )

        # CIDR matching
        cidrs = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text)
        for c in cidrs:
            if c in seen:
                continue
            seen.add(c)
            results.append(
                TargetEntity(
                    raw=c,
                    target_type="cidr",
                    normalized=c,
                    host=c,
                )
            )

        # IPv4 matching (excluding already matched URLs/CIDRs)
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        for ip in ips:
            if any(ip in u for u in urls) or any(ip in c for c in cidrs) or ip in seen:
                continue
            # Validate octet ranges
            octets = [int(o) for o in ip.split(".")]
            if all(0 <= o <= 255 for o in octets):
                seen.add(ip)
                results.append(
                    TargetEntity(
                        raw=ip,
                        target_type="ipv4",
                        normalized=ip,
                        host=ip,
                    )
                )

        # Domains (e.g. example.com, target.corp)
        domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
        for d in domains:
            d_clean = d.lower()
            if any(d_clean in u.lower() for u in urls) or d_clean in seen:
                continue
            # Exclude common command extensions like .py, .sh, .txt
            if d_clean.endswith(
                (".py", ".sh", ".txt", ".json", ".yaml", ".md", ".log", ".exe", ".bin")
            ):
                continue
            seen.add(d_clean)
            results.append(
                TargetEntity(
                    raw=d,
                    target_type="domain",
                    normalized=d_clean,
                    host=d_clean,
                )
            )

        return results

    def _classify_intent(self, text: str) -> CommandIntent:
        """Classify security instruction into primary intent category."""
        # Conversational
        if re.match(
            r"^(hi|hello|hey|good\s+(morning|afternoon|evening)|who are you|what can you do|help)\b",
            text,
        ):
            return CommandIntent.CONVERSATIONAL

        # Reporting / summary
        if any(
            kw in text
            for kw in ("report", "summarize", "summary", "executive summary", "export findings")
        ):
            return CommandIntent.REPORTING

        # Exploitation
        if any(
            kw in text
            for kw in (
                "exploit",
                "payload",
                "shellcode",
                "reverse shell",
                "metasploit",
                "pwn",
                "bypass auth",
            )
        ):
            return CommandIntent.EXPLOITATION

        # Post-exploitation
        if any(
            kw in text
            for kw in (
                "privesc",
                "privilege escalation",
                "dump hashes",
                "mimikatz",
                "lateral movement",
                "persistence",
            )
        ):
            return CommandIntent.POST_EXPLOITATION

        # Vulnerability assessment
        if any(
            kw in text
            for kw in ("vuln scan", "vulnerabilit", "cve-", "sqlmap", "nikto", "nuclei", "zap")
        ):
            return CommandIntent.VULNERABILITY_ASSESSMENT

        # Port scanning
        if any(
            kw in text
            for kw in ("port scan", "nmap", "scan ports", "open ports", "service scan", "syn scan")
        ):
            return CommandIntent.PORT_SCAN

        # Defensive / compliance / audit
        if any(
            kw in text
            for kw in (
                "compliance",
                "cis benchmark",
                "firewall",
                "hardening",
                "audit config",
                "siem",
            )
        ):
            return CommandIntent.DEFENSIVE_AUDIT

        # Reconnaissance
        if any(
            kw in text
            for kw in (
                "whois",
                "dns",
                "subdomain",
                "osint",
                "recon",
                "enum",
                "shodan",
                "theharvester",
            )
        ):
            return CommandIntent.RECONNAISSANCE

        # Default fallback
        if any(kw in text for kw in ("scan", "check", "inspect", "test")):
            return CommandIntent.RECONNAISSANCE

        return CommandIntent.UNKNOWN

    def _assess_opsec_risk(
        self, text: str, intent: CommandIntent
    ) -> tuple[OpsecRisk, int, list[str]]:
        """Assess OPSEC noise level and operational risk score (0 to 10)."""
        warnings: list[str] = []

        if intent == CommandIntent.CONVERSATIONAL or intent == CommandIntent.REPORTING:
            return OpsecRisk.PASSIVE, 0, []

        if intent == CommandIntent.EXPLOITATION:
            warnings.append(
                "Exploitation activities carry high detection risk and potential host instability."
            )
            return OpsecRisk.HIGH_RISK, 8, warnings

        if intent == CommandIntent.POST_EXPLOITATION:
            warnings.append(
                "Post-exploitation activities generate significant endpoint telemetry (EDR/SIEM)."
            )
            return OpsecRisk.HIGH_RISK, 9, warnings

        # Fuzzing or high-thread tools
        if any(kw in text for kw in ("hydra", "brute", "fuzz", "gobuster", "ffuf", "sqlmap")):
            warnings.append(
                "High request rate tools generate noticeable network noise and rate-limiting."
            )
            return OpsecRisk.INTRUSIVE, 6, warnings

        if intent == CommandIntent.VULNERABILITY_ASSESSMENT:
            warnings.append("Vulnerability scanning triggers signature-based IDS/IPS alerts.")
            return OpsecRisk.ACTIVE_SCAN, 5, warnings

        if intent == CommandIntent.PORT_SCAN:
            return OpsecRisk.ACTIVE_SCAN, 4, warnings

        if intent == CommandIntent.RECONNAISSANCE:
            if any(kw in text for kw in ("shodan", "whois", "censys", "dns")):
                return OpsecRisk.PASSIVE, 1, []
            return OpsecRisk.LOW_NOISE, 2, []

        return OpsecRisk.LOW_NOISE, 2, []

    def _suggest_tools(self, intent: CommandIntent, text: str) -> list[str]:
        """Suggest optimal security tools based on classified intent."""
        tool_map: dict[CommandIntent, list[str]] = {
            CommandIntent.RECONNAISSANCE: ["whois", "nslookup", "dig", "sublist3r", "theHarvester"],
            CommandIntent.PORT_SCAN: ["nmap", "masscan", "rustscan", "nc"],
            CommandIntent.VULNERABILITY_ASSESSMENT: ["nuclei", "nikto", "sqlmap", "trivy"],
            CommandIntent.EXPLOITATION: ["msfconsole", "searchsploit", "curl"],
            CommandIntent.DEFENSIVE_AUDIT: ["checkov", "semgrep", "trivy", "lynis"],
            CommandIntent.REPORTING: ["report_generator"],
            CommandIntent.CONVERSATIONAL: [],
            CommandIntent.POST_EXPLOITATION: [],
            CommandIntent.UNKNOWN: ["nmap", "curl"],
        }
        return tool_map.get(intent, ["nmap"])

    def _check_platform(self, text: str) -> list[str]:
        """Check for platform incompatibilities."""
        notes: list[str] = []
        is_windows = _platform.system() == "Windows"
        if is_windows:
            if "-ss" in text or "syn scan" in text:
                notes.append(
                    "On Windows, raw SYN scans (-sS) require admin/WinPcap; recommend TCP connect scan (-sT)."
                )
            if "sudo" in text:
                notes.append("Unix 'sudo' command is not supported on Windows environments.")
        return notes


__all__ = [
    "CommandAnalyzer",
    "CommandIntent",
    "OpsecRisk",
    "TargetEntity",
    "CommandAnalysis",
]
