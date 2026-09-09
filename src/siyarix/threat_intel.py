# SPDX-License-Identifier: AGPL-3.0-or-later
"""Threat Intelligence Integration for Siyarix.

This module provides real-time lookups to threat intelligence feeds
such as AlienVault OTX, Shodan, and NVD CVE database.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


class ThreatIntelProvider:
    """Base class for Threat Intelligence integrations."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key


class AlienVaultOTX(ThreatIntelProvider):
    """AlienVault Open Threat Exchange integration."""

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self) -> None:
        super().__init__(api_key=os.getenv("ALIENVAULT_API_KEY"))

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup an IP address in AlienVault OTX."""
        url = f"{self.BASE_URL}/IPv4/{ip}/general"
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            _parsed = urllib.parse.urlparse(url)
            if _parsed.scheme not in ("http", "https"):
                raise ValueError(f"Disallowed URL scheme: {_parsed.scheme!r}")
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310 # noqa: ASYNC210
                data = json.loads(response.read().decode())
                return {
                    "source": "AlienVault OTX",
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                }
        except urllib.error.URLError as e:
            logger.warning("AlienVault lookup failed for %s: %s", ip, e)
            return {"source": "AlienVault OTX", "error": str(e)}


class NVDDatabase(ThreatIntelProvider):
    """National Vulnerability Database (NVD) integration."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        """Fetch CVE details from NVD."""
        url = f"{self.BASE_URL}?cveId={cve_id}"
        try:
            _parsed = urllib.parse.urlparse(url)
            if _parsed.scheme not in ("http", "https"):
                raise ValueError(f"Disallowed URL scheme: {_parsed.scheme!r}")
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310 # noqa: ASYNC210
                data = json.loads(response.read().decode())
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    base_score = None
                    if "cvssMetricV31" in metrics:
                        base_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    return {
                        "source": "NVD",
                        "id": cve_id,
                        "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                        "base_score": base_score,
                    }
                return {"source": "NVD", "error": "CVE not found"}
        except urllib.error.URLError as e:
            logger.warning("NVD lookup failed for %s: %s", cve_id, e)
            return {"source": "NVD", "error": str(e)}


class ThreatIntelManager:
    """Facade for querying all configured threat intel providers."""

    def __init__(self) -> None:
        self.alienvault = AlienVaultOTX()
        self.nvd = NVDDatabase()

    async def analyze_target(self, target: str) -> dict[str, Any]:
        """Perform a comprehensive threat intel sweep on a target."""
        # Simple heuristic to determine if target is IP or CVE
        if target.startswith("CVE-"):
            return await self.nvd.lookup_cve(target)
        else:
            # Assuming IP for now
            return await self.alienvault.lookup_ip(target)


class MITREAttackDB:
    """Offline database for MITRE ATT&CK Enterprise tactics and techniques."""

    TACTICS: ClassVar[dict[str, str]] = {
        "TA0043": "Reconnaissance",
        "TA0042": "Resource Development",
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0011": "Command and Control",
        "TA0010": "Exfiltration",
        "TA0040": "Impact",
    }

    TECHNIQUES: ClassVar[dict[str, dict[str, Any]]] = {
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands, scripts, or binaries.",
            "url": "https://attack.mitre.org/techniques/T1059/",
            "subtechniques": [
                "T1059.001 (PowerShell)",
                "T1059.003 (Windows Command Shell)",
                "T1059.004 (Unix Shell)",
                "T1059.006 (Python)",
            ],
        },
        "T1566": {
            "name": "Phishing",
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "description": "Adversaries may send phishing messages to gain access to victim systems via spearphishing emails, attachments, or links.",
            "url": "https://attack.mitre.org/techniques/T1566/",
            "subtechniques": [
                "T1566.001 (Spearphishing Attachment)",
                "T1566.002 (Spearphishing Link)",
            ],
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, system, or service bugs.",
            "url": "https://attack.mitre.org/techniques/T1190/",
            "subtechniques": [],
        },
        "T1547": {
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
            "url": "https://attack.mitre.org/techniques/T1547/",
            "subtechniques": ["T1547.001 (Registry Run Keys / Startup Folder)"],
        },
        "T1053": {
            "name": "Scheduled Task/Job",
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
            "url": "https://attack.mitre.org/techniques/T1053/",
            "subtechniques": ["T1053.003 (Cron)", "T1053.005 (Scheduled Task)"],
        },
        "T1068": {
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
            "url": "https://attack.mitre.org/techniques/T1068/",
            "subtechniques": [],
        },
        "T1055": {
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
            "url": "https://attack.mitre.org/techniques/T1055/",
            "subtechniques": [
                "T1055.001 (Dynamic-link Library Injection)",
                "T1055.012 (Process Hollowing)",
            ],
        },
        "T1027": {
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
            "url": "https://attack.mitre.org/techniques/T1027/",
            "subtechniques": ["T1027.002 (Software Packing)", "T1027.013 (Encrypted Payload)"],
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
            "url": "https://attack.mitre.org/techniques/T1003/",
            "subtechniques": [
                "T1003.001 (LSASS Memory)",
                "T1003.002 (Security Account Manager)",
            ],
        },
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
            "url": "https://attack.mitre.org/techniques/T1110/",
            "subtechniques": ["T1110.001 (Password Guessing)", "T1110.003 (Password Spraying)"],
        },
        "T1046": {
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "description": "Adversaries may attempt to get a listing of services running on hosts or a network.",
            "url": "https://attack.mitre.org/techniques/T1046/",
            "subtechniques": [],
        },
        "T1082": {
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
            "url": "https://attack.mitre.org/techniques/T1082/",
            "subtechniques": [],
        },
        "T1021": {
            "name": "Remote Services",
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.",
            "url": "https://attack.mitre.org/techniques/T1021/",
            "subtechniques": [
                "T1021.001 (Remote Desktop Protocol)",
                "T1021.002 (SMB/Windows Admin Shares)",
                "T1021.004 (SSH)",
            ],
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
            "url": "https://attack.mitre.org/techniques/T1071/",
            "subtechniques": ["T1071.001 (Web Protocols)", "T1071.004 (DNS)"],
        },
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "tactic_id": "TA0010",
            "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "subtechniques": [],
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "description": "Adversaries may encrypt data on target systems or large numbers of systems in a network to interrupt availability to system and network resources.",
            "url": "https://attack.mitre.org/techniques/T1486/",
            "subtechniques": [],
        },
        "T1499": {
            "name": "Endpoint Denial of Service",
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of targeted services.",
            "url": "https://attack.mitre.org/techniques/T1499/",
            "subtechniques": [],
        },
        "T1595": {
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
            "url": "https://attack.mitre.org/techniques/T1595/",
            "subtechniques": [
                "T1595.001 (Scanning IP Blocks)",
                "T1595.002 (Vulnerability Scanning)",
            ],
        },
    }

    def __init__(self) -> None:
        pass

    def query_technique(self, technique_id: str) -> dict[str, Any]:
        """Look up a technique by ID (e.g. T1059 or T1059.001)."""
        tid = technique_id.strip().upper()
        if tid in self.TECHNIQUES:
            data = dict(self.TECHNIQUES[tid])
            data["id"] = tid
            return data
        base_id = tid.split(".")[0]
        if base_id in self.TECHNIQUES:
            data = dict(self.TECHNIQUES[base_id])
            data["id"] = tid
            return data
        return {}

    def search(self, query: str) -> list[dict[str, str]]:
        """Search techniques by ID, name, tactic, or description."""
        q = query.strip().lower()
        if not q:
            return []
        matches: list[dict[str, str]] = []
        for tid, info in self.TECHNIQUES.items():
            if (
                q in tid.lower()
                or q in str(info["name"]).lower()
                or q in str(info["tactic"]).lower()
                or q in str(info.get("description", "")).lower()
            ):
                matches.append(
                    {
                        "id": tid,
                        "name": str(info["name"]),
                        "tactic": str(info["tactic"]),
                        "description": str(info.get("description", "")),
                    }
                )
        return matches

    def list_techniques(self) -> list[dict[str, str]]:
        """Return all registered techniques."""
        return [
            {
                "id": tid,
                "name": str(info["name"]),
                "tactic": str(info["tactic"]),
                "description": str(info.get("description", "")),
            }
            for tid, info in self.TECHNIQUES.items()
        ]

    def list_tactics(self) -> list[dict[str, str]]:
        """Return all MITRE ATT&CK enterprise tactics."""
        return [{"id": tid, "name": name} for tid, name in self.TACTICS.items()]

    def map_finding(self, text: str) -> list[dict[str, Any]]:
        """Map text or finding keyword to likely MITRE techniques."""
        t = text.lower()
        results: list[dict[str, Any]] = []
        mapping_rules = [
            (
                [
                    "sql injection",
                    "sqli",
                    "cve-",
                    "rce",
                    "remote code execution",
                    "deserialization",
                ],
                "T1190",
            ),
            (["scan", "nmap", "port", "recon", "discovery"], "T1046"),
            (["brute", "password", "hydra", "credential stuffing", "spray"], "T1110"),
            (["powershell", "bash", "cmd", "shell", "exec", "script"], "T1059"),
            (["phish", "email", "attachment"], "T1566"),
            (["dump", "lsass", "sam", "shadow"], "T1003"),
            (["privilege", "privesc", "escalat"], "T1068"),
            (["encrypt", "ransomware", "ransom"], "T1486"),
            (["dos", "denial of service"], "T1499"),
            (["rdp", "ssh", "smb", "lateral"], "T1021"),
        ]
        seen_ids = set()
        for keywords, tech_id in mapping_rules:
            if any(k in t for k in keywords) and tech_id not in seen_ids:
                seen_ids.add(tech_id)
                tech = self.query_technique(tech_id)
                if tech:
                    results.append(tech)
        return results


class ThreatIntelFeed:
    """Offline and multi-feed threat intelligence aggregator."""

    DEFAULT_FEEDS: ClassVar[list[dict[str, Any]]] = [
        {
            "name": "AlienVault OTX",
            "type": "reputation",
            "description": "Open Threat Exchange crowdsourced IP/domain pulses",
            "status": "active",
        },
        {
            "name": "National Vulnerability Database (NVD)",
            "type": "vulnerability",
            "description": "NIST official repository of standards-based vulnerability data",
            "status": "active",
        },
        {
            "name": "CISA Known Exploited Vulnerabilities (KEV)",
            "type": "catalog",
            "description": "Catalog of vulnerabilities that have been exploited in the wild",
            "status": "integrated",
        },
        {
            "name": "MITRE ATT&CK Enterprise",
            "type": "knowledge_base",
            "description": "Curated knowledge base of adversary tactics and techniques",
            "status": "active",
        },
    ]

    KNOWN_CVES: ClassVar[dict[str, dict[str, Any]]] = {
        "CVE-2021-44228": {
            "id": "CVE-2021-44228",
            "name": "Log4Shell",
            "description": "Apache Log4j2 JNDI remote code execution vulnerability",
            "base_score": 10.0,
            "severity": "CRITICAL",
            "mitre_technique": "T1190",
        },
        "CVE-2023-34362": {
            "id": "CVE-2023-34362",
            "name": "MOVEit Transfer SQLi",
            "description": "MOVEit Transfer web application SQL injection resulting in RCE",
            "base_score": 9.8,
            "severity": "CRITICAL",
            "mitre_technique": "T1190",
        },
        "CVE-2024-21413": {
            "id": "CVE-2024-21413",
            "name": "Microsoft Outlook RCE #MonikerLink",
            "description": "Microsoft Outlook Remote Code Execution Vulnerability",
            "base_score": 9.8,
            "severity": "CRITICAL",
            "mitre_technique": "T1566",
        },
        "CVE-2024-3094": {
            "id": "CVE-2024-3094",
            "name": "XZ Utils Backdoor",
            "description": "Malicious code injected into xz/liblzma upstream releases allowing unauthorized SSH authentication bypass",
            "base_score": 10.0,
            "severity": "CRITICAL",
            "mitre_technique": "T1199",
        },
    }

    def __init__(self) -> None:
        self._custom_indicators: list[dict[str, Any]] = []

    def query_cve(self, cve_id: str) -> dict[str, Any]:
        """Look up CVE in offline curated database."""
        cid = cve_id.strip().upper()
        if cid in self.KNOWN_CVES:
            return dict(self.KNOWN_CVES[cid])
        return {}

    def search(self, target: str) -> list[dict[str, Any]]:
        """Search feeds and indicators for target IP, domain, CVE, or keyword."""
        q = target.strip().lower()
        if not q:
            return []
        matches: list[dict[str, Any]] = []
        for cid, cve_info in self.KNOWN_CVES.items():
            if (
                q in cid.lower()
                or q in cve_info["name"].lower()
                or q in cve_info["description"].lower()
            ):
                matches.append(dict(cve_info))
        for ind in self._custom_indicators:
            if q in ind.get("value", "").lower() or q in ind.get("description", "").lower():
                matches.append(dict(ind))
        return matches

    def list_feeds(self) -> list[dict[str, Any]]:
        """List all available threat intel feeds."""
        return [dict(f) for f in self.DEFAULT_FEEDS]

    def add_indicator(
        self,
        indicator_type: str,
        value: str,
        severity: str = "medium",
        description: str = "",
    ) -> None:
        """Add a custom observable indicator to local feed cache."""
        self._custom_indicators.append(
            {
                "type": indicator_type,
                "value": value,
                "severity": severity,
                "description": description,
            }
        )


# Global singleton
intel_manager = ThreatIntelManager()
