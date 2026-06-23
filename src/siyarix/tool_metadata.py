# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static metadata for common security and utility tools.

Functions first consult the cyber_tools.json database, falling back
to the built-in static mappings for tools not yet in the database.
"""

from __future__ import annotations

from typing import Any

from .tool_models import RiskLevel, ToolCategory

_DB: dict[str, Any] | None = None


def _load_db() -> dict[str, Any]:
    global _DB
    if _DB is not None:
        return _DB
    try:
        import json
        from pathlib import Path

        p = Path(__file__).parent / "data" / "cyber_tools.json"
        if p.exists():
            _DB = json.loads(p.read_text())
        else:
            _DB = {}
    except Exception:
        _DB = {}
    return _DB


def _db_lookup(name: str) -> dict[str, Any]:
    db = _load_db()
    entry = db.get(name, {})
    if not entry:
        for tool_name, data in db.items():
            if name in data.get("aliases", []):
                return data
    return entry


def categorize_tool(name: str) -> ToolCategory:
    entry = _db_lookup(name)
    if entry:
        try:
            return ToolCategory(entry["category"])
        except ValueError:
            pass
    mapping = {
        "nmap": ToolCategory.RECON,
        "masscan": ToolCategory.RECON,
        "amass": ToolCategory.RECON,
        "subfinder": ToolCategory.RECON,
        "shodan": ToolCategory.RECON,
        "bettercap": ToolCategory.NETWORK,
        "ettercap": ToolCategory.NETWORK,
        "nikto": ToolCategory.SCANNING,
        "nuclei": ToolCategory.SCANNING,
        "wpscan": ToolCategory.SCANNING,
        "sqlmap": ToolCategory.SCANNING,
        "gobuster": ToolCategory.SCANNING,
        "ffuf": ToolCategory.SCANNING,
        "hydra": ToolCategory.EXPLOITATION,
        "hashcat": ToolCategory.CRYPTO,
        "john": ToolCategory.CRYPTO,
        "aircrack-ng": ToolCategory.NETWORK,
        "burpsuite": ToolCategory.WEB,
        "zaproxy": ToolCategory.WEB,
        "dig": ToolCategory.RECON,
        "whois": ToolCategory.RECON,
        "curl": ToolCategory.UTILITY,
        "whatweb": ToolCategory.WEB,
        "wget": ToolCategory.UTILITY,
        "graph_analyzer": ToolCategory.REPORTING,
        "threat_intel": ToolCategory.REPORTING,
    }
    return mapping.get(name, ToolCategory.UTILITY)


def risk_for_tool(name: str) -> RiskLevel:
    entry = _db_lookup(name)
    if entry:
        try:
            return RiskLevel(entry["risk_level"])
        except ValueError:
            pass
    high_risk = {"metasploit", "sqlmap", "hashcat", "hydra", "ettercap", "bettercap"}
    medium_risk = {"nmap", "nuclei", "nikto", "gobuster", "ffuf", "wpscan", "masscan"}
    if name in high_risk:
        return RiskLevel.HIGH
    if name in medium_risk:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def describe_tool(name: str) -> str:
    entry = _db_lookup(name)
    if entry and entry.get("description"):
        return entry["description"]
    descriptions = {
        "nmap": "Network port scanner and service detector",
        "nikto": "Web server vulnerability scanner",
        "nuclei": "Template-based vulnerability scanner",
        "gobuster": "Directory/file & DNS busting tool",
        "ffuf": "Fast web fuzzer",
        "hydra": "Network login brute-forcer",
        "masscan": "TCP port scanner at scale",
        "amass": "Attack surface mapping and asset discovery",
        "subfinder": "Subdomain discovery tool",
        "wpscan": "WordPress security scanner",
        "sqlmap": "SQL injection detection and exploitation",
        "shodan": "Internet-connected device search engine",
        "bettercap": "Network attack and monitoring framework",
        "ettercap": "ARP poisoning and MITM attacks",
        "aircrack-ng": "WiFi network security assessment",
        "hashcat": "Password hash recovery",
        "john": "Password cracker",
        "burpsuite": "Web application security testing",
        "zaproxy": "Web application security scanner",
        "dig": "DNS record query and enumeration tool",
        "whois": "Domain registration and WHOIS lookup",
        "curl": "HTTP client for headers and response analysis",
        "whatweb": "Web technology stack fingerprinting",
        "wget": "HTTP/HTTPS file download and mirroring",
        "graph_analyzer": "Analyze attack paths and blast radius from the knowledge graph",
        "threat_intel": "Query CVE and MITRE ATT&CK intelligence databases locally",
    }
    return descriptions.get(name, name)


def tags_for_tool(name: str) -> list[str]:
    entry = _db_lookup(name)
    if entry and entry.get("tags"):
        return entry["tags"]
    tag_map = {
        "nmap": ["port-scan", "network", "service-detection"],
        "nikto": ["web", "vulnerability", "server"],
        "nuclei": ["vulnerability", "template", "http"],
        "gobuster": ["directory", "brute-force", "http"],
        "ffuf": ["fuzzer", "directory", "http"],
        "hydra": ["brute-force", "login", "network"],
        "masscan": ["port-scan", "fast", "network"],
        "amass": ["recon", "subdomain", "osint"],
        "subfinder": ["recon", "subdomain", "passive"],
        "wpscan": ["cms", "wordpress", "vulnerability"],
        "sqlmap": ["sql-injection", "database", "exploit"],
        "shodan": ["osint", "iot", "search"],
        "bettercap": ["mitm", "arp", "sniffing"],
        "ettercap": ["mitm", "arp", "poisoning"],
        "aircrack-ng": ["wifi", "wpa", "capture"],
        "hashcat": ["password", "hash", "gpu"],
        "john": ["password", "cracker", "cpu"],
        "burpsuite": ["web", "proxy", "scanner"],
        "zaproxy": ["web", "scanner", "dast"],
        "dig": ["dns", "recon", "network"],
        "whois": ["domain", "recon", "osint"],
        "curl": ["http", "client", "request"],
        "whatweb": ["fingerprint", "web", "recon"],
        "wget": ["http", "download", "client"],
        "graph_analyzer": ["graph", "analysis", "pathfinding", "offline"],
        "threat_intel": ["cve", "mitre", "intelligence", "offline"],
    }

    return tag_map.get(name, [name])


def personas_for_tool(name: str) -> list[str]:
    entry = _db_lookup(name)
    if entry and entry.get("personas"):
        return entry["personas"]
    default_map = {
        "nmap": ["pentester", "redteam", "blueteam", "devsecops"],
        "nuclei": ["pentester", "redteam", "blueteam", "devsecops"],
    }
    return default_map.get(name, [])


__all__ = [
    "categorize_tool",
    "risk_for_tool",
    "describe_tool",
    "tags_for_tool",
    "personas_for_tool",
]
