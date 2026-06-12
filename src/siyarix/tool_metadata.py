# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static metadata for common security and utility tools."""

from __future__ import annotations

from .tool_models import RiskLevel, ToolCategory


def categorize_tool(name: str) -> ToolCategory:
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
    }
    return mapping.get(name, ToolCategory.UTILITY)


def risk_for_tool(name: str) -> RiskLevel:
    high_risk = {"metasploit", "sqlmap", "hashcat", "hydra", "ettercap", "bettercap"}
    medium_risk = {"nmap", "nuclei", "nikto", "gobuster", "ffuf", "wpscan", "masscan"}
    if name in high_risk:
        return RiskLevel.HIGH
    if name in medium_risk:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def describe_tool(name: str) -> str:
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
    }
    return descriptions.get(name, name)


def tags_for_tool(name: str) -> list[str]:
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
        "john": ["password", "hash", "crack"],
        "burpsuite": ["proxy", "web", "scan"],
        "zaproxy": ["proxy", "web", "scan"],
        "dig": ["dns", "recon", "enumeration"],
        "whois": ["osint", "recon", "registration"],
        "curl": ["http", "client", "headers"],
        "whatweb": ["web", "fingerprint", "technology"],
        "wget": ["http", "download", "client"],
    }
    return tag_map.get(name, [name])

__all__ = [
    "categorize_tool",
    "risk_for_tool",
    "describe_tool",
    "tags_for_tool",
]
