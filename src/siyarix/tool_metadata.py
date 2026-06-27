# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static metadata for common security and utility tools.

Functions first consult the cyber_tools.json database, falling back
to the built-in static mappings for tools not yet in the database.
"""

from __future__ import annotations

from typing import Any, cast

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
                return cast("dict[str, Any]", data)
    return cast("dict[str, Any]", entry)


def categorize_tool(name: str) -> ToolCategory:
    entry = _db_lookup(name)
    if entry:
        try:
            return ToolCategory(entry["category"])
        except ValueError:
            pass
    mapping = {
        # Port scanning / recon
        "nmap": ToolCategory.RECON,
        "masscan": ToolCategory.RECON,
        "rustscan": ToolCategory.RECON,
        "naabu": ToolCategory.RECON,
        "amass": ToolCategory.RECON,
        "subfinder": ToolCategory.RECON,
        "shodan": ToolCategory.RECON,
        # Network tools
        "bettercap": ToolCategory.NETWORK,
        "ettercap": ToolCategory.NETWORK,
        "aircrack-ng": ToolCategory.NETWORK,
        "responder": ToolCategory.NETWORK,
        "crackmapexec": ToolCategory.NETWORK,
        "impacket": ToolCategory.NETWORK,
        "smbmap": ToolCategory.NETWORK,
        "enum4linux": ToolCategory.NETWORK,
        # Vulnerability scanning
        "nikto": ToolCategory.SCANNING,
        "nuclei": ToolCategory.SCANNING,
        "wpscan": ToolCategory.SCANNING,
        "wapiti": ToolCategory.SCANNING,
        "arachni": ToolCategory.SCANNING,
        # Web fuzzing / enumeration
        "gobuster": ToolCategory.SCANNING,
        "ffuf": ToolCategory.SCANNING,
        "dirb": ToolCategory.SCANNING,
        "dirsearch": ToolCategory.SCANNING,
        "feroxbuster": ToolCategory.SCANNING,
        # Exploitation
        "sqlmap": ToolCategory.SCANNING,
        "hydra": ToolCategory.EXPLOITATION,
        "metasploit": ToolCategory.EXPLOITATION,
        "commix": ToolCategory.EXPLOITATION,
        "xsstrike": ToolCategory.EXPLOITATION,
        "dalfox": ToolCategory.EXPLOITATION,
        # Password cracking
        "hashcat": ToolCategory.CRYPTO,
        "john": ToolCategory.CRYPTO,
        # Web application testing
        "burpsuite": ToolCategory.WEB,
        "zaproxy": ToolCategory.WEB,
        "whatweb": ToolCategory.WEB,
        "wafw00f": ToolCategory.WEB,
        # DNS utilities
        "dig": ToolCategory.RECON,
        "whois": ToolCategory.RECON,
        "dnsrecon": ToolCategory.RECON,
        "dnsenum": ToolCategory.RECON,
        # General utilities
        "curl": ToolCategory.UTILITY,
        "wget": ToolCategory.UTILITY,
        # Forensics tools
        "volatility": ToolCategory.FORENSICS,
        "yara": ToolCategory.FORENSICS,
        "exiftool": ToolCategory.FORENSICS,
        "pypykatz": ToolCategory.FORENSICS,
        "mimikatz": ToolCategory.FORENSICS,
        "sleuthkit": ToolCategory.FORENSICS,
        "autopsy": ToolCategory.FORENSICS,
        "foremost": ToolCategory.FORENSICS,
        "binwalk": ToolCategory.FORENSICS,
        "strings": ToolCategory.FORENSICS,
        "bulk_extractor": ToolCategory.FORENSICS,
        # SAST / code analysis
        "semgrep": ToolCategory.DEVSECOPS,
        "bandit": ToolCategory.DEVSECOPS,
        "gitleaks": ToolCategory.DEVSECOPS,
        "trufflehog": ToolCategory.DEVSECOPS,
        "checkov": ToolCategory.DEVSECOPS,
        # Container / vulnerability scanning
        "trivy": ToolCategory.CONTAINER,
        "grype": ToolCategory.CONTAINER,
        "syft": ToolCategory.CONTAINER,
        "dockle": ToolCategory.CONTAINER,
        # Cloud security
        "prowler": ToolCategory.CLOUD,
        "scoutsuite": ToolCategory.CLOUD,
        "aws": ToolCategory.CLOUD,
        "kubectl": ToolCategory.CLOUD,
        "kube-hunter": ToolCategory.CLOUD,
        # Reverse engineering
        "radare2": ToolCategory.FORENSICS,
        "apktool": ToolCategory.FORENSICS,
        "ghidra": ToolCategory.FORENSICS,
        # Reporting / analysis
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
    high_risk = {
        "metasploit",
        "sqlmap",
        "hashcat",
        "hydra",
        "ettercap",
        "bettercap",
        "mimikatz",
        "crackmapexec",
        "impacket",
    }
    medium_risk = {
        "nmap",
        "nuclei",
        "nikto",
        "gobuster",
        "ffuf",
        "wpscan",
        "masscan",
        "responder",
        "smbmap",
        "enum4linux",
    }
    low_risk = {
        "curl",
        "wget",
        "semgrep",
        "bandit",
        "gitleaks",
        "trufflehog",
        "checkov",
        "trivy",
        "grype",
        "syft",
        "volatility",
        "yara",
        "exiftool",
        "prowler",
        "scoutsuite",
    }
    if name in high_risk:
        return RiskLevel.HIGH
    if name in medium_risk:
        return RiskLevel.MEDIUM
    if name in low_risk:
        return RiskLevel.LOW
    return RiskLevel.SAFE


def describe_tool(name: str) -> str:
    entry = _db_lookup(name)
    if entry and entry.get("description"):
        return cast("str", entry["description"])
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
        "volatility": "Memory forensics framework for RAM dump analysis",
        "yara": "Pattern matching tool for malware identification and classification",
        "exiftool": "Read and write metadata information from files",
        "pypykatz": "Python implementation of Mimikatz for credential extraction from memory",
        "mimikatz": "Windows credential extraction and pass-the-hash toolkit",
        "sleuthkit": "Disk forensics toolkit for file system analysis",
        "foremost": "File carving tool to recover deleted files",
        "binwalk": "Firmware analysis tool for extracting embedded files",
        "strings": "Extract printable strings from binary files",
        "bulk_extractor": "High-performance data extraction for digital forensics",
        "semgrep": "Static analysis engine for code patterns and security rules",
        "bandit": "Python-specific security linter for finding common vulnerabilities",
        "gitleaks": "Secrets detection tool for git repositories",
        "trufflehog": "Credential and secrets scanner for git repos and files",
        "checkov": "Infrastructure as Code (IaC) static analysis for cloud misconfigurations",
        "trivy": "Comprehensive vulnerability scanner for containers, filesystems, and repos",
        "grype": "Vulnerability scanner for container images and filesystems",
        "syft": "Software bill of materials (SBOM) generator for containers",
        "prowler": "AWS security auditing and CIS benchmark compliance tool",
        "scoutsuite": "Multi-cloud security audit framework (AWS, Azure, GCP)",
        "kubectl": "Kubernetes cluster management and security command-line tool",
        "kube-hunter": "Kubernetes penetration testing tool for security weaknesses",
        "radare2": "Reverse engineering framework for binary analysis and disassembly",
        "apktool": "Android APK reverse engineering and decompilation tool",
        "responder": "LLMNR/NBT-NS/mDNS poisoner for network credential harvesting",
        "crackmapexec": "Post-exploitation toolkit for Windows/Active Directory reconnaissance",
        "impacket": "Python toolkit for building and manipulating network protocols",
        "smbmap": "SMB share enumeration and file access across Windows networks",
        "enum4linux": "Windows/Samba enumeration tool for user, share, and policy discovery",
        "graph_analyzer": "Analyze attack paths and blast radius from the knowledge graph",
        "threat_intel": "Query CVE and MITRE ATT&CK intelligence databases locally",
    }
    return descriptions.get(name, name)


def tags_for_tool(name: str) -> list[str]:
    entry = _db_lookup(name)
    if entry and entry.get("tags"):
        return cast("list[str]", entry["tags"])
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
        # Forensics
        "volatility": ["forensics", "memory", "ram", "analysis"],
        "yara": ["forensics", "malware", "pattern", "detection"],
        "exiftool": ["forensics", "metadata", "analysis"],
        "pypykatz": ["forensics", "credentials", "memory", "windows"],
        "mimikatz": ["forensics", "credentials", "windows", "ad"],
        "sleuthkit": ["forensics", "disk", "filesystem", "analysis"],
        "foremost": ["forensics", "carving", "recovery"],
        "binwalk": ["forensics", "firmware", "extraction"],
        "strings": ["forensics", "binary", "analysis"],
        "bulk_extractor": ["forensics", "extraction", "analysis"],
        # SAST / code
        "semgrep": ["sast", "code-review", "static-analysis", "security"],
        "bandit": ["sast", "python", "security", "linter"],
        "gitleaks": ["secrets", "git", "scanning", "detection"],
        "trufflehog": ["secrets", "scanning", "detection", "credentials"],
        "checkov": ["iac", "terraform", "cloudformation", "compliance"],
        # Container
        "trivy": ["container", "vulnerability", "scanning", "cve"],
        "grype": ["container", "vulnerability", "scanning", "cve"],
        "syft": ["container", "sbom", "inventory", "dependencies"],
        # Cloud
        "prowler": ["cloud", "aws", "compliance", "cis"],
        "scoutsuite": ["cloud", "security", "audit", "multi-cloud"],
        "kubectl": ["kubernetes", "k8s", "cloud", "orchestration"],
        "kube-hunter": ["kubernetes", "k8s", "security", "pentest"],
        # Reverse engineering
        "radare2": ["reverse-engineering", "binary", "disassembly", "analysis"],
        "apktool": ["android", "apk", "reverse-engineering", "decompile"],
        # AD / Network post-exploitation
        "responder": ["network", "llmnr", "poisoning", "capture"],
        "crackmapexec": ["windows", "ad", "lateral-movement", "post-exploit"],
        "impacket": ["network", "protocol", "windows", "ad"],
        "smbmap": ["smb", "windows", "share", "enumeration"],
        "enum4linux": ["smb", "windows", "enumeration", "network"],
    }

    return tag_map.get(name, [name])


def personas_for_tool(name: str) -> list[str]:
    entry = _db_lookup(name)
    if entry and entry.get("personas"):
        return cast("list[str]", entry["personas"])
    default_map = {
        # Scanning / recon
        "nmap": ["pentester", "redteam", "blueteam", "devsecops"],
        "nuclei": ["pentester", "redteam", "blueteam", "devsecops"],
        "masscan": ["pentester", "redteam"],
        "amass": ["pentester", "redteam", "blueteam", "osint"],
        "subfinder": ["pentester", "redteam", "osint"],
        # Forensics
        "volatility": ["dfir", "blueteam", "forensics"],
        "yara": ["dfir", "blueteam", "malware", "forensics"],
        "exiftool": ["dfir", "forensics", "osint"],
        "pypykatz": ["dfir", "forensics", "redteam"],
        "mimikatz": ["redteam", "pentester", "forensics"],
        "sleuthkit": ["dfir", "forensics", "blueteam"],
        "foremost": ["dfir", "forensics"],
        "binwalk": ["forensics", "iot"],
        # SAST / code review
        "semgrep": ["devsecops", "appsec", "auditor"],
        "bandit": ["devsecops", "appsec", "python"],
        "gitleaks": ["devsecops", "auditor", "blueteam"],
        "trufflehog": ["devsecops", "auditor", "blueteam"],
        "checkov": ["devsecops", "cloud", "auditor"],
        # Container
        "trivy": ["devsecops", "container", "blueteam"],
        "grype": ["devsecops", "container"],
        "syft": ["devsecops", "container"],
        # Cloud
        "prowler": ["cloud", "auditor", "blueteam"],
        "scoutsuite": ["cloud", "auditor", "blueteam"],
        "kubectl": ["cloud", "devsecops", "blueteam"],
        "kube-hunter": ["pentester", "redteam", "cloud"],
        # Reverse engineering
        "radare2": ["malware", "forensics", "reversing"],
        "apktool": ["mobile", "pentester", "reversing"],
        # Network / AD
        "responder": ["pentester", "redteam"],
        "crackmapexec": ["pentester", "redteam", "ad"],
        "impacket": ["pentester", "redteam", "ad"],
        "smbmap": ["pentester", "redteam", "blueteam"],
        "enum4linux": ["pentester", "redteam", "blueteam"],
    }
    return default_map.get(name, [])


__all__ = [
    "categorize_tool",
    "risk_for_tool",
    "describe_tool",
    "tags_for_tool",
    "personas_for_tool",
]
