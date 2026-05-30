# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool registry — discovers locally installed security tools and probes their versions.

Supports both static (built-in) and autonomous (plugin/registry-registered) tool registration.
The registry provides capability-based lookup for the execution engine.
Includes caching to avoid repeated subprocess calls on every command.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
import platform
import re
import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass, field
from pathlib import Path

from siyarix.executor import safe_run_sync

logger = logging.getLogger(__name__)

_EXTERNAL_METADATA_FILE = Path(__file__).resolve().parent / "data" / "tool_metadata.json"

# ---------------------------------------------------------------------------
# Known tools registry — the REGISTRY component
# ---------------------------------------------------------------------------

_KNOWN_TOOLS: dict[str, dict] = {
    # ── Recon / Network ──────────────────────────────────────────────────
    "nmap": {
        "version_cmd": ["nmap", "--version"],
        "capabilities": ["port_scan", "service_detect", "os_detect", "network_recon"],
        "category": "recon",
        "description": "Network exploration and port scanning",
        "default_args": ["-sV"],
    },
    "masscan": {
        "version_cmd": ["masscan", "--version"],
        "capabilities": ["fast_port_scan", "network_recon"],
        "category": "recon",
        "description": "Internet-scale port scanner",
        "default_args": [],
    },
    "rustscan": {
        "version_cmd": ["rustscan", "--version"],
        "capabilities": ["fast_port_scan", "network_recon"],
        "category": "recon",
        "description": "Fast port scanner (Rust)",
        "default_args": [],
    },
    # ── DNS / OSINT ────────────────────────────────────────────────────────
    "amass": {
        "version_cmd": ["amass", "-version"],
        "capabilities": ["subdomain_enum", "dns_recon", "osint"],
        "category": "recon",
        "description": "In-depth attack surface mapping",
        "default_args": [],
    },
    "subfinder": {
        "version_cmd": ["subfinder", "-version"],
        "capabilities": ["subdomain_enum", "passive_recon"],
        "category": "recon",
        "description": "Subdomain discovery tool",
        "default_args": [],
    },
    "dnsx": {
        "version_cmd": ["dnsx", "-version"],
        "capabilities": ["dns_brute", "dns_recon"],
        "category": "recon",
        "description": "Fast DNS toolkit",
        "default_args": [],
    },
    "theHarvester": {
        "version_cmd": ["theHarvester", "--version"],
        "capabilities": ["email_harvest", "domain_recon", "osint"],
        "category": "recon",
        "description": "OSINT email & domain intelligence",
        "default_args": [],
    },
    "whois": {
        "version_cmd": ["whois", "--version"],
        "capabilities": ["domain_recon", "osint"],
        "category": "recon",
        "description": "Domain WHOIS lookup",
        "default_args": [],
    },
    "shodan": {
        "version_cmd": ["shodan", "version"],
        "capabilities": ["osint", "passive_recon", "vuln_detect"],
        "category": "recon",
        "description": "Shodan CLI for search engine for internet-connected devices",
        "default_args": [],
    },
    # ── Web / HTTP ──────────────────────────────────────────────────────────
    "nikto": {
        "version_cmd": ["nikto", "-Version"],
        "capabilities": ["web_scan", "vuln_detect", "server_audit"],
        "category": "web",
        "description": "Web server vulnerability scanner",
        "default_args": [],
    },
    "gobuster": {
        "version_cmd": ["gobuster", "version"],
        "capabilities": ["dir_enum", "dns_enum", "vhost_enum"],
        "category": "recon",
        "description": "Directory/file, DNS, and VHost brute-force scanner",
        "default_args": [],
    },
    "ffuf": {
        "version_cmd": ["ffuf", "-V"],
        "capabilities": ["fuzzing", "dir_enum", "parameter_fuzzing"],
        "category": "recon",
        "description": "Fast web fuzzer written in Go",
        "default_args": [],
    },
    "feroxbuster": {
        "version_cmd": ["feroxbuster", "--version"],
        "capabilities": ["dir_enum", "fuzzing"],
        "category": "recon",
        "description": "Fast, recursive content discovery (Rust)",
        "default_args": [],
    },
    "httpx": {
        "version_cmd": ["httpx", "-version"],
        "capabilities": ["http_probe", "tech_detect", "status_check"],
        "category": "recon",
        "description": "Fast HTTP toolkit (Project Discovery)",
        "default_args": [],
    },
    "wpscan": {
        "version_cmd": ["wpscan", "--version"],
        "capabilities": ["wordpress_scan", "plugin_enum", "theme_enum"],
        "category": "web",
        "description": "WordPress security scanner",
        "default_args": [],
    },
    "sqlmap": {
        "version_cmd": ["sqlmap", "--version"],
        "capabilities": ["sqli", "db_enum", "web_scan"],
        "category": "web",
        "description": "Automatic SQL injection and database takeover",
        "default_args": ["--batch"],
    },
    # ── Vulnerability Scanning ───────────────────────────────────────────
    "nuclei": {
        "version_cmd": ["nuclei", "-version"],
        "capabilities": ["template_scan", "vuln_detect", "cve_scan"],
        "category": "vuln",
        "description": "Template-based vulnerability scanner (Project Discovery)",
        "default_args": [],
    },
    # ── Exploitation ────────────────────────────────────────────────────────
    "hydra": {
        "version_cmd": ["hydra", "-V"],
        "capabilities": ["brute_force", "password_attack", "credential_test"],
        "category": "exploit",
        "description": "Network logon cracker (supports 50+ protocols)",
        "default_args": [],
    },
    "john": {
        "version_cmd": ["john", "--version"],
        "capabilities": ["password_crack", "hash_crack"],
        "category": "exploit",
        "description": "John the Ripper password cracker",
        "default_args": [],
    },
    "hashcat": {
        "version_cmd": ["hashcat", "--version"],
        "capabilities": ["password_crack", "hash_crack", "gpu_crack"],
        "category": "exploit",
        "description": "Advanced GPU-accelerated password recovery",
        "default_args": [],
    },
    "msfconsole": {
        "version_cmd": ["msfconsole", "--version"],
        "capabilities": ["exploitation", "post_exploit", "payload_gen"],
        "category": "exploit",
        "description": "Metasploit Framework console",
        "default_args": [],
    },
    # ── MITM / Network Attacks ───────────────────────────────────────────
    "bettercap": {
        "version_cmd": ["bettercap", "--version"],
        "capabilities": [
            "mitm",
            "arp_spoof",
            "dns_spoof",
            "http_proxy",
            "network_sniff",
        ],
        "category": "exploit",
        "description": "Swiss-army knife for network attacks and monitoring (MITM)",
        "default_args": [],
    },
    "ettercap": {
        "version_cmd": ["ettercap", "--version"],
        "capabilities": ["mitm", "arp_poison", "packet_sniff", "protocol_analyze"],
        "category": "exploit",
        "description": "Comprehensive MITM attack framework",
        "default_args": [],
    },
    # ── Wireless ──────────────────────────────────────────────────────────
    "aircrack-ng": {
        "version_cmd": ["aircrack-ng", "--version"],
        "capabilities": ["wireless_attack", "wpa_crack", "packet_capture", "deauth"],
        "category": "exploit",
        "description": "Wireless network security assessment suite",
        "default_args": [],
    },
    # ── Windows / Active Directory ─────────────────────────────────────────
    "impacket": {
        "version_cmd": ["impacket", "--version"],
        "capabilities": [
            "smb_recon",
            "kerberoast",
            "wmi_exec",
            "pass_the_hash",
            "dc_sync",
        ],
        "category": "exploit",
        "description": "Impacket — Windows protocol abuse toolkit (SMB, Kerberos, WMI)",
        "default_args": [],
    },
    # ── Web Proxies / DAST ──────────────────────────────────────────────────
    "zap.sh": {
        "version_cmd": ["zap.sh", "-version"],
        "capabilities": ["web_scan", "proxy", "api_scan", "dast"],
        "category": "web",
        "description": "OWASP Zed Attack Proxy (DAST)",
        "default_args": [],
    },
    "burpsuite": {
        "version_cmd": ["burpsuite", "--version"],
        "capabilities": ["web_proxy", "web_scan", "intruder", "dast"],
        "category": "web",
        "description": "Burp Suite web security testing platform",
        "default_args": [],
    },
    # ── Secret / Code Scanning ──────────────────────────────────────────────
    "trufflehog": {
        "version_cmd": ["trufflehog", "--version"],
        "capabilities": ["secret_scan", "git_scan", "credentials_detect"],
        "category": "recon",
        "description": "Find credentials in code/history",
        "default_args": [],
    },
    "gitleaks": {
        "version_cmd": ["gitleaks", "version"],
        "capabilities": ["secret_scan", "git_scan"],
        "category": "recon",
        "description": "Detect hardcoded secrets in git repos",
        "default_args": [],
    },
    # ── Cloud ───────────────────────────────────────────────────────────────
    "aws": {
        "version_cmd": ["aws", "--version"],
        "capabilities": ["cloud_enum", "aws_recon"],
        "category": "cloud",
        "description": "AWS CLI (cloud reconnaissance)",
        "default_args": [],
    },
    "az": {
        "version_cmd": ["az", "--version"],
        "capabilities": ["cloud_enum", "azure_recon"],
        "category": "cloud",
        "description": "Azure CLI",
        "default_args": [],
    },
    "gcloud": {
        "version_cmd": ["gcloud", "--version"],
        "capabilities": ["cloud_enum", "gcp_recon"],
        "category": "cloud",
        "description": "Google Cloud CLI",
        "default_args": [],
    },
    # ── Containers / Infra ───────────────────────────────────────────────
    "docker": {
        "version_cmd": ["docker", "--version"],
        "capabilities": ["container_runtime", "image_manage"],
        "category": "infra",
        "description": "Docker CLI",
        "default_args": [],
    },
    "podman": {
        "version_cmd": ["podman", "--version"],
        "capabilities": ["container_runtime", "image_manage"],
        "category": "infra",
        "description": "Podman container engine",
        "default_args": [],
    },
    "kubectl": {
        "version_cmd": ["kubectl", "version", "--client", "--short"],
        "capabilities": ["k8s_manage", "cluster_recon"],
        "category": "infra",
        "description": "Kubernetes CLI",
        "default_args": [],
    },
    "helm": {
        "version_cmd": ["helm", "version"],
        "capabilities": ["k8s_package", "cluster_recon"],
        "category": "infra",
        "description": "Helm package manager for Kubernetes",
        "default_args": [],
    },
    "terraform": {
        "version_cmd": ["terraform", "version"],
        "capabilities": ["iac_plan", "infra_manage"],
        "category": "infra",
        "description": "Terraform IaC CLI",
        "default_args": [],
    },
    "ansible": {
        "version_cmd": ["ansible", "--version"],
        "capabilities": ["automation", "config_manage"],
        "category": "infra",
        "description": "Ansible automation tool",
        "default_args": [],
    },
    # ── Social Engineering ──────────────────────────────────────────────────
    "setoolkit": {
        "version_cmd": ["setoolkit", "--version"],
        "capabilities": ["social_engineering", "phishing", "credential_harvest"],
        "category": "social",
        "description": "Social Engineering Toolkit (SET)",
        "default_args": [],
    },
    "beef": {
        "version_cmd": ["beef", "--version"],
        "capabilities": ["browser_exploit", "phishing", "social_engineering"],
        "category": "social",
        "description": "Browser Exploitation Framework (BeEF)",
        "default_args": [],
    },
    "gophish": {
        "version_cmd": ["gophish", "--version"],
        "capabilities": ["phishing", "campaign_manage", "email_track"],
        "category": "social",
        "description": "Open-source phishing framework",
        "default_args": [],
    },
    "ghost-phisher": {
        "version_cmd": ["ghost-phisher", "--version"],
        "capabilities": ["phishing", "wireless_ap", "credential_harvest"],
        "category": "social",
        "description": "Phishing and fake AP framework",
        "default_args": [],
    },
    # ── Wireless ──────────────────────────────────────────────────────────
    "reaver": {
        "version_cmd": ["reaver", "--version"],
        "capabilities": ["wps_attack", "wireless_attack", "pin_brute"],
        "category": "wireless",
        "description": "WPS/WPA2 PIN attack tool",
        "default_args": [],
    },
    "wifite": {
        "version_cmd": ["wifite", "--version"],
        "capabilities": ["wireless_audit", "wpa_crack", "deauth"],
        "category": "wireless",
        "description": "Automated wireless audit tool",
        "default_args": [],
    },
    "kismet": {
        "version_cmd": ["kismet", "--version"],
        "capabilities": ["wireless_detect", "packet_capture", "sniff"],
        "category": "wireless",
        "description": "Wireless network detector and sniffer",
        "default_args": [],
    },
    # ── Network Tools (missing) ───────────────────────────────────────────────
    "netcat": {
        "version_cmd": ["nc", "--version"],
        "capabilities": ["port_scan", "banner_grab", "reverse_shell", "file_transfer"],
        "category": "recon",
        "description": "Network utility for reading/writing network connections",
        "default_args": [],
    },
    "socat": {
        "version_cmd": ["socat", "-V"],
        "capabilities": ["port_forward", "relay", "proxying"],
        "category": "recon",
        "description": "Multipurpose relay/SOCKS proxy",
        "default_args": [],
    },
    "tshark": {
        "version_cmd": ["tshark", "--version"],
        "capabilities": ["packet_capture", "protocol_analyze", "traffic_dump"],
        "category": "recon",
        "description": "CLI packet analyzer (Wireshark CLI)",
        "default_args": [],
    },
    # ── Exploitation (missing) ────────────────────────────────────────────────
    "metasploit": {
        "version_cmd": ["msfconsole", "--version"],
        "capabilities": [
            "exploitation",
            "post_exploit",
            "payload_gen",
            "auxiliary_scan",
        ],
        "category": "exploit",
        "description": "Metasploit Framework (alias for msfconsole)",
        "default_args": [],
    },
    "bloodhound": {
        "version_cmd": ["bloodhound", "--version"],
        "capabilities": ["ad_recon", "acl_analyze", "attack_path"],
        "category": "exploit",
        "description": "Active Directory attack path analysis",
        "default_args": [],
    },
    "responder": {
        "version_cmd": ["responder", "--version"],
        "capabilities": ["llmnr_poison", "ntlm_relay", "network_sniff"],
        "category": "exploit",
        "description": "LLMNR/NBT-NS/mDNS poisoner and NTLM relay",
        "default_args": [],
    },
    "crackmapexec": {
        "version_cmd": ["crackmapexec", "--version"],
        "capabilities": ["smb_recon", "winrm_exec", "pass_the_hash", "credential_dump"],
        "category": "exploit",
        "description": "Swiss-army knife for Windows/AD post-exploitation",
        "default_args": [],
    },
    "evil-winrm": {
        "version_cmd": ["evil-winrm", "--version"],
        "capabilities": ["winrm_shell", "pass_the_hash", "windows_post_exploit"],
        "category": "exploit",
        "description": "WinRM shell for Windows post-exploitation",
        "default_args": [],
    },
    "empire": {
        "version_cmd": ["empire", "--version"],
        "capabilities": ["post_exploit", "c2", "stager_gen", "power_shell"],
        "category": "exploit",
        "description": "PowerShell Empire post-exploitation agent",
        "default_args": [],
    },
    "pwncat": {
        "version_cmd": ["pwncat", "--version"],
        "capabilities": ["reverse_shell", "privilege_esc", "post_exploit"],
        "category": "exploit",
        "description": "Bind/reverse shell handler with privesc",
        "default_args": [],
    },
    # ── Forensics / Reporting ──────────────────────────────────────────────
    "volatility": {
        "version_cmd": ["volatility", "--version"],
        "capabilities": ["memory_forensics", "process_dump", "registry_analyze"],
        "category": "forensics",
        "description": "Volatile memory analysis framework",
        "default_args": [],
    },
    "autopsy": {
        "version_cmd": ["autopsy", "--version"],
        "capabilities": ["disk_forensics", "file_carve", "timeline_analyze"],
        "category": "forensics",
        "description": "Sleuth Kit GUI for digital forensics",
        "default_args": [],
    },
    "sleuthkit": {
        "version_cmd": ["tsk_loaddb", "--version"],
        "capabilities": ["disk_forensics", "file_carve", "filesystem_analyze"],
        "category": "forensics",
        "description": "Sleuth Kit CLI for disk forensics",
        "default_args": [],
    },
    "binwalk": {
        "version_cmd": ["binwalk", "--version"],
        "capabilities": ["firmware_analyze", "file_extract", "entropy_scan"],
        "category": "forensics",
        "description": "Firmware analysis and extraction tool",
        "default_args": [],
    },
    # ── Additional Exploitation ──────────────────────────────────────────────
    "certipy": {
        "version_cmd": ["certipy", "--version"],
        "capabilities": ["ad_cert_abuse", "ad_recon", "esc_attack"],
        "category": "exploit",
        "description": "Active Directory certificate abuse toolkit",
        "default_args": [],
    },
    "chisel": {
        "version_cmd": ["chisel", "--version"],
        "capabilities": ["tunnel", "port_forward", "proxying"],
        "category": "exploit",
        "description": "Fast TCP/UDP tunnel over HTTP",
        "default_args": [],
    },
    "ligolo-ng": {
        "version_cmd": ["ligolo-ng", "--version"],
        "capabilities": ["tunnel", "proxy", "pivot"],
        "category": "exploit",
        "description": "Tunneling/pivoting tool for penetration testing",
        "default_args": [],
    },
    # ── Additional Recon / OSINT ─────────────────────────────────────────────
    "waybackurls": {
        "version_cmd": ["waybackurls", "--version"],
        "capabilities": ["url_gather", "osint", "passive_recon"],
        "category": "recon",
        "description": "Wayback Machine URL harvester",
        "default_args": [],
    },
    "gau": {
        "version_cmd": ["gau", "--version"],
        "capabilities": ["url_gather", "osint", "passive_recon"],
        "category": "recon",
        "description": "Get All URLs - passive URL gathering",
        "default_args": [],
    },
    "katana": {
        "version_cmd": ["katana", "--version"],
        "capabilities": ["crawler", "url_gather", "spider"],
        "category": "recon",
        "description": "Next-gen web crawling and spidering",
        "default_args": [],
    },
    "httprobe": {
        "version_cmd": ["httprobe", "--version"],
        "capabilities": ["http_probe", "alive_check", "tech_detect"],
        "category": "recon",
        "description": "Take a list of domains and probe for working HTTP/HTTPS",
        "default_args": [],
    },
    "unfurl": {
        "version_cmd": ["unfurl", "--version"],
        "capabilities": ["url_analyze", "osint", "data_extract"],
        "category": "recon",
        "description": "URL extract and analyze tool (Tomnomnom)",
        "default_args": [],
    },
    "interactsh": {
        "version_cmd": ["interactsh-client", "--version"],
        "capabilities": ["oob_detect", "dns_callback", "http_callback"],
        "category": "web",
        "description": "OOB interaction detection client",
        "default_args": [],
    },
    "cloudflared": {
        "version_cmd": ["cloudflared", "--version"],
        "capabilities": ["tunnel", "proxy", "dns_over_https"],
        "category": "infra",
        "description": "Cloudflare tunnel client",
        "default_args": [],
    },
}

# Human-friendly name aliases (human name → binary name)
_TOOL_NAME_ALIASES: dict[str, str] = {
    "metasploit": "msfconsole",
    "zaproxy": "zap.sh",
    "burp": "burpsuite",
    "theharvester": "theHarvester",
    "aircrack": "aircrack-ng",
    "beef-framework": "beef",
    "set": "setoolkit",
    "cme": "crackmapexec",
    "mimikatz": "crackmapexec",
    "winrm": "evil-winrm",
    "ps-empire": "empire",
    "vol": "volatility",
    "bloodhound-ce": "bloodhound",
}

# Reverse alias map: binary name → human-friendly name used in manifests
_BINARY_TO_ALIAS: dict[str, str] = {v: k for k, v in _TOOL_NAME_ALIASES.items()}

# Capability → category mapping for AI planner context
CAPABILITY_CATEGORIES: dict[str, str] = {
    "port_scan": "recon",
    "service_detect": "recon",
    "os_detect": "recon",
    "network_recon": "recon",
    "subdomain_enum": "recon",
    "dns_recon": "recon",
    "fast_port_scan": "recon",
    "dir_enum": "recon",
    "fuzzing": "recon",
    "osint": "recon",
    "web_scan": "web",
    "vuln_detect": "vuln",
    "sqli": "web",
    "template_scan": "vuln",
    "cve_scan": "vuln",
    "brute_force": "exploit",
    "password_crack": "exploit",  # nosec B105
    "exploitation": "exploit",
    "secret_scan": "recon",  # nosec B105
    "cloud_enum": "cloud",
    "azure_recon": "cloud",
    "aws_recon": "cloud",
    "gcp_recon": "cloud",
    "container_runtime": "infra",
    "image_manage": "infra",
    "k8s_manage": "infra",
    "k8s_package": "infra",
    "cluster_recon": "infra",
    "iac_plan": "infra",
    "infra_manage": "infra",
    "automation": "infra",
    "config_manage": "infra",
    "mitm": "exploit",
    "arp_spoof": "exploit",
    "dns_spoof": "exploit",
    "network_sniff": "exploit",
    "arp_poison": "exploit",
    "packet_sniff": "exploit",
    "protocol_analyze": "exploit",
    "wireless_attack": "exploit",
    "wpa_crack": "exploit",
    "packet_capture": "exploit",
    "deauth": "exploit",
    "smb_recon": "exploit",
    "kerberoast": "exploit",
    "wmi_exec": "exploit",
    "pass_the_hash": "exploit",
    "dc_sync": "exploit",
}

# Cache TTL for tool discovery (seconds)
_DISCOVERY_CACHE_TTL = 300.0  # 5 minutes


@dataclass
class ToolInfo:
    """Metadata for a discovered security tool."""

    name: str
    binary: str
    path: str
    version: str
    capabilities: list[str] = field(default_factory=list)
    category: str = "unknown"
    description: str = ""
    default_args: list[str] = field(default_factory=list)
    is_dynamic: bool = False  # True if registered dynamically (not from _KNOWN_TOOLS)

    def __repr__(self) -> str:
        return f"ToolInfo(name={self.name!r}, version={self.version!r}, path={self.path!r})"


_CAT_MAP: dict[str, str] = {
    "dns_recon": "recon", "port_scan": "recon", "osint": "recon",
    "web_scan": "web", "dir_enum": "web", "fuzzing": "web", "sqli": "web",
    "vuln_detect": "vuln", "cve_scan": "vuln",
    "brute_force": "exploit", "password_crack": "exploit", "exploitation": "exploit",
    "mitm": "exploit", "ad_recon": "exploit", "smb_recon": "exploit",
    "social_engineering": "social",
    "wireless_attack": "wireless",
    "cloud_enum": "cloud",
    "container_runtime": "infra", "k8s_manage": "infra", "iac_plan": "infra",
    "forensics": "forensics", "packet_sniff": "recon",
    "secret_scan": "web", "reverse_shell": "exploit", "proxy": "exploit",
    "certificate_scan": "recon", "api_scan": "web",
}


class ToolRegistry:
    """Discovers locally installed security tools and probes their versions.

    Supports both static (built-in _KNOWN_TOOLS) and dynamic tool registration.
    Discovery results are cached for _DISCOVERY_CACHE_TTL seconds to avoid
    repeated subprocess invocations on every command.
    """

    def __init__(self) -> None:
        self._dynamic_tools: dict[str, dict] = {}
        self._wsl_binary = shutil.which("wsl")
        self._cache: list[ToolInfo] | None = None
        self._cache_time: float = 0.0
        self._external_metadata: dict[str, dict] = self._load_external_metadata()

    def _wsl_discovery_enabled(self) -> bool:
        raw = os.getenv("SIYARIX_ENABLE_WSL_DISCOVERY", "1").strip().lower()
        return raw not in {"0", "false", "no", "off"}

    def _resolve_tool_path(self, tool_name: str) -> tuple[str | None, bool]:
        """Resolve executable path, including optional WSL fallback on Windows."""
        local_path = shutil.which(tool_name)
        if local_path:
            return local_path, False

        if (
            platform.system().lower() != "windows"
            or not self._wsl_discovery_enabled()
            or not self._wsl_binary
        ):
            return None, False

        try:
            # Only allow simple tool names (alphanumeric, dash, underscore) to avoid shell injection
            if not all(c.isalnum() or c in "-_" for c in tool_name):
                return None, False
            # Use safe_run_sync to avoid accidental shell=True patterns
            result = safe_run_sync(
                [self._wsl_binary, "-e", "sh", "-lc", f"command -v {tool_name}"],
                timeout=5,
            )
        except Exception as exc:
            logger.exception(
                "WSL tool path resolution failed for %s: %s", tool_name, exc
            )
            return None, False

        if result.returncode != 0 or not (result.stdout or "").strip():
            return None, False

        return self._wsl_binary, True

    def _load_external_metadata(self) -> dict[str, dict]:
        """Load tool metadata from the external JSON file."""
        f = _EXTERNAL_METADATA_FILE
        if not f.exists():
            return {}
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            logger.debug("Loaded %d entries from %s", len(data), f)
            return data
        except Exception as exc:
            logger.warning("Failed to load tool metadata from %s: %s", f, exc)
            return {}

    def _lookup_external_metadata(self, name: str) -> dict | None:
        """Look up a tool in external metadata, then known tools, then infer from help."""
        meta = self._external_metadata.get(name)
        if meta:
            return meta
        meta = _KNOWN_TOOLS.get(name)
        if meta:
            return meta
        return None

    def _infer_capabilities(self, name: str, binary_path: str) -> dict:
        """Run --help on a binary and infer capabilities from output text."""
        _HELP_PATTERNS: list[tuple[re.Pattern, str]] = [
            (re.compile(r"port\s*scan|nmap|masscan"), "port_scan"),
            (re.compile(r"service\s*(detect|version|probe)"), "service_detect"),
            (re.compile(r"os\s*(detect|fingerprint|identify)"), "os_detect"),
            (re.compile(r"dns|domain|subdomain|resolv|dig"), "dns_recon"),
            (re.compile(r"subdomain|subdomain_enum"), "subdomain_enum"),
            (re.compile(r"whois|osint|passive|recon"), "osint"),
            (re.compile(r"vuln|vulnerability|cve|cvss"), "vuln_detect"),
            (re.compile(r"web\s*(scan|app|server)"), "web_scan"),
            (re.compile(r"dir.*(enum|bust)|gobuster|dirb"), "dir_enum"),
            (re.compile(r"fuzz|ffuf|wfuzz|param"), "fuzzing"),
            (re.compile(r"sql|sqli|injection|database"), "sqli"),
            (re.compile(r"brute|bruteforce|hydra"), "brute_force"),
            (re.compile(r"password|credential|hash|john"), "password_crack"),
            (re.compile(r"exploit|exploitation|msf|metasploit"), "exploitation"),
            (re.compile(r"post.*exploit"), "post_exploit"),
            (re.compile(r"mitm|arp.*spoof|ettercap"), "mitm"),
            (re.compile(r"sniff|packet|tcpdump|tshark"), "packet_sniff"),
            (re.compile(r"wireless|wifi|aircrack"), "wireless_attack"),
            (re.compile(r"cloud|aws|azure|gcp|s3"), "cloud_enum"),
            (re.compile(r"container|docker|podman"), "container_runtime"),
            (re.compile(r"k8s|kubernetes|kubectl"), "k8s_manage"),
            (re.compile(r"iac|terraform|ansible"), "iac_plan"),
            (re.compile(r"social.*eng|phish|setoolkit"), "social_engineering"),
            (re.compile(r"reverse.*shell|payload"), "reverse_shell"),
            (re.compile(r"proxy|tunnel|chisel"), "proxy"),
            (re.compile(r"forensic|volatility|sleuth"), "forensics"),
            (re.compile(r"secret|gitleaks|trufflehog"), "secret_scan"),
            (re.compile(r"ldap|kerberos|bloodhound"), "ad_recon"),
            (re.compile(r"samba|smb|cifs|netbios"), "smb_recon"),
            (re.compile(r"cert|tls|ssl|https"), "certificate_scan"),
            (re.compile(r"api|rest|graphql"), "api_scan"),
        ]
        _EXCLUDE = [re.compile(r"usage:\s+python\d*\s+-m", re.I), re.compile(r"no\s+help|unrecognized", re.I)]
        caps: set[str] = set()
        for flag in ("--help", "-h"):
            try:
                r = subprocess.run([binary_path, flag], capture_output=True, text=True, timeout=5)  # nosec B603
                text = (r.stdout + r.stderr).lower()
                if any(p.search(text) for p in _EXCLUDE):
                    continue
                for pattern, cap in _HELP_PATTERNS:
                    if pattern.search(text):
                        caps.add(cap)
                if not caps and len(text.strip()) > 50:
                    caps.add("cli_tool")
            except (OSError, subprocess.TimeoutExpired):
                continue
        if not caps:
            return {}
        category = next((_CAT_MAP[c] for c in caps if c in _CAT_MAP), "tool")
        desc = f"{name} — inferred from --help"
        return {"capabilities": sorted(caps), "category": category, "description": desc}

    def register_dynamic(
        self,
        name: str,
        binary: str,
        capabilities: list[str] | None = None,
        category: str = "custom",
        description: str = "",
        default_args: list[str] | None = None,
    ) -> None:
        """Register a tool dynamically (e.g., from discovery or plugins).

        Dynamic tools supplement the built-in registry and are available
        to the execution engine.
        """
        self._dynamic_tools[binary] = {
            "version_cmd": [binary, "--version"],
            "capabilities": capabilities or [],
            "category": category,
            "description": description,
            "default_args": default_args or [],
            "display_name": name,
        }
        # Invalidate cache
        self._cache = None

    def discover(
        self, force_refresh: bool = False, fast: bool = False
    ) -> list[ToolInfo]:
        """Return a list of :class:`ToolInfo` for every tool found on PATH.

        Results are cached for _DISCOVERY_CACHE_TTL seconds. Pass
        ``force_refresh=True`` to bypass the cache.
        """
        now = time.monotonic()
        if (
            not force_refresh
            and self._cache is not None
            and (now - self._cache_time) < _DISCOVERY_CACHE_TTL
        ):
            return self._cache

        found: list[ToolInfo] = []
        fast_mode = fast or os.getenv("SIYARIX_FAST_DISCOVERY", "0") == "1"

        # Static tools
        for tool_name, meta in _KNOWN_TOOLS.items():
            path, discovered_via_wsl = self._resolve_tool_path(tool_name)
            if path is None:
                continue
            version = (
                "unknown"
                if fast_mode
                else self.probe_version(tool_name, path, via_wsl=discovered_via_wsl)
            )
            friendly_name = _BINARY_TO_ALIAS.get(tool_name, tool_name)
            default_args = list(meta.get("default_args", []))
            if discovered_via_wsl:
                default_args = ["-e", tool_name, *default_args]
            found.append(
                ToolInfo(
                    name=friendly_name,
                    binary=tool_name,
                    path=path,
                    version=version,
                    capabilities=list(meta["capabilities"]),
                    category=meta.get("category", "unknown"),
                    description=meta.get("description", ""),
                    default_args=default_args,
                    is_dynamic=False,
                )
            )

        # Dynamic tools (include auto-detected from scan_path)
        for tool_name, meta in self._dynamic_tools.items():
            path = shutil.which(tool_name)
            if path is None:
                continue
            version = (
                "unknown" if fast_mode else self._probe_dynamic_version(tool_name, path)
            )
            # Try to enrich empty capabilities from external metadata
            caps = list(meta.get("capabilities", []))
            cat = meta.get("category", "custom")
            desc = meta.get("description", "")
            if not caps or cat == "auto-detect":
                ext = self._lookup_external_metadata(tool_name)
                if ext:
                    caps = list(ext.get("capabilities", caps))
                    cat = ext.get("category", cat)
                    desc = ext.get("description", desc)
                elif not caps and path:
                    inferred = self._infer_capabilities(tool_name, path)
                    if inferred:
                        caps = list(inferred.get("capabilities", caps))
                        cat = inferred.get("category", cat)
                        desc = inferred.get("description", desc)
            found.append(
                ToolInfo(
                    name=meta.get("display_name", tool_name),
                    binary=tool_name,
                    path=path,
                    version=version,
                    capabilities=caps,
                    category=cat,
                    description=desc,
                    default_args=list(meta.get("default_args", [])),
                    is_dynamic=True,
                )
            )

        self._cache = found
        self._cache_time = now
        return found

    def find_by_capability(self, capability: str) -> list[ToolInfo]:
        """Find all discovered tools that have the given capability."""
        return [t for t in self.discover() if capability in t.capabilities]

    def find_by_category(self, category: str) -> list[ToolInfo]:
        """Find all discovered tools in the given category."""
        return [t for t in self.discover() if t.category == category]

    def probe_version(self, name: str, path: str, *, via_wsl: bool = False) -> str:
        """Run the version command for *name* and return a version string.

        Falls back to ``"unknown"`` if the command fails or times out.
        """
        meta = _KNOWN_TOOLS.get(name)
        if meta is None:
            return "unknown"
        cmd = [path, *meta["version_cmd"][1:]]
        if via_wsl:
            cmd = [path, "-e", name, *meta["version_cmd"][1:]]
        try:
            result = safe_run_sync(cmd, timeout=10)
            output = (result.stdout or result.stderr or "").strip()
            # Return first non-empty line
            for line in output.splitlines():
                line = line.strip()
                if line:
                    return line
            return "unknown"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("probe_version failed for %s: %s", name, exc)
            return "unknown"

    def _probe_dynamic_version(self, name: str, path: str) -> str:
        """Probe version for a dynamically registered tool."""
        try:
            result = safe_run_sync([path, "--version"], timeout=10)
            output = (result.stdout or result.stderr or "").strip()
            for line in output.splitlines():
                line = line.strip()
                if line:
                    return line
            return "unknown"
        except Exception as exc:
            logger.warning(
                "Failed to probe dynamic tool version for %s: %s", name, exc
            )
            return "unknown"

    def to_manifest(self) -> dict:
        """Return a serializable manifest of discovered tools for server registration."""
        tools = self.discover()
        return {
            "tools": [
                {
                    "name": t.name,
                    "binary": t.binary,
                    "path": t.path,
                    "version": t.version,
                    "capabilities": t.capabilities,
                    "category": t.category,
                    "description": t.description,
                    "is_dynamic": t.is_dynamic,
                }
                for t in tools
            ]
        }

    def update_metadata(self, output_path: Path) -> int:
        """Scan PATH and generate a new metadata file."""
        logger.info("Scanning PATH and inferring capabilities from --help ...")
        scanned = self.scan_path()
        logger.info("Found %d tools with inferable metadata", len(scanned))

        merged = dict(_KNOWN_TOOLS)
        for tool_name in scanned:
            if tool_name not in merged:
                merged[tool_name] = {
                    "category": "auto-detect",
                    "description": f"Auto-detected tool: {tool_name}",
                }

        def _sort_key(item: tuple[str, dict[str, Any]]) -> Any:
            meta = item[1]
            return (meta.get("category", "z"), item[0])
        merged = dict(sorted(merged.items(), key=_sort_key))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        logger.info("Wrote %d entries to %s", len(merged), output_path)
        return len(merged)

    def scan_path(self, timeout: float = 5.0) -> list[str]:
        """Scan ALL binaries on PATH and register unknown ones as dynamic tools.

        Walks every directory in ``os.environ["PATH"]``, checks each executable,
        and registers any unknown tools under category ``"auto-detect"``.

        Returns:
            List of newly registered tool names.
        """
        import time as _time

        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        discovered: list[str] = []
        known = set(_KNOWN_TOOLS.keys()) | set(self._dynamic_tools.keys())
        start = _time.monotonic()

        for directory in path_dirs:
            if _time.monotonic() - start > timeout:
                logger.warning("scan_path timed out after %.1fs", timeout)
                break
            if not os.path.isdir(directory):
                continue
            try:
                for entry in os.listdir(directory):
                    if _time.monotonic() - start > timeout:
                        break
                    full = os.path.join(directory, entry)
                    name, ext = os.path.splitext(entry)
                    if not os.path.isfile(full):
                        continue
                    if os.name == "nt":
                        if ext.lower() not in (".exe", ".bat", ".ps1", ".cmd"):
                            continue
                    elif not os.access(full, os.X_OK):
                        continue
                    # Normalize: strip common extensions
                    binary = name.lower()
                    if binary in known or binary in discovered:
                        continue
                    # Register as dynamic
                    self.register_dynamic(
                        name=binary,
                        binary=binary,
                        capabilities=[],
                        category="auto-detect",
                        description=f"Auto-detected from PATH: {full}",
                    )
                    discovered.append(binary)
            except PermissionError:
                continue
            except OSError:
                continue

        if discovered:
            logger.info(
                "scan_path discovered %d new tools: %s", len(discovered), discovered
            )
        return discovered
