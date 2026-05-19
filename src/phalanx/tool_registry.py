"""Tool registry — discovers locally installed security tools and probes their versions.

Supports both static (built-in) and autonomous (plugin/registry-registered) tool registration.
The registry provides capability-based lookup for the execution engine.
Includes caching to avoid repeated subprocess calls on every command.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass, field
import logging

from siyarix.executor import safe_run_sync

logger = logging.getLogger(__name__)

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
}

# Human-friendly name aliases (human name → binary name)
_TOOL_NAME_ALIASES: dict[str, str] = {
    "metasploit": "msfconsole",
    "zaproxy": "zap.sh",
    "burp": "burpsuite",
    "theharvester": "theHarvester",
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
                [self._wsl_binary, "-e", "sh", "-lc", f"command -v {tool_name}"], timeout=5
            )
        except Exception as exc:
            logger.exception("WSL tool path resolution failed for %s: %s", tool_name, exc)
            return None, False

        if result.returncode != 0 or not (result.stdout or "").strip():
            return None, False

        return self._wsl_binary, True

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

    def discover(self, force_refresh: bool = False, fast: bool = False) -> list[ToolInfo]:
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

        # Dynamic tools
        for tool_name, meta in self._dynamic_tools.items():
            path = shutil.which(tool_name)
            if path is None:
                continue
            version = "unknown" if fast_mode else self._probe_dynamic_version(tool_name, path)
            found.append(
                ToolInfo(
                    name=meta.get("display_name", tool_name),
                    binary=tool_name,
                    path=path,
                    version=version,
                    capabilities=list(meta.get("capabilities", [])),
                    category=meta.get("category", "custom"),
                    description=meta.get("description", ""),
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
            logger.exception("Failed to probe dynamic tool version for %s: %s", name, exc)
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

    def to_planner_context(self) -> list[dict]:
        """Return tool information formatted for task planner context."""
        return [
            {
                "name": t.name,
                "binary": t.binary,
                "capabilities": t.capabilities,
                "category": t.category,
                "description": t.description,
                "default_args": t.default_args,
            }
            for t in self.discover(fast=True)
        ]
