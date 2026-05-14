"""Tool registry — discovers locally installed security tools and probes their versions.

Supports both static (built-in) and dynamic (plugin/AI-registered) tool registration.
The registry provides capability-based lookup for the hybrid execution engine.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Known tools registry — the STATIC component
# ---------------------------------------------------------------------------

_KNOWN_TOOLS: dict[str, dict] = {
    "nmap": {
        "version_cmd": ["nmap", "--version"],
        "capabilities": ["port_scan", "service_detect", "os_detect", "network_recon"],
        "category": "recon",
        "description": "Network exploration and port scanning",
        "default_args": ["-sV"],
    },
    "nikto": {
        "version_cmd": ["nikto", "-Version"],
        "capabilities": ["web_scan", "vuln_detect", "server_audit"],
        "category": "web",
        "description": "Web server vulnerability scanner",
        "default_args": [],
    },
    "sqlmap": {
        "version_cmd": ["sqlmap", "--version"],
        "capabilities": ["sqli", "db_enum", "web_scan"],
        "category": "web",
        "description": "Automatic SQL injection and database takeover",
        "default_args": ["--batch"],
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
        "description": "Fast web fuzzer",
        "default_args": [],
    },
    "masscan": {
        "version_cmd": ["masscan", "--version"],
        "capabilities": ["fast_port_scan", "network_recon"],
        "category": "recon",
        "description": "Internet-scale port scanner",
        "default_args": [],
    },
    "wpscan": {
        "version_cmd": ["wpscan", "--version"],
        "capabilities": ["wordpress_scan", "plugin_enum", "theme_enum"],
        "category": "web",
        "description": "WordPress security scanner",
        "default_args": [],
    },
    "nuclei": {
        "version_cmd": ["nuclei", "-version"],
        "capabilities": ["template_scan", "vuln_detect", "cve_scan"],
        "category": "vuln",
        "description": "Template-based vulnerability scanner",
        "default_args": [],
    },
    "hydra": {
        "version_cmd": ["hydra", "-V"],
        "capabilities": ["brute_force", "password_attack", "credential_test"],
        "category": "exploit",
        "description": "Network logon cracker",
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
        "description": "Advanced password recovery (GPU-accelerated)",
        "default_args": [],
    },
    "msfconsole": {
        "version_cmd": ["msfconsole", "--version"],
        "capabilities": ["exploitation", "post_exploit", "payload_gen"],
        "category": "exploit",
        "description": "Metasploit Framework console",
        "default_args": [],
    },
    "zap.sh": {
        "version_cmd": ["zap.sh", "-version"],
        "capabilities": ["web_scan", "proxy", "api_scan"],
        "category": "web",
        "description": "OWASP Zed Attack Proxy",
        "default_args": [],
    },
    "burpsuite": {
        "version_cmd": ["burpsuite", "--version"],
        "capabilities": ["web_proxy", "web_scan", "intruder"],
        "category": "web",
        "description": "Burp Suite web security testing",
        "default_args": [],
    },
}

# Human-friendly name aliases (human name → binary name)
_TOOL_NAME_ALIASES: dict[str, str] = {
    "metasploit": "msfconsole",
    "zaproxy": "zap.sh",
}

# Reverse alias map: binary name → human-friendly name used in manifests
_BINARY_TO_ALIAS: dict[str, str] = {v: k for k, v in _TOOL_NAME_ALIASES.items()}

# Capability → category mapping for AI planner context
CAPABILITY_CATEGORIES: dict[str, str] = {
    "port_scan": "recon",
    "service_detect": "recon",
    "os_detect": "recon",
    "network_recon": "recon",
    "web_scan": "web",
    "vuln_detect": "vuln",
    "sqli": "web",
    "dir_enum": "recon",
    "fuzzing": "recon",
    "fast_port_scan": "recon",
    "template_scan": "vuln",
    "cve_scan": "vuln",
    "brute_force": "exploit",
    "password_crack": "exploit",
    "exploitation": "exploit",
}

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

class ToolRegistry:
    """Discovers locally installed security tools and probes their versions.

    Supports both static (built-in _KNOWN_TOOLS) and dynamic tool registration.
    The registry is the foundation of the hybrid execution engine.
    """

    def __init__(self) -> None:
        self._dynamic_tools: dict[str, dict] = {}
        self._wsl_binary = shutil.which("wsl")

    def _wsl_discovery_enabled(self) -> bool:
        raw = os.getenv("SIYARIX_ENABLE_WSL_DISCOVERY", "1").strip().lower()
        return raw not in {"0", "false", "no", "off"}

    def _resolve_tool_path(self, tool_name: str) -> tuple[str | None, bool]:
        """Resolve executable path, including optional WSL fallback on Windows."""
        local_path = shutil.which(tool_name)
        if local_path:
            return local_path, False

        if platform.system().lower() != "windows" or not self._wsl_discovery_enabled() or not self._wsl_binary:
            return None, False

        try:
            result = subprocess.run(
                [self._wsl_binary, "-e", "sh", "-lc", f"command -v {tool_name}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
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
        """Register a tool dynamically (e.g., from AI discovery or plugins).

        Dynamic tools supplement the built-in registry and are available
        to the hybrid execution engine.
        """
        self._dynamic_tools[binary] = {
            "version_cmd": [binary, "--version"],
            "capabilities": capabilities or [],
            "category": category,
            "description": description,
            "default_args": default_args or [],
            "display_name": name,
        }

    def discover(self) -> list[ToolInfo]:
        """Return a list of :class:`ToolInfo` for every tool found on PATH.

        Combines static (built-in) and dynamically registered tools.
        """
        found: list[ToolInfo] = []

        # Static tools
        for tool_name, meta in _KNOWN_TOOLS.items():
            path, discovered_via_wsl = self._resolve_tool_path(tool_name)
            if path is None:
                continue
            version = self.probe_version(tool_name, path, via_wsl=discovered_via_wsl)
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
            version = self._probe_dynamic_version(tool_name, path)
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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout or result.stderr or "").strip()
            # Return first non-empty line
            for line in output.splitlines():
                line = line.strip()
                if line:
                    return line
            return "unknown"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "unknown"

    def _probe_dynamic_version(self, name: str, path: str) -> str:
        """Probe version for a dynamically registered tool."""
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout or result.stderr or "").strip()
            for line in output.splitlines():
                line = line.strip()
                if line:
                    return line
            return "unknown"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
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

    def to_ai_context(self) -> list[dict]:
        """Return tool information formatted for AI planner context."""
        return [
            {
                "name": t.name,
                "binary": t.binary,
                "capabilities": t.capabilities,
                "category": t.category,
                "description": t.description,
                "default_args": t.default_args,
            }
            for t in self.discover()
        ]
