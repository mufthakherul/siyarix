# SPDX-License-Identifier: AGPL-3.0-or-later

"""Auto-installation of missing security tools.

Detects missing tools and installs them using the appropriate package manager
based on the detected platform, as described in Chapter 6.4.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ToolInstallResult:
    """Result of a tool installation attempt."""

    tool: str
    success: bool = False
    method: str = ""
    output: str = ""
    error: str = ""


# Known tool → install mappings
_TOOL_INSTALL_MAP: dict[str, dict[str, list[str]]] = {
    "nmap": {
        "apt": ["apt-get", "install", "-y", "nmap"],
        "brew": ["brew", "install", "nmap"],
        "choco": ["choco", "install", "-y", "nmap"],
        "pacman": ["pacman", "-S", "--noconfirm", "nmap"],
        "dnf": ["dnf", "install", "-y", "nmap"],
    },
    "nuclei": {
        "apt": ["apt-get", "install", "-y", "nuclei"],
        "brew": ["brew", "install", "nuclei"],
        "go": [
            "go",
            "install",
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        ],
        "curl": [
            "curl",
            "-s",
            "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip",
        ],
    },
    "masscan": {
        "apt": ["apt-get", "install", "-y", "masscan"],
        "brew": ["brew", "install", "masscan"],
        "pacman": ["pacman", "-S", "--noconfirm", "masscan"],
    },
    "gobuster": {
        "apt": ["apt-get", "install", "-y", "gobuster"],
        "brew": ["brew", "install", "gobuster"],
        "go": ["go", "install", "github.com/OJ/gobuster/v3@latest"],
    },
    "ffuf": {
        "apt": ["apt-get", "install", "-y", "ffuf"],
        "brew": ["brew", "install", "ffuf"],
        "go": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
    },
    "sqlmap": {
        "pip": [sys.executable, "-m", "pip", "install", "sqlmap"],
        "apt": ["apt-get", "install", "-y", "sqlmap"],
        "brew": ["brew", "install", "sqlmap"],
    },
    "hydra": {
        "apt": ["apt-get", "install", "-y", "hydra"],
        "brew": ["brew", "install", "hydra"],
        "pacman": ["pacman", "-S", "--noconfirm", "hydra"],
    },
    "subfinder": {
        "apt": ["apt-get", "install", "-y", "subfinder"],
        "brew": ["brew", "install", "subfinder"],
        "go": [
            "go",
            "install",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        ],
    },
    "nikto": {
        "apt": ["apt-get", "install", "-y", "nikto"],
        "brew": ["brew", "install", "nikto"],
        "pacman": ["pacman", "-S", "--noconfirm", "nikto"],
    },
    "feroxbuster": {
        "apt": ["apt-get", "install", "-y", "feroxbuster"],
        "brew": ["brew", "install", "feroxbuster"],
        "cargo": ["cargo", "install", "feroxbuster"],
    },
    "wpscan": {
        "apt": ["apt-get", "install", "-y", "wpscan"],
        "brew": ["brew", "install", "wpscan"],
        "gem": ["gem", "install", "wpscan"],
    },
    "john": {
        "apt": ["apt-get", "install", "-y", "john"],
        "brew": ["brew", "install", "john"],
        "pacman": ["pacman", "-S", "--noconfirm", "john"],
    },
    "hashcat": {
        "apt": ["apt-get", "install", "-y", "hashcat"],
        "brew": ["brew", "install", "hashcat"],
        "pacman": ["pacman", "-S", "--noconfirm", "hashcat"],
    },
    "bettercap": {
        "apt": ["apt-get", "install", "-y", "bettercap"],
        "brew": ["brew", "install", "bettercap"],
        "go": ["go", "install", "github.com/bettercap/bettercap@latest"],
    },
    "trufflehog": {
        "apt": ["apt-get", "install", "-y", "trufflehog"],
        "brew": ["brew", "install", "trufflehog"],
        "go": ["go", "install", "github.com/trufflesecurity/trufflehog/v3@latest"],
    },
    "gitleaks": {
        "apt": ["apt-get", "install", "-y", "gitleaks"],
        "brew": ["brew", "install", "gitleaks"],
        "go": ["go", "install", "github.com/gitleaks/gitleaks/v8@latest"],
    },
    "aircrack-ng": {
        "apt": ["apt-get", "install", "-y", "aircrack-ng"],
        "brew": ["brew", "install", "aircrack-ng"],
        "pacman": ["pacman", "-S", "--noconfirm", "aircrack-ng"],
    },
    "impacket": {
        "pip": [sys.executable, "-m", "pip", "install", "impacket"],
        "apt": ["apt-get", "install", "-y", "python3-impacket"],
        "brew": ["brew", "install", "impacket"],
    },
    "msfconsole": {
        "apt": ["apt-get", "install", "-y", "metasploit-framework"],
        "brew": ["brew", "install", "metasploit"],
        "pacman": ["pacman", "-S", "--noconfirm", "metasploit"],
    },
    "msfvenom": {
        "apt": ["apt-get", "install", "-y", "metasploit-framework"],
        "brew": ["brew", "install", "metasploit"],
    },
    "meterpreter": {
        "apt": ["apt-get", "install", "-y", "metasploit-framework"],
        "brew": ["brew", "install", "metasploit"],
    },
    "setoolkit": {
        "apt": ["apt-get", "install", "-y", "set"],
        "brew": ["brew", "install", "set"],
        "git": [
            "git",
            "clone",
            "https://github.com/trustedsec/social-engineer-toolkit",
            "/opt/set",
        ],
    },
    "beef": {
        "apt": ["apt-get", "install", "-y", "beef-xss"],
        "brew": ["brew", "install", "beef"],
        "git": ["git", "clone", "https://github.com/beefproject/beef", "/opt/beef"],
    },
    "gophish": {
        "apt": ["apt-get", "install", "-y", "gophish"],
        "brew": ["brew", "install", "gophish"],
        "wget": [
            "wget",
            "-q",
            "https://github.com/gophish/gophish/releases/latest/download/gophish-linux-amd64.zip",
        ],
    },
    "reaver": {
        "apt": ["apt-get", "install", "-y", "reaver"],
        "brew": ["brew", "install", "reaver"],
        "pacman": ["pacman", "-S", "--noconfirm", "reaver"],
    },
    "wifite": {
        "apt": ["apt-get", "install", "-y", "wifite"],
        "brew": ["brew", "install", "wifite"],
        "git": ["git", "clone", "https://github.com/derv82/wifite2", "/opt/wifite2"],
    },
    "kismet": {
        "apt": ["apt-get", "install", "-y", "kismet"],
        "brew": ["brew", "install", "kismet"],
        "pacman": ["pacman", "-S", "--noconfirm", "kismet"],
    },
    "volatility": {
        "pip": [sys.executable, "-m", "pip", "install", "volatility3"],
        "apt": ["apt-get", "install", "-y", "volatility"],
        "brew": ["brew", "install", "volatility"],
    },
    "binwalk": {
        "apt": ["apt-get", "install", "-y", "binwalk"],
        "brew": ["brew", "install", "binwalk"],
        "pip": [sys.executable, "-m", "pip", "install", "binwalk"],
    },
    "certipy": {
        "pip": [sys.executable, "-m", "pip", "install", "certipy-ad"],
        "apt": ["apt-get", "install", "-y", "certipy"],
    },
    "chisel": {
        "apt": ["apt-get", "install", "-y", "chisel"],
        "brew": ["brew", "install", "chisel"],
        "go": ["go", "install", "github.com/jpillora/chisel@latest"],
    },
    "waybackurls": {
        "go": ["go", "install", "github.com/tomnomnom/waybackurls@latest"],
        "brew": ["brew", "install", "waybackurls"],
    },
    "gau": {
        "go": ["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"],
        "brew": ["brew", "install", "gau"],
    },
    "katana": {
        "go": ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
        "brew": ["brew", "install", "katana"],
    },
    "httprobe": {
        "go": ["go", "install", "github.com/tomnomnom/httprobe@latest"],
        "brew": ["brew", "install", "httprobe"],
    },
    "unfurl": {
        "go": ["go", "install", "github.com/tomnomnom/unfurl@latest"],
        "brew": ["brew", "install", "unfurl"],
    },
    "interactsh": {
        "go": [
            "go",
            "install",
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        ],
        "brew": ["brew", "install", "interactsh"],
    },
    "cloudflared": {
        "apt": ["apt-get", "install", "-y", "cloudflared"],
        "brew": ["brew", "install", "cloudflared"],
        "wget": [
            "wget",
            "-q",
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
        ],
    },
    "bloodhound": {
        "apt": ["apt-get", "install", "-y", "bloodhound"],
        "brew": ["brew", "install", "bloodhound"],
        "npm": ["npm", "install", "-g", "bloodhound"],
    },
    "responder": {
        "apt": ["apt-get", "install", "-y", "responder"],
        "brew": ["brew", "install", "responder"],
        "git": [
            "git",
            "clone",
            "https://github.com/lgandx/Responder",
            "/opt/responder",
        ],
    },
    "crackmapexec": {
        "pip": [sys.executable, "-m", "pip", "install", "crackmapexec"],
        "apt": ["apt-get", "install", "-y", "crackmapexec"],
        "brew": ["brew", "install", "crackmapexec"],
    },
    "evil-winrm": {
        "apt": ["apt-get", "install", "-y", "evil-winrm"],
        "brew": ["brew", "install", "evil-winrm"],
        "gem": ["gem", "install", "evil-winrm"],
    },
    "empire": {
        "pip": [sys.executable, "-m", "pip", "install", "empire"],
        "apt": ["apt-get", "install", "-y", "powershell-empire"],
        "git": ["git", "clone", "https://github.com/BC-SECURITY/Empire", "/opt/empire"],
    },
    "pwncat": {
        "pip": [sys.executable, "-m", "pip", "install", "pwncat-cs"],
        "apt": ["apt-get", "install", "-y", "pwncat"],
    },
    "socat": {
        "apt": ["apt-get", "install", "-y", "socat"],
        "brew": ["brew", "install", "socat"],
        "pacman": ["pacman", "-S", "--noconfirm", "socat"],
    },
    "tshark": {
        "apt": ["apt-get", "install", "-y", "tshark"],
        "brew": ["brew", "install", "tshark"],
        "pacman": ["pacman", "-S", "--noconfirm", "tshark"],
    },
    "netcat": {
        "apt": ["apt-get", "install", "-y", "netcat-openbsd"],
        "brew": ["brew", "install", "netcat"],
        "pacman": ["pacman", "-S", "--noconfirm", "netcat"],
    },
    "ligolo-ng": {
        "go": ["go", "install", "github.com/nicocha30/ligolo-ng/cmd/ligolo-ng@latest"],
        "brew": ["brew", "install", "ligolo-ng"],
    },
}


class ToolInstaller:
    """Detects and installs missing security tools."""

    def __init__(self) -> None:
        self._package_manager: str = self._detect_package_manager()
        self._install_history: list[ToolInstallResult] = []

    def _detect_package_manager(self) -> str:
        if shutil.which("apt-get"):
            return "apt"
        if shutil.which("brew"):
            return "brew"
        if shutil.which("choco"):
            return "choco"
        if shutil.which("pacman"):
            return "pacman"
        if shutil.which("dnf"):
            return "dnf"
        # Fallback: try pip for Python tools
        return "pip"

    def is_installed(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def check_many(self, tools: list[str]) -> dict[str, bool]:
        return {tool: self.is_installed(tool) for tool in tools}

    def install(self, tool: str) -> ToolInstallResult:
        result = ToolInstallResult(tool=tool)

        if self.is_installed(tool):
            result.success = True
            result.method = "already_installed"
            self._install_history.append(result)
            return result

        install_methods = _TOOL_INSTALL_MAP.get(tool, {})
        if not install_methods:
            result.error = f"No install method known for {tool}"
            logger.warning(result.error)
            return result

        # Try preferred package manager first, then fallbacks
        preferred_order = [self._package_manager, "pip", "go", "curl", "apt", "brew"]
        tried_methods = set()

        for method in preferred_order:
            if method in tried_methods:
                continue
            tried_methods.add(method)

            cmd = install_methods.get(method)
            if not cmd:
                continue

            logger.info("Installing %s via %s: %s", tool, method, " ".join(cmd))
            result.method = method

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.returncode == 0:
                    result.success = True
                    result.output = proc.stdout[:500]
                    logger.info("Successfully installed %s via %s", tool, method)
                    break
                result.error = proc.stderr[:500]
            except subprocess.TimeoutExpired:
                result.error = f"Installation of {tool} timed out after 120s"
            except FileNotFoundError:
                result.error = f"Package manager '{cmd[0]}' not found"
            except Exception as exc:
                result.error = str(exc)

        self._install_history.append(result)
        return result

    def install_many(self, tools: list[str]) -> list[ToolInstallResult]:
        return [self.install(tool) for tool in tools]

    def auto_install_missing(
        self, tools: list[str], interactive: bool = True
    ) -> list[ToolInstallResult]:
        results: list[ToolInstallResult] = []
        for tool in tools:
            if self.is_installed(tool):
                continue
            if interactive:
                logger.info("Tool '%s' is required but not found.", tool)
            results.append(self.install(tool))
        return results

    @property
    def history(self) -> list[ToolInstallResult]:
        return list(self._install_history)

    def reset(self) -> None:
        self._install_history.clear()


__all__ = ["ToolInstaller", "ToolInstallResult"]
