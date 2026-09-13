# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool Installer & Lifecycle Module for Siyarix.

Handles automated installation, uninstallation, updating, and recipe lookup
for cybersecurity tools across platforms (Windows winget/choco/scoop, Linux
apt/pacman/dnf/apk, macOS brew, Android/Termux pkg, pip, and go).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys as _sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import winreg
except ImportError:
    from unittest.mock import MagicMock as _MagicMock

    winreg = _MagicMock()
    _sys.modules["winreg"] = winreg

logger = logging.getLogger(__name__)


def tty_confirm(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question via /dev/tty, bypassing prompt_toolkit's raw mode."""
    import sys

    # Never block in non-interactive, headless, or automated environments
    if not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        return default

    from rich.console import Console

    suffix = " [Y/n]" if default else " [y/N]"
    Console(stderr=True).print(prompt + suffix, end=" ")
    try:
        with open("/dev/tty") as _tty:
            answer = _tty.readline().strip().lower()
    except Exception:
        try:
            answer = input().strip().lower()
        except Exception:
            answer = ""
    if not answer:
        return default
    return answer[0] == "y"


@dataclass
class ToolInstallResult:
    """Result of a tool installation or update attempt."""

    tool: str
    success: bool
    method: str = ""
    output: str = ""
    error: str = ""


@dataclass
class ToolUninstallResult:
    """Result of a tool uninstallation attempt."""

    tool: str
    success: bool
    method: str = ""
    output: str = ""
    error: str = ""


# Comprehensive multi-platform package recipes database
_TOOL_RECIPES: dict[str, dict[str, str]] = {
    "nmap": {
        "winget": "Insecure.Nmap",
        "choco": "nmap",
        "scoop": "nmap",
        "apt": "nmap",
        "pacman": "nmap",
        "dnf": "nmap",
        "apk": "nmap",
        "brew": "nmap",
        "pkg": "nmap",
    },
    "nikto": {
        "apt": "nikto",
        "pacman": "nikto",
        "dnf": "nikto",
        "brew": "nikto",
        "pkg": "nikto",
    },
    "sqlmap": {
        "apt": "sqlmap",
        "pacman": "sqlmap",
        "brew": "sqlmap",
        "pkg": "sqlmap",
        "pip": "sqlmap",
        "choco": "sqlmap",
    },
    "hydra": {
        "apt": "hydra",
        "pacman": "hydra",
        "brew": "hydra",
        "pkg": "hydra",
        "dnf": "hydra",
    },
    "nuclei": {
        "winget": "ProjectDiscovery.Nuclei",
        "choco": "nuclei",
        "scoop": "nuclei",
        "brew": "nuclei",
        "apt": "nuclei",
        "pacman": "nuclei",
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "subfinder": {
        "brew": "subfinder",
        "scoop": "subfinder",
        "apt": "subfinder",
        "pacman": "subfinder",
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "httpx": {
        "brew": "httpx",
        "scoop": "httpx",
        "pip": "httpx",
        "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "ffuf": {
        "winget": "ffuf.ffuf",
        "choco": "ffuf",
        "scoop": "ffuf",
        "brew": "ffuf",
        "pkg": "ffuf",
        "apt": "ffuf",
        "pacman": "ffuf",
        "go": "github.com/ffuf/ffuf/v2@latest",
    },
    "gobuster": {
        "brew": "gobuster",
        "pkg": "gobuster",
        "apt": "gobuster",
        "pacman": "gobuster",
        "go": "github.com/OJ/gobuster/v3@latest",
    },
    "amass": {
        "brew": "amass",
        "apt": "amass",
        "pacman": "amass",
        "scoop": "amass",
        "go": "github.com/owasp-amass/amass/v4/...@master",
    },
    "masscan": {
        "apt": "masscan",
        "pacman": "masscan",
        "brew": "masscan",
        "dnf": "masscan",
    },
    "rustscan": {
        "winget": "RustScan.RustScan",
        "scoop": "rustscan",
        "brew": "rustscan",
        "pacman": "rustscan",
        "apt": "rustscan",
    },
    "aircrack-ng": {
        "apt": "aircrack-ng",
        "pacman": "aircrack-ng",
        "brew": "aircrack-ng",
        "dnf": "aircrack-ng",
        "choco": "aircrack-ng",
    },
    "hashcat": {
        "winget": "Hashcat.Hashcat",
        "choco": "hashcat",
        "apt": "hashcat",
        "pacman": "hashcat",
        "brew": "hashcat",
        "dnf": "hashcat",
    },
    "john": {
        "winget": "JohnTheRipper.JohnTheRipper",
        "choco": "john",
        "apt": "john",
        "pacman": "john",
        "brew": "john",
        "dnf": "john",
    },
    "wireshark": {
        "winget": "WiresharkFoundation.Wireshark",
        "choco": "wireshark",
        "apt": "wireshark",
        "pacman": "wireshark-cli",
        "brew": "wireshark",
        "dnf": "wireshark-cli",
    },
    "tshark": {
        "apt": "tshark",
        "pacman": "wireshark-cli",
        "brew": "wireshark",
        "pkg": "tshark",
        "dnf": "wireshark-cli",
        "apk": "tshark",
    },
    "tcpdump": {
        "apt": "tcpdump",
        "pacman": "tcpdump",
        "brew": "tcpdump",
        "pkg": "tcpdump",
        "dnf": "tcpdump",
        "apk": "tcpdump",
    },
    "exiftool": {
        "apt": "libimage-exiftool-perl",
        "pacman": "perl-image-exiftool",
        "dnf": "perl-Image-ExifTool",
        "brew": "exiftool",
        "pkg": "exiftool",
        "scoop": "exiftool",
        "apk": "exiftool",
    },
    "radare2": {
        "apt": "radare2",
        "pacman": "radare2",
        "brew": "radare2",
        "pkg": "radare2",
        "dnf": "radare2",
    },
    "yara": {
        "winget": "VirusTotal.YARA",
        "choco": "yara",
        "apt": "yara",
        "pacman": "yara",
        "brew": "yara",
        "pkg": "yara",
        "dnf": "yara",
    },
    "impacket": {
        "apt": "python3-impacket",
        "pacman": "impacket",
        "pip": "impacket",
    },
    "metasploit": {
        "apt": "metasploit-framework",
        "pacman": "metasploit",
    },
    "semgrep": {
        "pip": "semgrep",
        "brew": "semgrep",
    },
    "bandit": {
        "pip": "bandit",
        "apt": "bandit",
        "brew": "bandit",
    },
    "trufflehog": {
        "brew": "trufflehog",
        "pip": "trufflehog",
        "go": "github.com/trufflesecurity/trufflehog/v3@latest",
    },
    "checkov": {
        "pip": "checkov",
        "brew": "checkov",
    },
    "prowler": {
        "pip": "prowler",
        "brew": "prowler",
    },
    "commix": {
        "apt": "commix",
        "pip": "commix",
    },
    "xsstrike": {
        "pip": "xsstrike",
    },
    "dalfox": {
        "brew": "dalfox",
        "go": "github.com/hahwul/dalfox/v2@latest",
    },
    "wafw00f": {
        "apt": "wafw00f",
        "pip": "wafw00f",
        "brew": "wafw00f",
    },
    "dig": {
        "apt": "dnsutils",
        "pacman": "bind",
        "dnf": "bind-utils",
        "brew": "bind",
        "pkg": "dnsutils",
    },
    "nslookup": {
        "apt": "dnsutils",
        "pkg": "dnsutils",
    },
    "netstat": {
        "apt": "net-tools",
        "pkg": "net-tools",
    },
    "whois": {
        "apt": "whois",
        "pacman": "whois",
        "dnf": "whois",
        "brew": "whois",
        "pkg": "whois",
    },
    "curl": {
        "winget": "cURL.cURL",
        "choco": "curl",
        "scoop": "curl",
        "apt": "curl",
        "pacman": "curl",
        "dnf": "curl",
        "apk": "curl",
        "brew": "curl",
        "pkg": "curl",
    },
    "git": {
        "winget": "Git.Git",
        "choco": "git",
        "scoop": "git",
        "apt": "git",
        "pacman": "git",
        "dnf": "git",
        "apk": "git",
        "brew": "git",
        "pkg": "git",
    },
    "openssl": {
        "winget": "ShiningLight.OpenSSL",
        "pkg": "openssl-tool",
        "apt": "openssl",
        "pacman": "openssl",
        "dnf": "openssl",
        "brew": "openssl",
    },
    "jq": {
        "winget": "jqlang.jq",
        "choco": "jq",
        "scoop": "jq",
        "apt": "jq",
        "pacman": "jq",
        "dnf": "jq",
        "apk": "jq",
        "brew": "jq",
        "pkg": "jq",
    },
}


class ToolInstaller:
    """Manages system tool installation, uninstallation, updating, and inspection."""

    def __init__(self, console: Optional[Any] = None) -> None:
        self.console = console
        self._install_history: list[ToolInstallResult] = []
        self._uninstall_history: list[ToolUninstallResult] = []

    def _print(self, msg: str) -> None:
        if self.console:
            self.console.print(msg)
        else:
            logger.info(msg)

    @property
    def history(self) -> list[ToolInstallResult]:
        return self._install_history

    @property
    def uninstall_history(self) -> list[ToolUninstallResult]:
        return self._uninstall_history

    def reset(self) -> None:
        self._install_history.clear()
        self._uninstall_history.clear()

    def is_installed(self, tool: str) -> bool:
        """Check if a tool is available on the system PATH or configured binary path."""
        try:
            from siyarix.tool_config import ToolConfigManager

            mgr = ToolConfigManager.get_instance()
            # Check user override binary path
            override = mgr.get_override(tool)
            if override and override.binary_path:
                p = Path(override.binary_path)
                if p.is_file() and (os.access(str(p), os.X_OK) or os.name == "nt"):
                    return True
            # Check custom tool binary
            custom = mgr.get_custom_tool(tool)
            if custom:
                p = Path(custom.binary)
                if p.is_file():
                    return True
                return shutil.which(custom.binary) is not None
        except Exception:
            pass

        return shutil.which(tool) is not None

    def check_many(self, tools: list[str]) -> dict[str, bool]:
        """Check multiple tools at once."""
        return {tool: self.is_installed(tool) for tool in tools}

    def resolve_package(self, tool: str, pm: str | None = None) -> str:
        """Resolve the package name or identifier for a tool and package manager."""
        pm = pm or self._detect_pm()
        recipes = _TOOL_RECIPES.get(tool.lower(), {})
        if pm in recipes:
            return recipes[pm]
        return tool

    def get_install_recipe(self, tool: str) -> dict[str, Any]:
        """Inspect the installation command and package manager for a tool."""
        pm = self._detect_pm()
        recipes = _TOOL_RECIPES.get(tool.lower(), {})
        pkg = recipes.get(pm, tool)

        is_installed = self.is_installed(tool)
        is_windows = os.name == "nt"

        if is_windows:
            if shutil.which("winget") and (recipes.get("winget") or pm == "winget"):
                wid = recipes.get("winget", tool)
                install_cmd = ["winget", "install", "--id", wid, "--exact", "--silent"]
                uninstall_cmd = ["winget", "uninstall", "--id", wid, "--exact", "--silent"]
                method = "winget"
            elif shutil.which("choco") and (recipes.get("choco") or pm == "choco"):
                cid = recipes.get("choco", tool)
                install_cmd = ["choco", "install", "-y", cid]
                uninstall_cmd = ["choco", "uninstall", "-y", cid]
                method = "choco"
            elif shutil.which("scoop") and (recipes.get("scoop") or pm == "scoop"):
                sid = recipes.get("scoop", tool)
                install_cmd = ["scoop", "install", sid]
                uninstall_cmd = ["scoop", "uninstall", sid]
                method = "scoop"
            elif "pip" in recipes:
                install_cmd = [_sys.executable, "-m", "pip", "install", recipes["pip"]]
                uninstall_cmd = [_sys.executable, "-m", "pip", "uninstall", "-y", recipes["pip"]]
                method = "pip"
            else:
                install_cmd = ["winget", "install", tool]
                uninstall_cmd = ["winget", "uninstall", tool]
                method = "winget"
        elif pm == "pkg":
            install_cmd = ["pkg", "install", "-y", pkg]
            uninstall_cmd = ["pkg", "uninstall", "-y", pkg]
            method = "pkg"
        elif pm == "brew":
            install_cmd = ["brew", "install", pkg]
            uninstall_cmd = ["brew", "uninstall", pkg]
            method = "brew"
        elif pm in ("apt", "apt-get"):
            install_cmd = ["sudo", "apt-get", "install", "-y", pkg]
            uninstall_cmd = ["sudo", "apt-get", "remove", "-y", pkg]
            method = "apt"
        elif pm == "pacman":
            install_cmd = ["sudo", "pacman", "-Sy", "--noconfirm", pkg]
            uninstall_cmd = ["sudo", "pacman", "-R", "--noconfirm", pkg]
            method = "pacman"
        elif pm == "dnf":
            install_cmd = ["sudo", "dnf", "install", "-y", pkg]
            uninstall_cmd = ["sudo", "dnf", "remove", "-y", pkg]
            method = "dnf"
        elif pm == "apk":
            install_cmd = ["apk", "add", pkg]
            uninstall_cmd = ["apk", "del", pkg]
            method = "apk"
        elif "pip" in recipes:
            install_cmd = [_sys.executable, "-m", "pip", "install", recipes["pip"]]
            uninstall_cmd = [_sys.executable, "-m", "pip", "uninstall", "-y", recipes["pip"]]
            method = "pip"
        else:
            install_cmd = [pm, "install", "-y", pkg]
            uninstall_cmd = [pm, "remove", "-y", pkg]
            method = pm

        return {
            "tool": tool,
            "installed": is_installed,
            "pm": pm,
            "package": pkg,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "method": method,
            "all_recipes": recipes,
        }

    def install(
        self, tool: str, pkg: str | None = None, method: str | None = None
    ) -> ToolInstallResult:
        """Install a tool and track the result."""
        if self.is_installed(tool):
            res = ToolInstallResult(tool=tool, success=True, method="already_installed")
            self._install_history.append(res)
            return res

        success = self.install_tool(tool, pkg, method=method)
        res = ToolInstallResult(
            tool=tool,
            success=success,
            method=method or ("auto" if success else "failed"),
        )
        if not success:
            res.error = f"No install method known or successful for {tool}"

        self._install_history.append(res)
        return res

    def auto_install_missing(self, tools: list[str]) -> list[ToolInstallResult]:
        """Install all missing tools from a list."""
        results = []
        for tool in tools:
            if not self.is_installed(tool):
                results.append(self.install(tool))
        return results

    def install_tool(self, tool: str, pkg: str | None = None, method: str | None = None) -> bool:
        """Install a system tool using the appropriate package manager or method."""
        pkg = pkg or self.resolve_package(tool, method)
        self._print(f"  Installing [cyan]{tool}[/cyan]...")

        success = False
        if method == "pip" or (
            not method
            and tool in _TOOL_RECIPES
            and "pip" in _TOOL_RECIPES[tool]
            and not shutil.which("winget")
            and not shutil.which("apt")
            and not shutil.which("brew")
        ):
            pip_pkg = _TOOL_RECIPES.get(tool, {}).get("pip", pkg)
            success = self._install_pip(pip_pkg)
        elif method == "go" or (
            not method
            and tool in _TOOL_RECIPES
            and "go" in _TOOL_RECIPES[tool]
            and shutil.which("go")
            and not self.is_installed(tool)
        ):
            go_url = _TOOL_RECIPES.get(tool, {}).get("go", "")
            if go_url:
                success = self._install_go(go_url)
        elif os.name == "nt":
            success = self._install_win(tool, pkg, method=method)
        else:
            success = self._install_nix(tool, pkg, method=method)

        # Fallback to pip if applicable
        if not success and tool in _TOOL_RECIPES and "pip" in _TOOL_RECIPES[tool]:
            self._print(f"  [dim]System install failed, trying pip for {tool}...[/dim]")
            pip_pkg = _TOOL_RECIPES[tool]["pip"]
            success = self._install_pip(pip_pkg)

        # Invalidate which cache on success
        if success:
            try:
                from siyarix.tool_models import invalidate_which_cache

                invalidate_which_cache()
            except Exception:
                pass

        return success

    def uninstall(
        self, tool: str, method: str | None = None, purge: bool = False
    ) -> ToolUninstallResult:
        """Uninstall a tool and track the result."""
        if not self.is_installed(tool):
            res = ToolUninstallResult(tool=tool, success=True, method="not_installed")
            self._uninstall_history.append(res)
            return res

        success = self.uninstall_tool(tool, method=method, purge=purge)
        res = ToolUninstallResult(
            tool=tool,
            success=success,
            method=method or ("auto" if success else "failed"),
        )
        if not success:
            res.error = f"Uninstallation failed or no package manager could remove {tool}"

        self._uninstall_history.append(res)
        return res

    def uninstall_tool(self, tool: str, method: str | None = None, purge: bool = False) -> bool:
        """Uninstall a tool using the appropriate package manager."""
        self._print(f"  Uninstalling [cyan]{tool}[/cyan]...")

        # 1. Check if custom tool
        try:
            from siyarix.tool_config import ToolConfigManager

            mgr = ToolConfigManager.get_instance()
            if mgr.get_custom_tool(tool):
                mgr.remove_custom_tool(tool)
                self._print(f"  [green]✓ Removed custom tool definition for {tool}[/green]")
                return True
        except Exception:
            pass

        pkg = self.resolve_package(tool, method)
        success = False

        if method == "pip":
            pip_pkg = _TOOL_RECIPES.get(tool, {}).get("pip", pkg)
            success = self._uninstall_pip(pip_pkg)
        elif os.name == "nt":
            success = self._uninstall_win(tool, pkg, method=method)
        else:
            success = self._uninstall_nix(tool, pkg, method=method, purge=purge)

        # Fallback to pip if still present and known pip tool
        if not success and tool in _TOOL_RECIPES and "pip" in _TOOL_RECIPES[tool]:
            pip_pkg = _TOOL_RECIPES[tool]["pip"]
            success = self._uninstall_pip(pip_pkg)

        if success:
            try:
                from siyarix.tool_models import invalidate_which_cache

                invalidate_which_cache()
            except Exception:
                pass

        return success

    def update(self, tool: str, method: str | None = None) -> ToolInstallResult:
        """Update an installed tool to its latest version."""
        success = self.update_tool(tool, method=method)
        res = ToolInstallResult(
            tool=tool,
            success=success,
            method=method or ("update" if success else "failed"),
        )
        if not success:
            res.error = f"Update failed for {tool}"
        self._install_history.append(res)
        return res

    def update_tool(self, tool: str, method: str | None = None) -> bool:
        """Update a tool using the appropriate package manager."""
        self._print(f"  Updating [cyan]{tool}[/cyan]...")
        pkg = self.resolve_package(tool, method)

        if os.name == "nt":
            if shutil.which("winget"):
                wid = _TOOL_RECIPES.get(tool, {}).get("winget") or pkg
                cmd = ["winget", "upgrade", "--id", wid, "--exact", "--silent"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via winget[/green]")
                    return True
            if shutil.which("choco"):
                cmd = ["choco", "upgrade", "-y", pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via choco[/green]")
                    return True
        else:
            pm = self._detect_pm()
            if pm == "pkg":
                cmd = ["pkg", "upgrade", "-y", pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via pkg[/green]")
                    return True
            elif pm == "brew":
                cmd = ["brew", "upgrade", pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via brew[/green]")
                    return True
            elif pm in ("apt", "apt-get"):
                cmd = ["sudo", "apt-get", "install", "--only-upgrade", "-y", pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via apt[/green]")
                    return True
            elif pm == "pacman":
                cmd = ["sudo", "pacman", "-S", "--noconfirm", pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} updated via pacman[/green]")
                    return True

        # Try pip update if pip recipe exists
        if tool in _TOOL_RECIPES and "pip" in _TOOL_RECIPES[tool]:
            pip_pkg = _TOOL_RECIPES[tool]["pip"]
            cmd = [_sys.executable, "-m", "pip", "install", "--upgrade", pip_pkg]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            if res.returncode == 0:
                self._print(f"  [green]✓ {tool} updated via pip[/green]")
                return True

        self._print(f"  [yellow]Could not automatically update {tool}.[/yellow]")
        return False

    # ── Platform Install / Uninstall Handlers ──────────────────────────────

    def _install_win(self, tool: str, pkg: str, method: str | None = None) -> bool:
        """Install on Windows via winget/choco/scoop."""
        recipe = _TOOL_RECIPES.get(tool.lower(), {})

        if (not method or method == "winget") and shutil.which("winget"):
            winget_id = recipe.get("winget") or pkg
            try:
                cmd = [
                    "winget",
                    "install",
                    "--id",
                    winget_id,
                    "--exact",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]✓ {tool} installed via winget[/green]")
                    return True
                elif (
                    not result.returncode
                    or "already installed" in result.stdout
                    or "already installed" in result.stderr
                ):
                    self._print(
                        f"  [green]✓ {tool} already installed (verified via winget output)[/green]"
                    )
                    return True
            except Exception as e:
                logger.debug("Winget install failed: %s", e)

        if (not method or method == "choco") and shutil.which("choco"):
            choco_pkg = recipe.get("choco") or pkg
            try:
                cmd = ["choco", "install", "-y", choco_pkg]
                subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]✓ {tool} installed via choco[/green]")
                    return True
            except Exception as e:
                logger.debug("Choco install failed: %s", e)

        if (not method or method == "scoop") and shutil.which("scoop"):
            scoop_pkg = recipe.get("scoop") or pkg
            try:
                cmd = ["scoop", "install", scoop_pkg]
                subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]✓ {tool} installed via scoop[/green]")
                    return True
            except Exception as e:
                logger.debug("Scoop install failed: %s", e)

        self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
        return False

    def _uninstall_win(self, tool: str, pkg: str, method: str | None = None) -> bool:
        """Uninstall on Windows via winget/choco/scoop."""
        recipe = _TOOL_RECIPES.get(tool.lower(), {})

        if (not method or method == "winget") and shutil.which("winget"):
            winget_id = recipe.get("winget") or pkg
            try:
                cmd = ["winget", "uninstall", "--id", winget_id, "--exact", "--silent"]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                if result.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via winget[/green]")
                    return True
            except Exception as e:
                logger.debug("Winget uninstall failed: %s", e)

        if (not method or method == "choco") and shutil.which("choco"):
            choco_pkg = recipe.get("choco") or pkg
            try:
                cmd = ["choco", "uninstall", "-y", choco_pkg]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                if result.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via choco[/green]")
                    return True
            except Exception as e:
                logger.debug("Choco uninstall failed: %s", e)

        if (not method or method == "scoop") and shutil.which("scoop"):
            scoop_pkg = recipe.get("scoop") or pkg
            try:
                cmd = ["scoop", "uninstall", scoop_pkg]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                if result.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via scoop[/green]")
                    return True
            except Exception as e:
                logger.debug("Scoop uninstall failed: %s", e)

        self._print(f"  [yellow]Could not auto-uninstall {tool}.[/yellow]")
        return False

    def _refresh_windows_path(self) -> None:
        """Refresh os.environ['PATH'] from the Windows Registry."""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0,
                winreg.KEY_READ,
            ) as key:
                sys_path, _ = winreg.QueryValueEx(key, "PATH")
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Environment",
                0,
                winreg.KEY_READ,
            ) as key:
                user_path, _ = winreg.QueryValueEx(key, "PATH")
            os.environ["PATH"] = (
                str(sys_path) + ";" + str(user_path) + ";" + os.environ.get("PATH", "")
            )
        except Exception as exc:
            logger.debug("Failed to refresh Windows PATH: %s", exc)

    def _install_nix(self, tool: str, pkg: str, method: str | None = None) -> bool:
        """Install on Linux/macOS. Tries sudo first, falls back to user-only."""
        pm = method or self._detect_pm()
        recipe = _TOOL_RECIPES.get(tool.lower(), {})
        pkg = recipe.get(pm, pkg)

        # Termux native package manager handling (never uses sudo)
        if pm == "pkg":
            cmd = ["pkg", "install", "-y", pkg]
            try:
                self._print(f"  Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, stdin=_sys.stdin, timeout=300, check=False)
                if result.returncode == 0 or shutil.which(tool):
                    self._print(f"  [green]✓ {tool} installed via pkg[/green]")
                    return True
            except (subprocess.SubprocessError, PermissionError) as e:
                logger.debug("pkg install failed: %s", e)
            self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
            return False

        if pm in ("apt", "apt-get"):
            if pkg == "":
                self._print(
                    f"  [yellow]{tool} is not available via apt; install manually.[/yellow]"
                )
                return False
            self._print("  Updating package index...")
            subprocess.run(
                ["sudo", "-p", "Password required for update: ", pm, "update"],
                stdin=_sys.stdin,
                timeout=120,
                check=False,
            )
        elif pm == "brew":
            self._print("  Updating brew formulas...")
            subprocess.run(["brew", "update"], timeout=120, check=False)

        is_deb = pm in ("apt", "apt-get")
        if is_deb:
            base_cmd = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", pkg]
        else:
            base_cmd = {
                "brew": ["brew", "install", pkg],
                "pacman": ["pacman", "-Sy", "--noconfirm", pkg],
                "dnf": ["dnf", "install", "-y", pkg],
                "apk": ["apk", "add", pkg],
            }.get(pm, [pm, "install", "-y", pkg])

        for use_sudo in [True, False] if pm != "brew" else [False]:
            cmd = (["sudo", "-p", "Password required: "] + base_cmd) if use_sudo else base_cmd
            try:
                self._print(f"  Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, stdin=_sys.stdin, timeout=300, check=False)
                if result.returncode == 0 or shutil.which(tool):
                    self._print(f"  [green]✓ {tool} installed via {pm}[/green]")
                    return True
            except (subprocess.SubprocessError, PermissionError) as e:
                logger.debug("%s install failed (sudo=%s): %s", pm, use_sudo, e)
                continue

        self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
        return False

    def _uninstall_nix(
        self, tool: str, pkg: str, method: str | None = None, purge: bool = False
    ) -> bool:
        """Uninstall on Linux/macOS."""
        pm = method or self._detect_pm()
        recipe = _TOOL_RECIPES.get(tool.lower(), {})
        pkg = recipe.get(pm, pkg)

        if pm == "pkg":
            cmd = ["pkg", "uninstall", "-y", pkg]
            try:
                res = subprocess.run(cmd, stdin=_sys.stdin, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via pkg[/green]")
                    return True
            except Exception as e:
                logger.debug("pkg uninstall failed: %s", e)
            return False

        if pm == "brew":
            cmd = ["brew", "uninstall", pkg]
            try:
                res = subprocess.run(cmd, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via brew[/green]")
                    return True
            except Exception as e:
                logger.debug("brew uninstall failed: %s", e)
            return False

        action = "purge" if purge else "remove"
        if pm in ("apt", "apt-get"):
            base_cmd = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", action, "-y", pkg]
        elif pm == "pacman":
            flags = (
                ["-R", "--cascade", "--nosave", "--noconfirm"] if purge else ["-R", "--noconfirm"]
            )
            base_cmd = ["pacman", *flags, pkg]
        elif pm == "dnf":
            base_cmd = ["dnf", "remove", "-y", pkg]
        elif pm == "apk":
            base_cmd = ["apk", "del", pkg]
        else:
            base_cmd = [pm, "remove", "-y", pkg]

        for use_sudo in [True, False]:
            cmd = (["sudo", "-p", "Password required: "] + base_cmd) if use_sudo else base_cmd
            try:
                res = subprocess.run(cmd, stdin=_sys.stdin, timeout=300, check=False)
                if res.returncode == 0:
                    self._print(f"  [green]✓ {tool} uninstalled via {pm}[/green]")
                    return True
            except Exception as e:
                logger.debug("%s uninstall failed (sudo=%s): %s", pm, use_sudo, e)

        self._print(f"  [yellow]Could not auto-uninstall {tool}.[/yellow]")
        return False

    def _install_pip(self, pkg: str) -> bool:
        """Install a tool via Python pip."""
        from siyarix.chat.platform_utils import pip_install_args

        cmd = pip_install_args(pkg)
        try:
            self._print(f"  Running pip: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            if res.returncode == 0:
                self._print(f"  [green]✓ {pkg} installed via pip[/green]")
                return True
        except Exception as e:
            logger.debug("pip install failed: %s", e)
        return False

    def _uninstall_pip(self, pkg: str) -> bool:
        """Uninstall a tool via Python pip."""
        cmd = [_sys.executable, "-m", "pip", "uninstall", "-y", pkg]
        try:
            self._print(f"  Running pip uninstall: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            if res.returncode == 0:
                self._print(f"  [green]✓ {pkg} uninstalled via pip[/green]")
                return True
        except Exception as e:
            logger.debug("pip uninstall failed: %s", e)
        return False

    def _install_go(self, url: str) -> bool:
        """Install a tool via go install."""
        if not shutil.which("go"):
            return False
        cmd = ["go", "install", url]
        try:
            self._print(f"  Running go install: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            if res.returncode == 0:
                self._print("  [green]✓ Tool installed via go install[/green]")
                return True
        except Exception as e:
            logger.debug("go install failed: %s", e)
        return False

    def _detect_pm(self) -> str:
        from siyarix._platform import is_termux

        if is_termux() or shutil.which("pkg"):
            return "pkg"
        for pm in ["apt-get", "apt", "brew", "pacman", "dnf", "apk"]:
            if shutil.which(pm):
                return pm
        return "apt-get"


__all__ = [
    "ToolInstallResult",
    "ToolUninstallResult",
    "ToolInstaller",
    "tty_confirm",
]
