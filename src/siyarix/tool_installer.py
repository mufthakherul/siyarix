# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool Installer Module for Siyarix.

Handles automated installation of security tools across different OS platforms
(Windows winget/choco, Linux apt/pacman/dnf, macOS brew).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import logging
from dataclasses import dataclass
from typing import Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class ToolInstallResult:
    """Result of a tool installation attempt."""

    tool: str
    success: bool
    method: str = ""
    output: str = ""
    error: str = ""


class ToolInstaller:
    """Installs system tools gracefully."""

    def __init__(self, console: Optional[Any] = None) -> None:
        self.console = console
        self._install_history: list[ToolInstallResult] = []

    def _print(self, msg: str) -> None:
        if self.console:
            self.console.print(msg)
        else:
            logger.info(msg)

    @property
    def history(self) -> list[ToolInstallResult]:
        return self._install_history

    def reset(self) -> None:
        self._install_history.clear()

    def is_installed(self, tool: str) -> bool:
        """Check if a tool is available on the system PATH."""
        return shutil.which(tool) is not None

    def check_many(self, tools: list[str]) -> dict[str, bool]:
        """Check multiple tools at once."""
        return {tool: self.is_installed(tool) for tool in tools}

    def install(self, tool: str, pkg: str | None = None) -> ToolInstallResult:
        """Install a tool and track the result."""
        if self.is_installed(tool):
            res = ToolInstallResult(tool=tool, success=True, method="already_installed")
            self._install_history.append(res)
            return res

        success = self.install_tool(tool, pkg)
        res = ToolInstallResult(
            tool=tool,
            success=success,
            method="auto" if success else "failed",
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

    def install_tool(self, tool: str, pkg: str | None = None) -> bool:
        """Install a system tool using the appropriate package manager."""
        pkg = pkg or tool
        self._print(f"  Installing [cyan]{tool}[/cyan]...")

        if os.name == "nt":
            return self._install_win(tool, pkg)
        else:
            return self._install_nix(tool, pkg)

    def _install_win(self, tool: str, pkg: str) -> bool:
        """Install on Windows via winget/choco without hanging Start-Process."""
        if shutil.which("winget"):
            WINGET_MAP = {
                "nmap": "Insecure.Nmap",
                "openssl": "ShiningLight.OpenSSL",
                "git": "Git.Git",
                "curl": "cURL.cURL",
                "ffuf": "ffuf.ffuf",
                "nuclei": "ProjectDiscovery.Nuclei",
                "yara": "VirusTotal.YARA"
            }
            winget_id = WINGET_MAP.get(tool) or WINGET_MAP.get(pkg)
            
            try:
                if winget_id:
                    cmd = [
                        "winget", "install", "--id", winget_id, "--exact",
                        "--silent", "--accept-package-agreements", "--accept-source-agreements"
                    ]
                else:
                    cmd = [
                        "winget", "install", pkg, 
                        "--silent", "--accept-package-agreements", "--accept-source-agreements"
                    ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]\u2713 {tool} installed via winget[/green]")
                    return True
                elif not result.returncode or "already installed" in result.stdout or "already installed" in result.stderr:
                    self._print(f"  [green]\u2713 {tool} already installed (verified via winget output)[/green]")
                    return True
            except Exception as e:
                logger.debug(f"Winget install failed: {e}")

        if shutil.which("choco"):
            try:
                cmd = ["choco", "install", "-y", pkg]
                subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]\u2713 {tool} installed via choco[/green]")
                    return True
            except Exception as e:
                logger.debug(f"Choco install failed: {e}")

        self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
        return False

    def _refresh_windows_path(self) -> None:
        """Attempt to refresh os.environ['PATH'] from the Windows Registry."""
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 0, winreg.KEY_READ) as key:
                sys_path, _ = winreg.QueryValueEx(key, 'PATH')
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_READ) as key:
                user_path, _ = winreg.QueryValueEx(key, 'PATH')
            os.environ['PATH'] = sys_path + ';' + user_path
        except Exception:
            pass

    def _install_nix(self, tool: str, pkg: str) -> bool:
        """Install on Linux/macOS via sudo."""
        pm = self._detect_pm()
        
        # Pre-update package index for reliable installs
        if pm in ("apt", "apt-get"):
            self._print("  Updating package index...")
            subprocess.run(["sudo", "-p", "Password required for update: ", pm, "update"], capture_output=True, timeout=120, check=False)
        elif pm == "brew":
            self._print("  Updating brew formulas...")
            subprocess.run(["brew", "update"], capture_output=True, timeout=120, check=False)

        install_cmd = {
            "apt": ["apt-get", "install", "-y", pkg],
            "apt-get": ["apt-get", "install", "-y", pkg],
            "brew": ["brew", "install", pkg],
            "pacman": ["pacman", "-Sy", "--noconfirm", pkg],
            "dnf": ["dnf", "install", "-y", pkg],
            "apk": ["apk", "add", pkg],
        }.get(pm, [pm, "install", "-y", pkg])

        try:
            self._print(f"  Running: sudo {' '.join(install_cmd)}")
            env = {**os.environ}
            if pm in ("apt", "apt-get"):
                env["DEBIAN_FRONTEND"] = "noninteractive"
            subprocess.run(
                ["sudo", "-p", "Password required for installation: "] + install_cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
                env=env,
            )
            if shutil.which(tool):
                self._print(f"  [green]\u2713 {tool} installed via {pm}[/green]")
                return True
        except Exception as e:
            logger.debug(f"{pm} install failed: {e}")

        self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
        return False

    def _detect_pm(self) -> str:
        for pm in ["apt-get", "brew", "pacman", "dnf", "apk"]:
            if shutil.which(pm):
                return pm
        return "apt-get"
