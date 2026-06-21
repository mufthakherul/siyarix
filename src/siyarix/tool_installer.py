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
                "yara": "VirusTotal.YARA",
            }
            winget_id = WINGET_MAP.get(tool) or WINGET_MAP.get(pkg)

            try:
                if winget_id:
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
                else:
                    cmd = [
                        "winget",
                        "install",
                        pkg,
                        "--silent",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                self._refresh_windows_path()
                if shutil.which(tool):
                    self._print(f"  [green]\u2713 {tool} installed via winget[/green]")
                    return True
                elif (
                    not result.returncode
                    or "already installed" in result.stdout
                    or "already installed" in result.stderr
                ):
                    self._print(
                        f"  [green]\u2713 {tool} already installed (verified via winget output)[/green]"
                    )
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
        """Refresh os.environ['PATH'] from the Windows Registry."""
        try:
            import winreg

            with winreg.OpenKey(  # type: ignore[attr-defined]
                winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0,
                winreg.KEY_READ,  # type: ignore[attr-defined]
            ) as key:
                sys_path, _ = winreg.QueryValueEx(key, "PATH")  # type: ignore[attr-defined]
            with winreg.OpenKey(  # type: ignore[attr-defined]
                winreg.HKEY_CURRENT_USER,  # type: ignore[attr-defined]
                r"Environment",
                0,
                winreg.KEY_READ,  # type: ignore[attr-defined]
            ) as key:
                user_path, _ = winreg.QueryValueEx(key, "PATH")  # type: ignore[attr-defined]
            os.environ["PATH"] = sys_path + ";" + user_path + ";" + os.environ.get("PATH", "")
        except Exception as exc:
            logger.debug("Failed to refresh Windows PATH: %s", exc)

    def _install_nix(self, tool: str, pkg: str) -> bool:
        """Install on Linux/macOS. Tries sudo first, falls back to user-only."""
        pm = self._detect_pm()

        # Map common tool names to correct package names per package manager
        _APT_PKG_MAP = {
            "metasploit": "metasploit-framework",
            "impacket": "python3-impacket",
            "mimikatz": "",  # not in apt repos; skip
            "exiftool": "libimage-exiftool-perl",
        }
        if pm in ("apt", "apt-get"):
            mapped = _APT_PKG_MAP.get(tool)
            if mapped == "":
                self._print(f"  [yellow]{tool} is not available via apt; install manually.[/yellow]")
                return False
            pkg = mapped or pkg

        if pm in ("apt", "apt-get"):
            self._print("  Updating package index...")
            subprocess.run(
                ["sudo", "-p", "Password required for update: ", pm, "update"],
                capture_output=True,
                timeout=120,
                check=False,
            )
        elif pm == "brew":
            self._print("  Updating brew formulas...")
            subprocess.run(["brew", "update"], capture_output=True, timeout=120, check=False)

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
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, check=False
                )
                if result.returncode == 0 or shutil.which(tool):
                    if shutil.which(tool):
                        self._print(f"  [green]\u2713 {tool} installed via {pm}[/green]")
                        return True
            except (subprocess.SubprocessError, PermissionError) as e:
                logger.debug(f"{pm} install failed (sudo={use_sudo}): {e}")
                continue

        self._print(f"  [yellow]Could not auto-install {tool}.[/yellow]")
        return False

    def _detect_pm(self) -> str:
        for pm in ["apt-get", "brew", "pacman", "dnf", "apk"]:
            if shutil.which(pm):
                return pm
        return "apt-get"
