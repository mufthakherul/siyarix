# SPDX-License-Identifier: AGPL-3.0-or-later

"""First-run bootstrap system for Siyarix.

Handles initial setup, platform detection, dependency verification,
and first-run marker management as described in Chapter 2.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SIYARIX_HOME = Path.home() / ".siyarix"
INITIALIZED_MARKER = SIYARIX_HOME / ".initialized"


@dataclass
class PlatformInfo:
    """Detailed platform detection information."""

    system: str = ""
    release: str = ""
    shell: str = ""
    terminal: str = ""
    is_wsl: bool = False
    package_manager: str = ""
    python_version: str = ""


@dataclass
class BootstrapResult:
    """Result of the bootstrap process."""

    success: bool = False
    first_run: bool = False
    platform: PlatformInfo = field(default_factory=PlatformInfo)
    dependencies_ok: bool = False
    runtime_ok: bool = False
    tools_found: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    completed_at: str = ""


class BootstrapEngine:
    """First-run bootstrap and platform detection engine."""

    REQUIRED_PYTHON = (3, 11)

    def __init__(self, siyarix_home: Path | None = None) -> None:
        self._home = siyarix_home or SIYARIX_HOME
        self._result = BootstrapResult()

    @property
    def is_first_run(self) -> bool:
        return not (self._home / ".initialized").exists()

    def detect_platform(self) -> PlatformInfo:
        _sys = platform.system()
        info = PlatformInfo(
            system=_sys,
            release=platform.release(),
            shell=self._detect_shell(),
            terminal=os.environ.get("TERM", "unknown"),
            python_version=sys.version,
        )
        # Detect WSL
        if _sys == "Linux" and (
            "microsoft" in platform.release().lower()
            or "wsl" in platform.release().lower()
        ):
            info.is_wsl = True
        # Detect package manager
        if shutil.which("apt-get"):
            info.package_manager = "apt"
        elif shutil.which("brew"):
            info.package_manager = "brew"
        elif shutil.which("pkg"):
            info.package_manager = "pkg"
        elif shutil.which("choco"):
            info.package_manager = "choco"
        elif shutil.which("winget"):
            info.package_manager = "winget"
        elif shutil.which("pacman"):
            info.package_manager = "pacman"
        elif shutil.which("dnf"):
            info.package_manager = "dnf"
        elif shutil.which("apk"):
            info.package_manager = "apk"
        return info

    def check_python_version(self) -> bool:
        current = (sys.version_info.major, sys.version_info.minor)
        return current >= self.REQUIRED_PYTHON

    def check_dependencies(self) -> dict[str, bool]:
        deps = {}
        try:
            import pydantic

            deps["pydantic"] = True
            del pydantic
        except ImportError:
            deps["pydantic"] = False
        try:
            import rich

            deps["rich"] = True
            del rich
        except ImportError:
            deps["rich"] = False
        try:
            import httpx

            deps["httpx"] = True
            del httpx
        except ImportError:
            deps["httpx"] = False
        return deps

    def _detect_shell(self) -> str:
        if os.name == "nt":
            return os.environ.get("COMSPEC", "cmd.exe").lower()
        return os.environ.get("SHELL", "/bin/sh").lower()

    def _detect_terminal_from_env(self) -> str:
        """Detect terminal emulator."""
        term_program = os.environ.get("TERM_PROGRAM", "")
        term = os.environ.get("TERM", "")
        if term_program:
            return term_program
        if term:
            return term
        return "unknown"

    def check_database_backend(self) -> dict[str, bool]:
        """Check database backend availability (T7)."""
        result: dict[str, bool] = {"sqlite": True, "redis": False, "postgres": False}
        try:
            import sqlite3

            sqlite3.connect(":memory:").close()
            result["sqlite"] = True
        except Exception:
            result["sqlite"] = False
        try:
            import redis

            result["redis"] = True
            del redis
        except ImportError:
            result["redis"] = False
        try:
            import psycopg2

            result["postgres"] = True
            del psycopg2
        except ImportError:
            result["postgres"] = False
        return result

    def check_runtime_tools(self) -> dict[str, bool]:
        essential = ["nmap", "curl", "dig", "ping", "whois", "openssl"]
        found = {}
        for tool in essential:
            found[tool] = shutil.which(tool) is not None
        return found

    def check_optional_tools(self) -> dict[str, bool]:
        optional = [
            "nuclei",
            "ffuf",
            "gobuster",
            "subfinder",
            "httpx",
            "dnsx",
            "masscan",
            "nikto",
            "sqlmap",
            "hydra",
            "john",
            "hashcat",
            "trufflehog",
            "gitleaks",
            "docker",
            "kubectl",
            "terraform",
            "aws",
            "az",
            "gcloud",
        ]
        found = {}
        for tool in optional:
            found[tool] = shutil.which(tool) is not None
        return found

    def prompt_install_missing(
        self, missing: list[str], interactive: bool
    ) -> list[str]:
        """Prompt user for missing dependency installation (T9)."""
        if not interactive or not missing:
            return []
        try:
            from rich.console import Console
            from rich.prompt import Prompt

            c = Console()
            c.print(f"[yellow]Missing dependencies: {', '.join(missing)}[/yellow]")
            approved = []
            for dep in missing:
                answer = Prompt.ask(
                    f"Install {dep}?", choices=["y", "n", "a"], default="y"
                )
                if answer.lower() in ("y", "a"):
                    approved.append(dep)
            return approved
        except ImportError:
            return missing  # Auto-approve if rich not available

    def auto_install_packages(self, packages: list[str]) -> dict[str, bool]:
        """Auto-install approved packages (T10)."""
        import subprocess  # nosec B404

        results: dict[str, bool] = {}
        for pkg in packages:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )  # nosec B603
                results[pkg] = result.returncode == 0
            except Exception as exc:
                logger.warning("Failed to install %s: %s", pkg, exc)
                results[pkg] = False
        return results

    def ensure_directory_structure(self) -> None:
        dirs = [
            self._home,
            self._home / "personas",
            self._home / "personas" / "custom",
            self._home / "profiles",
            self._home / "memory",
            self._home / "logs" / "sessions",
            self._home / "logs" / "audit",
            self._home / "vault" / "keys",
            self._home / "vault" / "tokens",
            self._home / "cache" / "tool_outputs",
            self._home / "cache" / "ai_plans",
            self._home / "cache" / "dns",
            self._home / "cache" / "intel",
            self._home / "cache" / "scan_results",
            self._home / "cache" / "user_data",
            self._home / "templates" / "reports",
            self._home / "templates" / "playbooks",
            self._home / "playbooks",
            self._home / "achievements",
            self._home / "sessions",
            self._home / "masking",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        # Create config.yaml alias pointing to settings.toml (Appendix C)
        config_alias = self._home / "config.yaml"
        if not config_alias.exists():
            try:
                config_alias.write_text(
                    "# Siyarix configuration\n"
                    "# This file is an alias entry point.\n"
                    "# Actual settings are stored in settings.toml\n"
                )
            except OSError:
                pass

    def write_marker(self) -> None:
        marker = self._home / ".initialized"
        marker.write_text(
            f"# Siyarix initialized\n"
            f"version=1.0.0\n"
            f"created_at={datetime.now().isoformat()}\n"
            f"platform={platform.system()}\n"
            f"python={sys.version}\n"
        )

    async def run(self, interactive: bool = True) -> BootstrapResult:
        self._result = BootstrapResult(first_run=self.is_first_run)

        if not self.is_first_run:
            self._result.success = True
            self._result.dependencies_ok = True
            self._result.runtime_ok = True
            logger.debug("Bootstrap: already initialized, skipping")
            return self._result

        logger.info("Siyarix first-run bootstrap starting...")

        # T1-T2: Platform detection
        self._result.platform = self.detect_platform()

        # T3: Terminal/shell detection
        detected_shell = self._detect_shell()
        detected_terminal = self._detect_terminal_from_env()
        self._result.platform.shell = detected_shell
        self._result.platform.terminal = detected_terminal

        # T5: Python version check
        if not self.check_python_version():
            self._result.errors.append(
                f"Python {'.'.join(str(v) for v in self.REQUIRED_PYTHON)}+ required, "
                f"found {sys.version_info.major}.{sys.version_info.minor}"
            )

        # T6: Dependency check
        deps = self.check_dependencies()
        missing_deps = [k for k, v in deps.items() if not v]
        self._result.dependencies_ok = len(missing_deps) == 0

        # T7: Database backend check
        db_status = self.check_database_backend()
        if not db_status.get("sqlite", False):
            self._result.warnings.append(
                "SQLite not available — session persistence disabled"
            )

        # T8: Runtime tools check
        tools = self.check_runtime_tools()
        self._result.tools_found = sum(1 for v in tools.values() if v)
        self._result.runtime_ok = self._result.tools_found >= 2
        missing_tools = [k for k, v in tools.items() if not v]
        if missing_tools:
            self._result.warnings.append(
                f"Missing recommended tools: {', '.join(missing_tools)}"
            )

        # T9-T10: Interactive install prompt for missing deps
        if missing_deps and interactive:
            approved = self.prompt_install_missing(missing_deps, interactive)
            if approved:
                install_results = self.auto_install_packages(approved)
                success_count = sum(1 for v in install_results.values() if v)
                fail_count = len(approved) - success_count
                if fail_count > 0:
                    failed = [p for p, s in install_results.items() if not s]
                    self._result.warnings.append(
                        f"Failed to auto-install: {', '.join(failed)}"
                    )

        # Directory setup (T4)
        self.ensure_directory_structure()

        # T11: Write initialization marker
        self.write_marker()

        self._result.success = len(self._result.errors) == 0
        self._result.completed_at = datetime.now().isoformat()

        logger.info(
            "Bootstrap complete: %d tools found, %d warnings, %d errors",
            self._result.tools_found,
            len(self._result.warnings),
            len(self._result.errors),
        )
        return self._result


__all__ = [
    "BootstrapEngine",
    "BootstrapResult",
    "PlatformInfo",
    "SIYARIX_HOME",
    "INITIALIZED_MARKER",
]
