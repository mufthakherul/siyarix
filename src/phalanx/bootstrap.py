"""First-run bootstrap system for Phalanx.

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

PHALANX_HOME = Path.home() / ".phalanx"
INITIALIZED_MARKER = PHALANX_HOME / ".initialized"


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

    def __init__(self, phalanx_home: Path | None = None) -> None:
        self._home = phalanx_home or PHALANX_HOME
        self._result = BootstrapResult()

    @property
    def is_first_run(self) -> bool:
        return not (self._home / ".initialized").exists()

    def detect_platform(self) -> PlatformInfo:
        info = PlatformInfo(
            system=platform.system(),
            release=platform.release(),
            shell=os.environ.get("SHELL", ""),
            terminal=os.environ.get("TERM", "unknown"),
            python_version=sys.version,
        )
        # Detect WSL
        if "microsoft" in platform.release().lower() or "wsl" in platform.release().lower():
            info.is_wsl = True
        # Detect package manager
        if shutil.which("apt-get"):
            info.package_manager = "apt"
        elif shutil.which("brew"):
            info.package_manager = "brew"
        elif shutil.which("choco"):
            info.package_manager = "choco"
        elif shutil.which("pacman"):
            info.package_manager = "pacman"
        elif shutil.which("dnf"):
            info.package_manager = "dnf"
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

    def check_runtime_tools(self) -> dict[str, bool]:
        essential = ["nmap", "curl", "dig", "ping"]
        found = {}
        for tool in essential:
            found[tool] = shutil.which(tool) is not None
        return found

    def ensure_directory_structure(self) -> None:
        dirs = [
            self._home,
            self._home / "personas",
            self._home / "personas" / "custom",
            self._home / "plugins" / "installed",
            self._home / "plugins" / "available",
            self._home / "memory",
            self._home / "logs" / "sessions",
            self._home / "logs" / "audit",
            self._home / "vault",
            self._home / "cache" / "tool_outputs",
            self._home / "cache" / "ai_plans",
            self._home / "cache" / "dns",
            self._home / "templates" / "reports",
            self._home / "templates" / "playbooks",
            self._home / "masking",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def write_marker(self) -> None:
        marker = self._home / ".initialized"
        marker.write_text(
            f"# Phalanx initialized\n"
            f"version=2.0.0\n"
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

        logger.info("Phalanx first-run bootstrap starting...")

        # Platform detection
        self._result.platform = self.detect_platform()

        # Python version check
        if not self.check_python_version():
            self._result.errors.append(
                f"Python {'.'.join(str(v) for v in self.REQUIRED_PYTHON)}+ required, "
                f"found {sys.version_info.major}.{sys.version_info.minor}"
            )

        # Dependency check
        deps = self.check_dependencies()
        missing_deps = [k for k, v in deps.items() if not v]
        self._result.dependencies_ok = len(missing_deps) == 0
        if missing_deps and interactive:
            logger.warning("Missing dependencies: %s", ", ".join(missing_deps))

        # Runtime tools check
        tools = self.check_runtime_tools()
        self._result.tools_found = sum(1 for v in tools.values() if v)
        self._result.runtime_ok = self._result.tools_found >= 2  # At least 2 essential tools
        missing_tools = [k for k, v in tools.items() if not v]
        if missing_tools:
            self._result.warnings.append(f"Missing recommended tools: {', '.join(missing_tools)}")

        # Directory setup
        self.ensure_directory_structure()

        # Write initialization marker
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
    "PHALANX_HOME",
    "INITIALIZED_MARKER",
]
