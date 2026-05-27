"""Dynamic tool/command resolver with safety validation.

Resolves autonomous task suggestions and shell commands to safe, executable
commands. Enforces an allowlist and blocks dangerous/injected commands via
``DangerAnalyzer`` (from *security_hardening*) before execution.

This module acts as the security gate between the task planner and the
actual subprocess executor.
"""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass

from phalanx.security_hardening import (
    _INJECTION_PATTERNS,
    danger_analyzer,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety allowlists
# ---------------------------------------------------------------------------

# Commands that are ALWAYS safe to suggest (even outside the security tool registry)
_SAFE_COMMANDS: frozenset[str] = frozenset(
    {
        # Security tools
        "nmap",
        "nikto",
        "sqlmap",
        "gobuster",
        "ffuf",
        "masscan",
        "wpscan",
        "nuclei",
        "hydra",
        "john",
        "hashcat",
        "msfconsole",
        "zap.sh",
        "burpsuite",
        # Development/testing tools
        "pytest",
        "python",
        "python3",
        "node",
        "npm",
        "npx",
        "playwright",
        "vitest",
        "jest",
        "cargo",
        "go",
        "rustc",
        "gcc",
        "make",
        "cmake",
        # System info (read-only)
        "cat",
        "ls",
        "find",
        "grep",
        "awk",
        "sed",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "curl",
        "wget",
        "dig",
        "nslookup",
        "whois",
        "traceroute",
        "ping",
        "netstat",
        "ss",
        "ip",
        "ifconfig",
        "uname",
        "whoami",
        "hostname",
        "date",
        "uptime",
        "df",
        "du",
        "free",
        "lsof",
        "ps",
        "top",
        # Docker
        "docker",
        "docker-compose",
        "podman",
        # Git
        "git",
        "gh",
        "gitlab",
        # Cloud & IaC
        "kubectl",
        "helm",
        "terraform",
        "ansible",
        "aws",
        "gcloud",
        "az",
        "cloudflared",
        # Remote
        "ssh",
        "scp",
        "rsync",
        "mosh",
        # Databases
        "psql",
        "mysql",
        "sqlite3",
        "redis-cli",
        # Node/Python package managers
        "pnpm",
        "yarn",
        "bun",
        "uv",
        "poetry",
        # Package managers (install only, not uninstall)
        "pip",
        "pip3",
    }
)

# Environment variable patterns that might indicate secrets
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\{?(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\}?", re.IGNORECASE),
    re.compile(r"(?i)(?:password|passwd|pwd|secret|token|auth)\s*[=:]\s*\S+"),
]


@dataclass
class ResolvedCommand:
    """A validated, safe command ready for execution."""

    executable: str
    args: list[str]
    is_registered_tool: bool
    path: str
    safety_score: float  # 0.0 = blocked, 1.0 = fully trusted
    warnings: list[str]

    @property
    def is_safe(self) -> bool:
        return self.safety_score > 0.0

    @property
    def full_command(self) -> list[str]:
        return [self.path, *self.args]


class DynamicResolver:
    """Resolves tool names and commands to safe executables.

    This is the security boundary between autonomous actions and
    actual system execution. All commands pass through safety validation.
    """

    def __init__(
        self,
        registered_tools: dict[str, str] | None = None,
        extra_safe_commands: set[str] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        registered_tools:
            Mapping of tool name → executable path from the static ToolRegistry.
        extra_safe_commands:
            Additional commands to treat as safe (e.g., from plugins).
        """
        self._registered_tools = registered_tools or {}
        self._safe_commands = _SAFE_COMMANDS | (extra_safe_commands or set())

    def resolve(
        self,
        tool_or_command: str,
        args: list[str] | None = None,
    ) -> ResolvedCommand:
        """Resolve a tool name or command string to a safe executable.

        Parameters
        ----------
        tool_or_command:
            Either a tool name (e.g., "nmap") or a full command string.
        args:
            Optional list of arguments (if tool_or_command is a tool name).

        Returns
        -------
        ResolvedCommand with safety validation results.
        """
        args = args or []
        warnings: list[str] = []

        # 1) Check if it's a registered security tool (highest trust)
        if tool_or_command in self._registered_tools:
            return ResolvedCommand(
                executable=tool_or_command,
                args=args,
                is_registered_tool=True,
                path=self._registered_tools[tool_or_command],
                safety_score=1.0,
                warnings=[],
            )

        # 2) Check for dangerous command patterns via DangerAnalyzer
        full_cmd = f"{tool_or_command} {' '.join(args)}"
        report = danger_analyzer.analyze(full_cmd)
        if report.severity in ("critical", "high"):
            logger.warning("Blocked dangerous command: %s", full_cmd)
            return ResolvedCommand(
                executable=tool_or_command,
                args=args,
                is_registered_tool=False,
                path="",
                safety_score=0.0,
                warnings=report.reasons[:1],
            )

        # 3) Check for injection patterns (shared with InputValidator)
        for name, pattern in _INJECTION_PATTERNS:
            if pattern.search(full_cmd):
                logger.warning("Blocked injection (%s): %s", name, full_cmd)
                return ResolvedCommand(
                    executable=tool_or_command,
                    args=args,
                    is_registered_tool=False,
                    path="",
                    safety_score=0.0,
                    warnings=[f"Blocked: injection pattern '{name}' detected"],
                )

        # 4) Check for secret leaks
        for pattern in _SECRET_PATTERNS:
            if pattern.search(full_cmd):
                warnings.append("Command may reference sensitive environment variables")

        # 5) Check if the command is in the safe allowlist
        base_cmd = (
            tool_or_command.split()[0] if " " in tool_or_command else tool_or_command
        )
        is_safe = base_cmd in self._safe_commands

        # 5) Try to find the executable on PATH
        path = shutil.which(base_cmd)
        if not path:
            not_found_warnings = [*warnings, f"Command '{base_cmd}' not found on PATH"]
            return ResolvedCommand(
                executable=base_cmd,
                args=args,
                is_registered_tool=False,
                path="",
                safety_score=0.0,
                warnings=not_found_warnings,
            )

        # 6) Calculate safety score
        safety_score = 0.8 if is_safe else 0.4
        if warnings:
            safety_score -= 0.1

        if not is_safe:
            warnings.append(
                f"Command '{base_cmd}' is not in the known safe list; "
                "will require user confirmation"
            )

        return ResolvedCommand(
            executable=base_cmd,
            args=args,
            is_registered_tool=False,
            path=path,
            safety_score=safety_score,
            warnings=warnings,
        )

    def has_arg_injection(self, args: list[str]) -> tuple[bool, str]:
        """Check a list of arguments for injection patterns (delegates to InputValidator's patterns)."""
        full = " ".join(args)
        for name, pattern in _INJECTION_PATTERNS:
            if pattern.search(full):
                logger.warning("Arg injection detected (%s) in: %s", name, full[:200])
                return True, name
        return False, ""

    def resolve_tool_for_capability(
        self, capability: str, registered_tools: list[dict]
    ) -> str | None:
        """Find the best registered tool for a given capability.

        Parameters
        ----------
        capability:
            The capability needed (e.g., "port_scan", "web_scan").
        registered_tools:
            List of tool metadata dicts from ToolRegistry.discover().
        """
        for tool in registered_tools:
            if capability in tool.get("capabilities", []):
                return tool["name"]
        return None
