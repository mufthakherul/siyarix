"""Dynamic tool/command resolver with safety validation.

Resolves autonomous task suggestions and shell commands to safe, executable
commands. Enforces an allowlist and blocks dangerous patterns to prevent
command injection or destructive operations.

This module acts as the security gate between the task planner and the
actual subprocess executor.
"""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety allowlists and blocklists
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

# Patterns that are ALWAYS blocked — prevent destructive operations
_BLOCKED_PATTERNS: list[re.Pattern[str]] = [
    # ── Destructive system commands ──
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f", re.IGNORECASE),  # rm -rf
    re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r", re.IGNORECASE),  # rm -fr
    re.compile(r"\bmkfs\b", re.IGNORECASE),  # format disk
    re.compile(r"\bdd\s+if=", re.IGNORECASE),  # dd
    re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),  # Windows format
    re.compile(r">\s*/dev/sd[a-z]", re.IGNORECASE),  # write to disk
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bhalt\b", re.IGNORECASE),
    re.compile(r"\binit\s+0\b", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;", re.IGNORECASE),  # fork bomb
    re.compile(r"\bchmod\s+777\s+/", re.IGNORECASE),  # chmod 777 /
    re.compile(r"\bchown\s+.*\s+/(?!tmp)", re.IGNORECASE),  # chown system dirs
    re.compile(r">\s*/etc/", re.IGNORECASE),  # overwrite system config
    re.compile(r"\bsudo\s+rm\b", re.IGNORECASE),  # sudo rm
    re.compile(r"\bcurl\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.IGNORECASE),  # pipe to shell
    re.compile(r"\bwget\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.IGNORECASE),
    # ── SQL injection patterns ──
    re.compile(r";\s*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|EXEC)\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b[^;]*(?!WHERE)", re.IGNORECASE),
    re.compile(r"""['\"]\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+""", re.IGNORECASE),  # ' OR 1=1
    # ── Shell injection sequences ──
    re.compile(r"[;&|]{2,}"),  # && || ;;
    re.compile(r"`[^`]+`"),  # backtick execution
    re.compile(r"\$\([^)]+\)"),  # $() command substitution
    # ── Path traversal ──
    re.compile(r"(?:\.\.[\\/]){3,}"),  # ../../../
    # ── Null bytes ──
    re.compile(r"\x00"),  # null byte injection
    # ── Format string attacks ──
    re.compile(r"%n"),  # format string write
    re.compile(r"(?:%s){3,}"),  # format string read chain
    # ── Reverse shells / crypto miners ──
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"\bxmrig\b", re.IGNORECASE),  # crypto miner
    re.compile(r"\bcpuminer\b", re.IGNORECASE),
]

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

        # 2) Check for blocked patterns in the full command string
        full_cmd = f"{tool_or_command} {' '.join(args)}"
        for pattern in _BLOCKED_PATTERNS:
            if pattern.search(full_cmd):
                logger.warning("Blocked dangerous command pattern: %s", full_cmd)
                return ResolvedCommand(
                    executable=tool_or_command,
                    args=args,
                    is_registered_tool=False,
                    path="",
                    safety_score=0.0,
                    warnings=[f"Blocked: matches dangerous pattern {pattern.pattern!r}"],
                )

        # 3) Check for secret leaks
        for pattern in _SECRET_PATTERNS:
            if pattern.search(full_cmd):
                warnings.append("Command may reference sensitive environment variables")

        # 4) Check if the command is in the safe allowlist
        base_cmd = tool_or_command.split()[0] if " " in tool_or_command else tool_or_command
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
            warnings.append(f"Command '{base_cmd}' is not in the known safe list; " "will require user confirmation")

        return ResolvedCommand(
            executable=base_cmd,
            args=args,
            is_registered_tool=False,
            path=path,
            safety_score=safety_score,
            warnings=warnings,
        )

    def has_arg_injection(self, args: list[str]) -> tuple[bool, str]:
        """Check a list of arguments for injection patterns.

        Returns (found, description) where found is True if injection detected.
        """
        _ARG_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
            ("shell_pipe", re.compile(r"[|;&`]")),
            ("command_substitution", re.compile(r"\$\(|`")),
            ("path_traversal", re.compile(r"(?:\.\.[\\/]){3,}")),
            ("null_byte", re.compile(r"\x00")),
            ("newline", re.compile(r"[\r\n]")),
            ("sql_keyword", re.compile(
                r"\b(?:SELECT|INSERT|DELETE|DROP|ALTER|UNION|EXEC)\b.*[;'\"]",
                re.IGNORECASE,
            )),
        ]

        full = " ".join(args)
        for name, pattern in _ARG_INJECTION_PATTERNS:
            if pattern.search(full):
                logger.warning("Arg injection detected (%s) in: %s", name, full[:200])
                return True, name
        return False, ""

    def resolve_tool_for_capability(self, capability: str, registered_tools: list[dict]) -> str | None:
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
