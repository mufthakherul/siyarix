"""
Three-stage permission gate for runtime safety enforcement.

Syntax Check -> Forbidden Words -> Permission Gate
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

FORBIDDEN_PATTERNS: list[str] = [
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/",
    r":\(\)\s*\{",
    r">\s*/dev/sda",
    r"chmod\s+-?R?\s*777\s+/",
    r"wget\s+.*\|\s*bash",
    r"curl\s+.*\|\s*bash",
    r"sudo\s+rm\s+-rf\s+/",
    r"mv\s+/.*\s+/dev/null",
]


@dataclass
class GateResult:
    allowed: bool
    stage: str  # "syntax" | "forbidden" | "permission" | "review" | "approved"
    reason: str = ""
    tool: str = ""
    command: str = ""
    requires_review: bool = False


class PermissionGate:
    def __init__(self, persona_engine=None):
        self._persona_engine = persona_engine
        self._forbidden = [re.compile(p, re.IGNORECASE) for p in FORBIDDEN_PATTERNS]

    def check(
        self, command: str, tool: str = "", context: dict[str, Any] | None = None
    ) -> GateResult:
        # Stage 1: Syntax check
        if not command or not command.strip():
            return GateResult(False, "syntax", "Empty command", command=command)

        # Stage 2: Forbidden patterns
        for pattern in self._forbidden:
            if pattern.search(command):
                return GateResult(
                    False,
                    "forbidden",
                    f"Contains forbidden pattern: {pattern.pattern}",
                    tool=tool,
                    command=command,
                )

        # Stage 3: Permission check via ACL
        if self._persona_engine and tool:
            persona = getattr(self._persona_engine, "active_persona", None)
            if persona and hasattr(persona, "tool_acl"):
                acl = persona.tool_acl
                if not acl.is_allowed(tool):
                    return GateResult(
                        False,
                        "permission",
                        f"Tool '{tool}' not in allowed list",
                        tool=tool,
                        command=command,
                    )
                if acl.requires_review(tool):
                    return GateResult(
                        True,
                        "review",
                        f"Tool '{tool}' requires review",
                        tool=tool,
                        command=command,
                        requires_review=True,
                    )
                if acl.requires_permission(tool):
                    return GateResult(
                        True,
                        "permission",
                        f"Tool '{tool}' requires permission",
                        tool=tool,
                        command=command,
                        requires_review=True,
                    )

        return GateResult(True, "approved", "", tool=tool, command=command)
