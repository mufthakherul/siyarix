"""
Three-stage permission gate for runtime safety enforcement.

Syntax Check -> Danger Analysis -> Permission ACL
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .security_hardening import DangerAnalyzer

logger = logging.getLogger(__name__)


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
        self._danger_analyzer = DangerAnalyzer()

    def check(
        self, command: str, tool: str = "", context: dict[str, Any] | None = None
    ) -> GateResult:
        # Stage 1: Syntax check
        if not command or not command.strip():
            return GateResult(False, "syntax", "Empty command", command=command)

        # Stage 2: Danger analysis (uses DangerAnalyzer patterns from security_hardening)
        report = self._danger_analyzer.analyze(command)
        if report.severity == "critical":
            return GateResult(
                False,
                "forbidden",
                f"Destructive command blocked: {'; '.join(report.reasons)}",
                tool=tool,
                command=command,
            )
        if report.severity in ("high", "medium"):
            return GateResult(
                True,
                "review",
                f"Requires review: {'; '.join(report.reasons)}",
                tool=tool,
                command=command,
                requires_review=True,
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
