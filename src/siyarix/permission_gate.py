# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Two-stage permission gate for runtime safety enforcement.

Syntax Check -> Danger Analysis
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from .security_hardening import DangerAnalyzer
import logging

logger = logging.getLogger(__name__)


@dataclass
class GateResult:
    allowed: bool
    stage: Literal["syntax", "forbidden", "permission", "review", "approved"]
    reason: str = ""
    tool: str = ""
    command: str = ""
    requires_review: bool = False

    def __post_init__(self):
        if self.stage not in {"syntax", "forbidden", "permission", "review", "approved"}:
            raise ValueError(f"Invalid stage: {self.stage}")


class PermissionGate:
    def __init__(self, rate_limit_calls: int = 100, rate_limit_period: float = 60.0) -> None:
        self._danger_analyzer = DangerAnalyzer()
        self._calls: list[float] = []
        self.rate_limit_calls = rate_limit_calls
        self.rate_limit_period = rate_limit_period

    def check(
        self, command: str, tool: str = "", context: dict[str, Any] | None = None
    ) -> GateResult:
        now = time.time()
        self._calls = [t for t in self._calls if now - t < self.rate_limit_period]
        if len(self._calls) >= self.rate_limit_calls:
            return GateResult(False, "forbidden", "Rate limit exceeded", tool=tool, command=command)

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
        return GateResult(True, "approved", "", tool=tool, command=command)

__all__ = [
    "GateResult",
    "PermissionGate",
]
