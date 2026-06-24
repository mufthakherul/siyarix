# SPDX-License-Identifier: AGPL-3.0-or-later

"""Two-stage permission gate for runtime safety enforcement.

Syntax Check -> Danger Analysis
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .config import get_config_dir
from .security_hardening import DangerAnalyzer

logger = logging.getLogger(__name__)


class GateStage(StrEnum):
    SYNTAX = "syntax"
    FORBIDDEN = "forbidden"
    PERMISSION = "permission"
    REVIEW = "review"
    APPROVED = "approved"


@dataclass
class GateResult:
    allowed: bool
    stage: GateStage
    reason: str = ""
    tool: str = ""
    command: str = ""
    requires_review: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.stage, GateStage):
            try:
                self.stage = GateStage(self.stage)
            except ValueError:
                raise ValueError(f"Invalid stage: {self.stage}")


class PermissionGate:
    _RESTRICTED_PATTERNS = [
        re.compile(r"\brm\b[\s]+(?:-[a-zA-Z]*[rf][a-zA-Z]*[\s]*)*(?:-[a-zA-Z]*[rf])", re.IGNORECASE),
        re.compile(r"\brm\b\s+--(?:recursive|force)", re.IGNORECASE),
        re.compile(r"\bmkfs\b", re.IGNORECASE),
        re.compile(r"\bdd\b\s+if=", re.IGNORECASE),
    ]
    def __init__(self, rate_limit_calls: int = 100, rate_limit_period: float = 60.0) -> None:
        self._danger_analyzer = DangerAnalyzer()
        self._calls: list[float] = []
        self.rate_limit_calls = rate_limit_calls
        self.rate_limit_period = rate_limit_period
        self._state_file = get_config_dir() / "rate_limit.json"
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._load_state()
        self._dirty = False

    def _load_state(self) -> None:
        if self._state_file.exists():
            try:
                self._calls = json.loads(self._state_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    def _save_state(self, force: bool = False) -> None:
        if not force:
            self._dirty = True
            return
        try:
            self._state_file.write_text(json.dumps(self._calls), encoding="utf-8")
            self._dirty = False
        except Exception:
            pass

    def check(
        self, command: str, tool: str = "", context: dict[str, Any] | None = None,
    ) -> GateResult:
        now = time.time()
        self._calls = [t for t in self._calls if now - t < self.rate_limit_period]

        if context and isinstance(context, dict) and context.get("restricted_payload"):
            if any(p.search(command) for p in self._RESTRICTED_PATTERNS):
                return GateResult(
                    False,
                    GateStage.FORBIDDEN,
                    "Payload verification failed",
                    tool=tool,
                    command=command,
                )

        if len(self._calls) >= self.rate_limit_calls:
            self._save_state(force=True)
            return GateResult(
                False, GateStage.FORBIDDEN, "Rate limit exceeded", tool=tool, command=command,
            )

        self._calls.append(now)
        self._save_state(force=(len(self._calls) % 50 == 0))

        if not command or not command.strip():
            return GateResult(False, GateStage.SYNTAX, "Empty command", command=command)

        report = self._danger_analyzer.analyze(command)
        if report.severity == "critical":
            return GateResult(
                False,
                GateStage.FORBIDDEN,
                f"Destructive command blocked: {'; '.join(report.reasons)}",
                tool=tool,
                command=command,
            )
        if report.severity in ("high", "medium"):
            return GateResult(
                True,
                GateStage.REVIEW,
                f"Requires review: {'; '.join(report.reasons)}",
                tool=tool,
                command=command,
                requires_review=True,
            )
        return GateResult(True, GateStage.APPROVED, "", tool=tool, command=command)


__all__ = [
    "GateResult",
    "PermissionGate",
]
