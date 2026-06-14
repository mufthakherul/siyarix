# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Two-stage permission gate for runtime safety enforcement.

Syntax Check -> Danger Analysis
"""

from __future__ import annotations

import time
import json
import os
from dataclasses import dataclass
from typing import Any

from .security_hardening import DangerAnalyzer
from .config import get_config_dir
from enum import StrEnum
import logging

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
    def __init__(self, rate_limit_calls: int = 100, rate_limit_period: float = 60.0) -> None:
        self._danger_analyzer = DangerAnalyzer()
        self._calls: list[float] = []
        self.rate_limit_calls = rate_limit_calls
        self.rate_limit_period = rate_limit_period
        self._state_file = get_config_dir() / "rate_limit.json"
        self._load_state()

    def _load_state(self) -> None:
        if os.path.exists(self._state_file):
            try:
                with open(self._state_file, "r", encoding='utf-8') as f:
                    self._calls = json.load(f)
            except Exception:
                pass

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            with open(self._state_file, "w", encoding='utf-8') as f:
                json.dump(self._calls, f)
        except Exception:
            pass

    def check(
        self, command: str, tool: str = "", context: dict[str, Any] | None = None
    ) -> GateResult:
        now = time.time()
        self._calls = [t for t in self._calls if now - t < self.rate_limit_period]

        if context and context.get("restricted_payload"):
             if any(bad in command for bad in ("rm -rf", "mkfs", "dd if=")):
                 return GateResult(False, GateStage.FORBIDDEN, "Payload verification failed", tool=tool, command=command)

        if len(self._calls) >= self.rate_limit_calls:
            self._save_state()
            return GateResult(False, GateStage.FORBIDDEN, "Rate limit exceeded", tool=tool, command=command)

        self._calls.append(now)
        self._save_state()

        # Stage 1: Syntax check
        if not command or not command.strip():
            return GateResult(False, GateStage.SYNTAX, "Empty command", command=command)

        # Stage 2: Danger analysis (uses DangerAnalyzer patterns from security_hardening)
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
