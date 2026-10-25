# SPDX-License-Identifier: AGPL-3.0-or-later

"""Two-stage permission gate for runtime safety enforcement.

Syntax Check -> Danger Analysis
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .config import get_config_dir
from .security_hardening import DangerAnalyzer


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
        stage_val: Any = self.stage
        if not isinstance(stage_val, GateStage):
            try:
                self.stage = GateStage(stage_val)
            except ValueError:
                raise ValueError(f"Invalid stage: {self.stage}")


class PermissionGate:
    _RESTRICTED_PATTERNS = [
        re.compile(
            r"\brm\b[\s]+(?:-[a-zA-Z]*[rf][a-zA-Z]*[\s]*)*(?:-[a-zA-Z]*[rf])", re.IGNORECASE
        ),
        re.compile(r"\brm\b\s+--(?:recursive|force)", re.IGNORECASE),
        re.compile(
            r"\b(mkfs(?:\.\w+)?|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|mkswap|"
            r"ntfsformat|mkntfs|newfs(?:_\w+)?)\b",
            re.IGNORECASE,
        ),
        # Any dd with of=/dev/<block> (last of= checked in assert_command_not_destructive).
        re.compile(r"\bdd\b.*\bof=/dev/(?!null\b|zero\b)\S+", re.IGNORECASE),
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
        import atexit

        atexit.register(self._flush_dirty)

    def _load_state(self) -> None:
        if self._state_file.exists():
            try:
                raw = json.loads(self._state_file.read_text(encoding="utf-8"))
                if not isinstance(raw, list):
                    self._calls = []
                    return
                calls: list[float] = []
                for item in raw:
                    try:
                        calls.append(float(item))
                    except (TypeError, ValueError):
                        continue
                self._calls = calls
            except Exception:
                self._calls = []

    def _save_state(self, force: bool = False) -> None:
        if not force:
            self._dirty = True
            return
        try:
            self._state_file.write_text(json.dumps(self._calls), encoding="utf-8")
            self._dirty = False
        except Exception:
            pass

    def _flush_dirty(self) -> None:
        if self._dirty:
            self._save_state(force=True)

    def check(
        self,
        command: str,
        tool: str = "",
        context: dict[str, Any] | None = None,
    ) -> GateResult:
        now = time.time()
        self._calls = [t for t in self._calls if now - t < self.rate_limit_period]

        # Shared hard-blocks (dd of= last-wins, fdisk/parted, …) before soft review.
        try:
            from siyarix.destructive import assert_command_not_destructive

            assert_command_not_destructive(command)
        except Exception as exc:
            from siyarix.exceptions import PermissionDeniedError

            if isinstance(exc, PermissionDeniedError):
                return GateResult(
                    False,
                    GateStage.FORBIDDEN,
                    str(exc),
                    tool=tool,
                    command=command,
                )
            raise

        # Always check restricted patterns for destructive payloads
        if any(p.search(command) for p in self._RESTRICTED_PATTERNS):
            return GateResult(
                False,
                GateStage.FORBIDDEN,
                "Payload verification failed",
                tool=tool,
                command=command,
            )

        if not command or not command.strip():
            return GateResult(False, GateStage.SYNTAX, "Empty command", command=command)

        if len(self._calls) >= self.rate_limit_calls:
            self._save_state(force=True)
            return GateResult(
                False,
                GateStage.FORBIDDEN,
                "Rate limit exceeded",
                tool=tool,
                command=command,
            )

        self._calls.append(now)
        self._save_state(force=(len(self._calls) % 50 == 0))

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
