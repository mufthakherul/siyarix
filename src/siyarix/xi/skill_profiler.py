"""XI Skill Profiler — Detects user expertise level and adapts UX accordingly.

Tracks:
  • Command complexity patterns
  • Tool diversity usage
  • Error rate and recovery patterns
  • Speed of operation
  • Feature discovery (slash commands, shortcuts, advanced flags)

Outputs a SkillProfile with level (beginner/intermediate/advanced/expert)
that other modules use to adapt verbosity, suggestions, and warnings.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = ["SkillProfiler", "SkillProfile", "SkillLevel"]

logger = logging.getLogger(__name__)


class SkillLevel:
    """User expertise levels."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

    @classmethod
    def all(cls) -> list[str]:
        return [cls.BEGINNER, cls.INTERMEDIATE, cls.ADVANCED, cls.EXPERT]


@dataclass
class SkillProfile:
    """Current assessment of user skill."""

    level: str = SkillLevel.INTERMEDIATE
    score: float = 50.0  # 0-100 scale
    total_commands: int = 0
    unique_tools: int = 0
    advanced_features_used: int = 0
    error_rate: float = 0.0
    avg_command_interval_s: float = 0.0
    assessed_at: datetime = field(default_factory=datetime.now)

    @property
    def verbosity(self) -> str:
        """Recommended output verbosity based on skill level."""
        return {
            SkillLevel.BEGINNER: "verbose",
            SkillLevel.INTERMEDIATE: "normal",
            SkillLevel.ADVANCED: "compact",
            SkillLevel.EXPERT: "minimal",
        }.get(self.level, "normal")

    @property
    def show_hints(self) -> bool:
        return self.level in (SkillLevel.BEGINNER, SkillLevel.INTERMEDIATE)

    @property
    def auto_confirm_safe(self) -> bool:
        """Expert users can auto-confirm safe operations."""
        return self.level == SkillLevel.EXPERT

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "score": round(self.score, 1),
            "total_commands": self.total_commands,
            "unique_tools": self.unique_tools,
            "advanced_features_used": self.advanced_features_used,
            "error_rate": round(self.error_rate, 3),
            "avg_command_interval_s": round(self.avg_command_interval_s, 1),
            "verbosity": self.verbosity,
        }


# Advanced features that indicate expertise
_ADVANCED_FEATURES = frozenset(
    {
        "--mode autonomous",
        "--mode integrated",
        "--parallel",
        "--dry-run",
        "--persist",
        "/workflow",
        "/agent",
        "/translate",
        "/palette",
        "/security-cmds",
        "parallel_group",
        "depends_on",
        "pipe",
        "&&",
        "YAML workflow",
    }
)

# Advanced tools
_ADVANCED_TOOLS = frozenset(
    {
        "sqlmap",
        "hydra",
        "hashcat",
        "john",
        "msfconsole",
        "burpsuite",
        "bloodhound",
        "impacket",
        "responder",
        "mimikatz",
        "powershell-empire",
        "cobaltstrike",
    }
)


class SkillProfiler:
    """Tracks user behaviour and assesses skill level over time."""

    def __init__(self) -> None:
        self._tools_used: Counter[str] = Counter()
        self._total_commands: int = 0
        self._errors: int = 0
        self._advanced_features: set[str] = set()
        self._command_timestamps: list[float] = []
        self._profile = SkillProfile()

    def record_command(
        self,
        command: str,
        tool: str = "",
        success: bool = True,
    ) -> None:
        """Record a user command execution."""
        self._total_commands += 1
        self._command_timestamps.append(time.time())

        if tool:
            self._tools_used[tool] += 1

        if not success:
            self._errors += 1

        # Check for advanced features
        for feature in _ADVANCED_FEATURES:
            if feature.lower() in command.lower():
                self._advanced_features.add(feature)

        # Check for advanced tools
        if tool.lower() in _ADVANCED_TOOLS:
            self._advanced_features.add(f"tool:{tool}")

        # Re-assess after every 5 commands
        if self._total_commands % 5 == 0:
            self._assess()

    def _assess(self) -> None:
        """Reassess the user's skill level based on accumulated data."""
        score = 50.0  # Start at intermediate

        # Factor 1: Tool diversity (0-20 points)
        unique_tools = len(self._tools_used)
        score += min(unique_tools * 3, 20)

        # Factor 2: Advanced features (0-25 points)
        adv_count = len(self._advanced_features)
        score += min(adv_count * 5, 25)

        # Factor 3: Command volume (0-15 points)
        if self._total_commands > 50:
            score += 15
        elif self._total_commands > 20:
            score += 10
        elif self._total_commands > 10:
            score += 5

        # Factor 4: Error rate (penalty: -20 to 0)
        error_rate = self._errors / max(self._total_commands, 1)
        if error_rate > 0.5:
            score -= 20
        elif error_rate > 0.3:
            score -= 10
        elif error_rate > 0.15:
            score -= 5

        # Factor 5: Command speed (0-10 points) — fast operators = experienced
        avg_interval = self._avg_interval()
        if error_rate < 0.3:
            if avg_interval > 0 and avg_interval < 5.0:
                score += 10
            elif avg_interval > 0 and avg_interval < 15.0:
                score += 5

        # Clamp
        score = max(0.0, min(100.0, score))

        # Map score to level
        if score >= 85:
            level = SkillLevel.EXPERT
        elif score >= 65:
            level = SkillLevel.ADVANCED
        elif score >= 40:
            level = SkillLevel.INTERMEDIATE
        else:
            level = SkillLevel.BEGINNER

        self._profile = SkillProfile(
            level=level,
            score=score,
            total_commands=self._total_commands,
            unique_tools=unique_tools,
            advanced_features_used=adv_count,
            error_rate=error_rate,
            avg_command_interval_s=avg_interval,
        )

    def _avg_interval(self) -> float:
        """Average seconds between commands."""
        ts = self._command_timestamps
        if len(ts) < 2:
            return 0.0
        intervals = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
        # Only consider last 20 intervals
        recent = intervals[-20:]
        return sum(recent) / len(recent) if recent else 0.0

    @property
    def profile(self) -> SkillProfile:
        if self._total_commands > 0 and self._total_commands % 5 != 0:
            self._assess()
        return self._profile

    def reset(self) -> None:
        """Reset all tracked data."""
        self._tools_used.clear()
        self._total_commands = 0
        self._errors = 0
        self._advanced_features.clear()
        self._command_timestamps.clear()
        self._profile = SkillProfile()
