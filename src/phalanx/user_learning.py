"""
User Learning -- adaptive pedagogical output for Phalanx users.

As described in Chapter 10.2: adjusts verbosity, explanations,
and output style based on user experience level.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_LEARNING_DIR = _PHALANX_HOME / "learning"


class ExperienceLevel:
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


@dataclass
class UserProfile:
    username: str = ""
    experience: str = ExperienceLevel.INTERMEDIATE
    session_count: int = 0
    tool_count: int = 0
    preferences: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "experience": self.experience,
            "session_count": self.session_count,
            "tool_count": self.tool_count,
            "preferences": self.preferences,
        }

    @classmethod
    def from_dict(cls, data: dict) -> UserProfile:
        return cls(
            username=data.get("username", ""),
            experience=data.get("experience", ExperienceLevel.INTERMEDIATE),
            session_count=data.get("session_count", 0),
            tool_count=data.get("tool_count", 0),
            preferences=data.get("preferences", {}),
        )


class UserLearning:
    """Adaptive learning for output style and verbosity."""

    def __init__(self):
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        self._profile_path = _LEARNING_DIR / "user_profile.json"
        self._profile = UserProfile()
        self._load()

    def _load(self) -> None:
        if self._profile_path.exists():
            try:
                with open(str(self._profile_path)) as f:
                    self._profile = UserProfile.from_dict(json.load(f))
            except Exception as exc:
                logger.warning("Failed to load user profile: %s", exc)

    def _save(self) -> None:
        try:
            with open(str(self._profile_path), "w") as f:
                json.dump(self._profile.to_dict(), f, indent=2)
        except Exception as exc:
            logger.warning("Failed to save user profile: %s", exc)

    @property
    def experience(self) -> str:
        return self._profile.experience

    @experience.setter
    def experience(self, level: str) -> None:
        if level in (ExperienceLevel.NOVICE, ExperienceLevel.INTERMEDIATE, ExperienceLevel.ADVANCED, ExperienceLevel.EXPERT):
            self._profile.experience = level
            self._save()

    def record_session(self) -> None:
        self._profile.session_count += 1
        self._save()

    def record_tool_use(self) -> None:
        self._profile.tool_count += 1
        self._save()

    def should_show_explanation(self) -> bool:
        """Return True if the user should get verbose explanations."""
        return self._profile.experience in (ExperienceLevel.NOVICE, ExperienceLevel.INTERMEDIATE)

    def verbosity_level(self) -> int:
        """Return verbosity level: 0=terse, 1=normal, 2=verbose."""
        mapping = {
            ExperienceLevel.NOVICE: 2,
            ExperienceLevel.INTERMEDIATE: 1,
            ExperienceLevel.ADVANCED: 1,
            ExperienceLevel.EXPERT: 0,
        }
        return mapping.get(self._profile.experience, 1)

    def get_profile(self) -> Panel:
        p = self._profile
        return Panel(
            f"[bold]User:[/bold] {p.username or 'anonymous'}\n"
            f"[bold]Experience:[/bold] {p.experience}\n"
            f"[bold]Sessions:[/bold] {p.session_count}\n"
            f"[bold]Tools used:[/bold] {p.tool_count}\n"
            f"[bold]Verbosity:[/bold] {self.verbosity_level()}/2\n"
            f"[bold]Explanations:[/bold] {'On' if self.should_show_explanation() else 'Off'}",
            title="User Learning Profile",
            border_style="cyan",
        )

__all__ = ["UserLearning", "UserProfile", "ExperienceLevel"]
