"""Community features — leaderboards, sharing, and social interaction.

Provides global rankings, finding sharing, challenge achievements,
and community feed integration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

COMMUNITY_DIR = Path.home() / ".phalanx" / "community"


@dataclass
class CommunityProfile:
    username: str = ""
    display_name: str = ""
    bio: str = ""
    join_date: str = ""
    total_scans: int = 0
    total_findings: int = 0
    total_tools_used: int = 0
    achievements_unlocked: int = 0
    challenges_completed: int = 0
    reputation: int = 0
    badges: list[str] = field(default_factory=list)


@dataclass
class LeaderboardEntry:
    rank: int = 0
    username: str = ""
    score: int = 0
    scans: int = 0
    findings: int = 0
    achievements: int = 0


class CommunityService:
    """Community features — profiles, leaderboards, and social sharing."""

    def __init__(self) -> None:
        self._dir = COMMUNITY_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._profiles: dict[str, CommunityProfile] = {}

    def register(self, username: str, display_name: str = "", bio: str = "") -> CommunityProfile:
        profile = CommunityProfile(
            username=username,
            display_name=display_name or username,
            bio=bio,
            join_date=datetime.now(UTC).isoformat(),
        )
        self._profiles[username] = profile
        self._save()
        return profile

    def get_profile(self, username: str) -> CommunityProfile | None:
        return self._profiles.get(username)

    def update_stats(self, username: str, scans: int = 0, findings: int = 0, tools: int = 0, achievements: int = 0, challenges: int = 0) -> CommunityProfile | None:
        profile = self._profiles.get(username)
        if not profile:
            return None
        profile.total_scans += scans
        profile.total_findings += findings
        profile.total_tools_used = max(profile.total_tools_used, tools)
        profile.achievements_unlocked = max(profile.achievements_unlocked, achievements)
        profile.challenges_completed += challenges
        profile.reputation = (
            profile.total_scans * 10
            + profile.total_findings * 25
            + profile.achievements_unlocked * 100
            + profile.challenges_completed * 200
        )
        self._save()
        return profile

    def get_leaderboard(self, sort_by: str = "reputation", limit: int = 20) -> list[LeaderboardEntry]:
        profiles = list(self._profiles.values())
        key_map = {
            "reputation": lambda p: -p.reputation,
            "scans": lambda p: -p.total_scans,
            "findings": lambda p: -p.total_findings,
            "achievements": lambda p: -p.achievements_unlocked,
        }
        sort_fn = key_map.get(sort_by, key_map["reputation"])
        sorted_profiles = sorted(profiles, key=sort_fn)[:limit]
        return [
            LeaderboardEntry(
                rank=i + 1,
                username=p.username,
                score=p.reputation,
                scans=p.total_scans,
                findings=p.total_findings,
                achievements=p.achievements_unlocked,
            )
            for i, p in enumerate(sorted_profiles)
        ]

    def _save(self) -> None:
        try:
            data = {username: {
                "username": p.username, "display_name": p.display_name,
                "bio": p.bio, "join_date": p.join_date,
                "total_scans": p.total_scans, "total_findings": p.total_findings,
                "total_tools_used": p.total_tools_used,
                "achievements_unlocked": p.achievements_unlocked,
                "challenges_completed": p.challenges_completed,
                "reputation": p.reputation, "badges": p.badges,
            } for username, p in self._profiles.items()}
            (self._dir / "profiles.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to save community data: %s", exc)

    def summary(self) -> dict[str, Any]:
        return {
            "registered_users": len(self._profiles),
            "total_scans": sum(p.total_scans for p in self._profiles.values()),
            "total_findings": sum(p.total_findings for p in self._profiles.values()),
            "total_reputation": sum(p.reputation for p in self._profiles.values()),
        }


community_service = CommunityService()


__all__ = ["CommunityService", "CommunityProfile", "LeaderboardEntry", "community_service"]
