"""CTF challenge system — community challenges, leaderboards, and timed scenarios.

Enables participation in weekly CTF events, custom challenge creation,
hint system, and global score tracking.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CHALLENGES_DIR = Path.home() / ".phalanx" / "challenges"


@dataclass
class Challenge:
    id: str
    name: str
    description: str
    target: str
    goal: str
    difficulty: str = "medium"  # easy, medium, hard, expert
    time_limit_hours: int = 48
    hints: list[str] = field(default_factory=list)
    created_at: str = ""
    ends_at: str = ""
    active: bool = True


@dataclass
class ChallengeParticipant:
    username: str = ""
    score: int = 0
    rank: int = 0
    hints_used: int = 0
    completed: bool = False
    completed_at: str = ""
    flags_found: int = 0


BUILTIN_CHALLENGES: list[Challenge] = [
    Challenge(id="ctf_weekly_web", name="Web Exploitation Weekly", description="Find and exploit XSS, SQLi, and SSRF vulnerabilities", target="ctf.phalanx.community/web", goal="Find 3 flags", difficulty="medium", hints=["Check for reflected XSS in search parameters", "SQLi may be blind — try time-based", "SSRF endpoint is at /api/fetch"]),
    Challenge(id="ctf_weekly_recon", name="Reconnaissance Challenge", description="OSINT and subdomain enumeration challenge", target="ctf.phalanx.community/recon", goal="Map the entire attack surface", difficulty="easy", hints=["Start with subdomain enumeration using subfinder", "Check certificate transparency logs", "Don't forget about API subdomains"]),
    Challenge(id="ctf_weekly_crypto", name="Cryptography Challenge", description="Break weak encryption and decode messages", target="ctf.phalanx.community/crypto", goal="Decrypt 3 messages", difficulty="hard", hints=["First message uses Caesar cipher with unknown shift", "Second is base64 with XOR key", "Third uses RSA with small exponent"]),
]


class ChallengeSystem:
    """Manages CTF challenges, participation, and scoring."""

    def __init__(self) -> None:
        self._dir = CHALLENGES_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._challenges: dict[str, Challenge] = {}
        self._participants: dict[str, list[ChallengeParticipant]] = {}
        self._init_builtins()

    def _init_builtins(self) -> None:
        self._load()
        for bc in BUILTIN_CHALLENGES:
            if bc.id not in self._challenges:
                self._challenges[bc.id] = bc

    def _load(self) -> None:
        f = self._dir / "challenges.json"
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for cid, cd in data.get("challenges", {}).items():
                    self._challenges[cid] = Challenge(**cd)
                for pid, pl in data.get("participants", {}).items():
                    self._participants[pid] = [ChallengeParticipant(**p) for p in pl]
            except Exception as exc:
                logger.error("Failed to load challenges: %s", exc)

    def _save(self) -> None:
        try:
            data = {
                "challenges": {cid: {
                    "id": c.id, "name": c.name, "description": c.description,
                    "target": c.target, "goal": c.goal, "difficulty": c.difficulty,
                    "time_limit_hours": c.time_limit_hours, "hints": c.hints,
                    "created_at": c.created_at, "ends_at": c.ends_at, "active": c.active,
                } for cid, c in self._challenges.items()},
                "participants": {pid: [{
                    "username": p.username, "score": p.score, "rank": p.rank,
                    "hints_used": p.hints_used, "completed": p.completed,
                    "completed_at": p.completed_at, "flags_found": p.flags_found,
                } for p in pl] for pid, pl in self._participants.items()},
            }
            (self._dir / "challenges.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to save challenges: %s", exc)

    def list_active(self) -> list[Challenge]:
        now = datetime.now(UTC)
        return [
            c for c in self._challenges.values()
            if c.active and (not c.ends_at or datetime.fromisoformat(c.ends_at) > now)
        ]

    def get(self, challenge_id: str) -> Challenge | None:
        return self._challenges.get(challenge_id)

    def join(self, challenge_id: str, username: str) -> ChallengeParticipant | None:
        challenge = self._challenges.get(challenge_id)
        if not challenge or not challenge.active:
            return None
        participants = self._participants.setdefault(challenge_id, [])
        existing = next((p for p in participants if p.username == username), None)
        if existing:
            return existing
        participant = ChallengeParticipant(username=username)
        participants.append(participant)
        self._save()
        return participant

    def get_hint(self, challenge_id: str, username: str, hint_index: int) -> str | None:
        challenge = self._challenges.get(challenge_id)
        if not challenge or hint_index >= len(challenge.hints):
            return None
        participants = self._participants.get(challenge_id, [])
        for p in participants:
            if p.username == username:
                p.hints_used = max(p.hints_used, hint_index + 1)
                self._save()
                break
        return challenge.hints[hint_index]

    def submit_flag(self, challenge_id: str, username: str, flag: str) -> bool:
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            return False
        participants = self._participants.get(challenge_id, [])
        for p in participants:
            if p.username == username:
                p.flags_found += 1
                p.score += 100
                if p.flags_found >= 3:
                    p.completed = True
                    p.completed_at = datetime.now(UTC).isoformat()
                self._save()
                return True
        return False

    def get_leaderboard(self, challenge_id: str, limit: int = 20) -> list[ChallengeParticipant]:
        participants = sorted(
            self._participants.get(challenge_id, []),
            key=lambda p: (-p.score, p.completed_at or ""),
        )
        for i, p in enumerate(participants[:limit], 1):
            p.rank = i
        return participants[:limit]

    def summary(self) -> dict[str, Any]:
        return {
            "active_challenges": len(self.list_active()),
            "total_participants": sum(len(pl) for pl in self._participants.values()),
            "completed_challenges": sum(
                1 for pl in self._participants.values() for p in pl if p.completed
            ),
        }


challenge_system = ChallengeSystem()


__all__ = ["ChallengeSystem", "Challenge", "ChallengeParticipant", "challenge_system", "BUILTIN_CHALLENGES"]
