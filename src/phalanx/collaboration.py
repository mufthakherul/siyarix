"""
Team Collaboration module -- multi-user session management for Phalanx.

Provides session hosting, joining, and message broadcasting
for team-based penetration testing as described in Chapter 9.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

_PHALANX_HOME = Path.home() / ".phalanx"
_COLLAB_DIR = _PHALANX_HOME / "collab"


@dataclass
class CollabMember:
    name: str
    role: str  # "lead" | "analyst" | "observer"
    joined_at: str = ""


@dataclass
class CollabSession:
    session_id: str
    name: str
    host: str
    created_at: str = ""
    members: list[CollabMember] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    target: str = ""

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "host": self.host,
            "created_at": self.created_at,
            "members": [
                {"name": m.name, "role": m.role, "joined_at": m.joined_at}
                for m in self.members
            ],
            "messages": self.messages[-100:],
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CollabSession:
        return cls(
            session_id=data.get("session_id", ""),
            name=data.get("name", ""),
            host=data.get("host", ""),
            created_at=data.get("created_at", ""),
            members=[CollabMember(**m) for m in data.get("members", [])],
            messages=data.get("messages", []),
            target=data.get("target", ""),
        )

    def save(self) -> None:
        _COLLAB_DIR.mkdir(parents=True, exist_ok=True)
        path = _COLLAB_DIR / f"{self.session_id}.json"
        with open(str(path), "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, session_id: str) -> CollabSession | None:
        path = _COLLAB_DIR / f"{session_id}.json"
        if not path.exists():
            return None
        with open(str(path)) as f:
            return cls.from_dict(json.load(f))

    def add_member(self, name: str, role: str = "analyst") -> CollabMember:
        member = CollabMember(
            name=name, role=role, joined_at=datetime.now().isoformat()
        )
        self.members.append(member)
        self.save()
        return member

    def broadcast(self, sender: str, message: str) -> None:
        self.messages.append(
            {
                "sender": sender,
                "message": message,
                "timestamp": datetime.now().isoformat(),
            }
        )
        self.save()


class CollaborationManager:
    def __init__(self):
        _COLLAB_DIR.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, CollabSession] = {}

    def create_session(self, name: str, host: str, target: str = "") -> CollabSession:
        session_id = str(uuid.uuid4())[:12]
        session = CollabSession(
            session_id=session_id,
            name=name,
            host=host,
            created_at=datetime.now().isoformat(),
            target=target,
        )
        session.add_member(host, role="lead")
        self._sessions[session_id] = session
        session.save()
        return session

    def list_sessions(self) -> list[dict]:
        if not _COLLAB_DIR.exists():
            return []
        sessions = []
        for p in _COLLAB_DIR.glob("*.json"):
            with open(str(p)) as f:
                sessions.append(json.load(f))
        return sorted(sessions, key=lambda s: s.get("created_at", ""), reverse=True)

    def show_table(self, sessions: list[dict] | None = None) -> None:
        if sessions is None:
            sessions = self.list_sessions()
        if not sessions:
            console.print("[dim]No collaboration sessions found.[/dim]")
            return
        table = Table(title="Collaboration Sessions", header_style="bold cyan")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Host", style="yellow")
        table.add_column("Members", style="white")
        table.add_column("Target", style="dim")
        for s in sessions:
            member_count = len(s.get("members", []))
            table.add_row(
                s.get("session_id", "")[:8],
                s.get("name", ""),
                s.get("host", ""),
                str(member_count),
                s.get("target", "") or "-",
            )
        console.print(table)


__all__ = ["CollaborationManager", "CollabSession", "CollabMember"]
