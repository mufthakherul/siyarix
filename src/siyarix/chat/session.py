# SPDX-License-Identifier: AGPL-3.0-or-later

"""Chat session data models — ChatMessage, ChatSession with persistence and branching."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ChatMessage:
    """A single message in the chat history."""

    role: str  # "user" | "assistant" | "system"
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ChatSession:
    """A persistent chat session with history and branching support."""

    session_id: str
    messages: list[ChatMessage] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_active: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    target: str = ""
    mode: str = "integrated"

    def __post_init__(self) -> None:
        self._branching: Any = None

    @property
    def branching(self) -> Any:
        if self._branching is None:
            from ..session_branching import BranchingSession

            self._branching = BranchingSession(session_id=self.session_id)
        return self._branching

    def add_message(self, role: str, content: str, **metadata: Any) -> ChatMessage:
        if len(content) > 50000:
            content = content[:50000] + "\n...[truncated]"
        msg = ChatMessage(role=role, content=content, metadata=metadata)
        self.messages.append(msg)
        self.last_active = datetime.now(timezone.utc)
        if len(self.messages) > 300:
            self.messages = self.messages[-300:]
        if self._branching is not None:
            self._branching.add_message(role, content, **metadata)
        return msg

    def last_n(self, n: int = 10) -> list[ChatMessage]:
        return self.messages[-n:]

    def get_context_summary(self) -> str:
        recent = self.last_n(8)
        parts = []
        for msg in recent:
            prefix = "User" if msg.role == "user" else "Siyarix"
            parts.append(f"{prefix}: {msg.content[:200]}")
        return "\n".join(parts)

    def branch(self, at_message_idx: int | None = None, summary: str = "") -> ChatSession:
        """Create a branch from a specific message index."""
        entry_id = None
        if at_message_idx is not None and self._branching is not None:
            path = self._branching.get_path_to_leaf()
            if at_message_idx < len(path):
                entry_id = path[at_message_idx].id
        new_branch = ChatSession(
            session_id=self.session_id,
            target=self.target,
            mode=self.mode,
        )
        if self._branching is not None:
            branched = self._branching.branch(at_entry_id=entry_id, summary=summary)
            new_branch._branching = branched
        new_branch.messages = list(self.messages)
        return new_branch

    def save(self, path: Path) -> None:
        import json

        data = {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "target": self.target,
            "mode": self.mode,
            "messages": [m.to_dict() for m in self.messages],
        }
        path.write_text(json.dumps(data, indent=2))
        if self._branching is not None:
            from ..session_branching import BranchingSession

            if isinstance(self._branching, BranchingSession):
                self._branching.save()

    @classmethod
    def load(cls, path: Path) -> "ChatSession":
        import json

        data = json.loads(path.read_text())
        session = cls(
            session_id=data["session_id"],
            target=data.get("target", ""),
            mode=data.get("mode", "integrated"),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_active=datetime.fromisoformat(data["last_active"]),
        )
        for m in data.get("messages", []):
            session.messages.append(
                ChatMessage(
                    role=m["role"],
                    content=m["content"],
                    timestamp=datetime.fromisoformat(m["timestamp"]),
                    metadata=m.get("metadata", {}),
                )
            )
        return session
