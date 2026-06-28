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

    def export(self, fmt: str = "json") -> str | bytes:
        """Export conversation in the requested format."""
        if fmt == "json":
            import json

            data = {
                "session_id": self.session_id,
                "created_at": self.created_at.isoformat(),
                "last_active": self.last_active.isoformat(),
                "target": self.target,
                "mode": self.mode,
                "message_count": len(self.messages),
                "messages": [m.to_dict() for m in self.messages],
                "context": {k: v for k, v in self.context.items() if k in ("findings", "feedback")},
            }
            return json.dumps(data, indent=2)
        elif fmt in ("md", "markdown"):
            lines = ["# Siyarix Conversation Export", "", f"**Session:** {self.session_id[:16]}"]
            if self.target:
                lines.append(f"**Target:** {self.target}")
            lines.append(f"**Mode:** {self.mode}")
            lines.append(f"**Messages:** {len(self.messages)}")
            lines.append(
                f"**Exported:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            lines.append("")
            lines.append("---")
            lines.append("")
            for msg in self.messages:
                role_label = "👤 User" if msg.role == "user" else "🤖 Siyarix"
                ts = (
                    msg.timestamp.strftime("%H:%M:%S") if hasattr(msg.timestamp, "strftime") else ""
                )
                lines.append(f"### {role_label} ({ts})")
                lines.append("")
                lines.append(msg.content)
                lines.append("")
                lines.append("---")
                lines.append("")
            return "\n".join(lines)
        elif fmt == "html":
            html_parts = [
                "<!DOCTYPE html>",
                '<html><head><meta charset="utf-8">',
                "<title>Siyarix Conversation Export</title>",
                "<style>",
                "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; }",
                ".message { margin: 1em 0; padding: 1em; border-radius: 8px; }",
                ".user { background: #e3f2fd; border-left: 4px solid #1976d2; }",
                ".assistant { background: #f3e5f5; border-left: 4px solid #7b1fa2; }",
                ".system { background: #f5f5f5; border-left: 4px solid #616161; }",
                ".role { font-weight: bold; margin-bottom: 0.5em; }",
                ".timestamp { color: #666; font-size: 0.9em; }",
                "pre { background: #f5f5f5; padding: 1em; overflow-x: auto; }",
                "</style></head><body>",
                "<h1>Siyarix Conversation</h1>",
                f"<p>Session: {self.session_id[:16]} | Mode: {self.mode} | Messages: {len(self.messages)}</p>",
            ]
            for msg in self.messages:
                ts = (
                    msg.timestamp.strftime("%H:%M:%S") if hasattr(msg.timestamp, "strftime") else ""
                )
                role_class = msg.role if msg.role in ("user", "assistant", "system") else "system"
                html_parts.append(
                    f'<div class="message {role_class}">'
                    f'<div class="role">{msg.role.upper()}</div>'
                    f'<div class="timestamp">{ts}</div>'
                    f"<div>{msg.content}</div>"
                    f"</div>"
                )
            html_parts.append("</body></html>")
            return "\n".join(html_parts)
        elif fmt == "txt":
            lines = [
                "Siyarix Conversation Export",
                "=" * 40,
                f"Session: {self.session_id[:16]}",
                f"Mode: {self.mode}",
                f"Target: {self.target or 'N/A'}",
                f"Messages: {len(self.messages)}",
                "",
            ]
            for msg in self.messages:
                ts = (
                    msg.timestamp.strftime("%H:%M:%S") if hasattr(msg.timestamp, "strftime") else ""
                )
                label = f"[{ts}] {msg.role.upper()}"
                lines.append(label)
                lines.append("-" * len(label))
                lines.append(msg.content)
                lines.append("")
            return "\n".join(lines)
        elif fmt == "pdf":
            # For PDF, return HTML and let caller convert
            html = self.export("html")
            try:
                # Try using weasyprint or pdfkit
                try:
                    import pdfkit

                    pdf_bytes = pdfkit.from_string(html, False)
                    return pdf_bytes
                except ImportError:
                    try:
                        from weasyprint import HTML as WHTML

                        pdf_bytes = WHTML(string=html).write_pdf()
                        return pdf_bytes
                    except ImportError:
                        pass
                # Fallback: return HTML with note
                return html.encode("utf-8")
            except Exception:
                return html.encode("utf-8")
        return ""

    def to_dict(self) -> dict:
        """Serialize session to dictionary."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "target": self.target,
            "mode": self.mode,
            "messages": [m.to_dict() for m in self.messages],
            "context_keys": sorted(self.context.keys()),
        }

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
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        if self._branching is not None:
            from ..session_branching import BranchingSession

            if isinstance(self._branching, BranchingSession):
                self._branching.save()

    @classmethod
    def load(cls, path: Path) -> "ChatSession":
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
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
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    timestamp=datetime.fromisoformat(
                        m.get("timestamp", datetime.now(timezone.utc).isoformat())
                    ),
                    metadata=m.get("metadata", {}),
                )
            )
        return session
