"""Session branching — JSONL tree format for conversation branches.

OpenClaw pattern: session-manager.ts JSONL tree with id/parentId.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BranchEntry:
    """A single entry in a branched session JSONL file."""
    id: str = ""
    parent_id: str = ""
    type: str = "message"  # session, message, compaction, branch_summary, label
    role: str = ""
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _session_dir(session_id: str) -> Path:
    from .config import get_config_dir
    return get_config_dir() / "sessions"


# ---------------------------------------------------------------------------
# Branching session
# ---------------------------------------------------------------------------

class BranchingSession:
    """A session with branching support using JSONL tree format.

    Each entry has an id and parent_id forming a tree.
    branch() creates a fork; merge() brings changes back.
    """

    def __init__(self, session_id: str = "", path: Path | None = None) -> None:
        self.session_id = session_id or _new_id()
        self._entries: list[BranchEntry] = []
        self._leaf_id: str = "root"
        self._path = path or (_session_dir(self.session_id) / f"{self.session_id}.jsonl")
        self._dirty = False
        self._load()

    # ── Properties ─────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self._path

    @property
    def leaf_id(self) -> str:
        return self._leaf_id

    @property
    def entries(self) -> list[BranchEntry]:
        return list(self._entries)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    # ── Entry management ───────────────────────────────────────────

    def append_entry(
        self,
        entry_type: str,
        role: str = "",
        content: str = "",
        metadata: dict[str, Any] | None = None,
        parent_id: str | None = None,
    ) -> BranchEntry:
        """Append a new entry under the current leaf or specified parent."""
        entry = BranchEntry(
            id=_new_id(),
            parent_id=parent_id or self._leaf_id,
            type=entry_type,
            role=role,
            content=content,
            metadata=metadata or {},
            timestamp=_now(),
        )
        self._entries.append(entry)
        self._leaf_id = entry.id
        self._dirty = True
        return entry

    def add_message(self, role: str, content: str, **metadata: Any) -> BranchEntry:
        """Add a conversation message entry."""
        return self.append_entry("message", role=role, content=content, metadata=metadata)

    def add_compaction(self, summary: str, metadata: dict[str, Any] | None = None) -> BranchEntry:
        """Add a compaction summary entry."""
        return self.append_entry("compaction", content=summary, metadata=metadata)

    def add_label(self, label: str, metadata: dict[str, Any] | None = None) -> BranchEntry:
        """Add a bookmark/label entry."""
        return self.append_entry("label", content=label, metadata=metadata)

    def add_branch_summary(self, summary: str, metadata: dict[str, Any] | None = None) -> BranchEntry:
        """Add a branch summary entry (created when branching)."""
        return self.append_entry("branch_summary", content=summary, metadata=metadata)

    # ── Branching ──────────────────────────────────────────────────

    def branch(self, at_entry_id: str | None = None, summary: str = "") -> BranchingSession:
        """Create a branch from a specific entry.

        Returns a new BranchingSession sharing the same file.
        The new session's leaf is set to the branch point.
        """
        target_id = at_entry_id or self._leaf_id
        if not self._has_entry(target_id):
            raise ValueError(f"Entry {target_id} not found in session")

        branch = BranchingSession(session_id=self.session_id, path=self._path)
        branch._entries = list(self._entries)
        branch._leaf_id = target_id

        if summary:
            branch.add_branch_summary(summary)

        logger.info("Branched session %s at entry %s", self.session_id, target_id)
        return branch

    def merge_from(self, other: BranchingSession) -> int:
        """Merge entries from another branch into this session.

        Only adds entries not already present (by id).
        Returns the number of new entries added.
        """
        existing_ids = {e.id for e in self._entries}
        new_entries = [e for e in other._entries if e.id not in existing_ids]
        self._entries.extend(new_entries)
        self._leaf_id = other._leaf_id
        self._dirty = True
        logger.info("Merged %d entries into session %s", len(new_entries), self.session_id)
        return len(new_entries)

    def navigate_to(self, entry_id: str) -> None:
        """Move the leaf pointer to a specific entry."""
        if entry_id != "root" and not self._has_entry(entry_id):
            raise ValueError(f"Entry {entry_id} not found")
        self._leaf_id = entry_id

    # ── Path extraction ────────────────────────────────────────────

    def get_path_to_leaf(self) -> list[BranchEntry]:
        """Walk from leaf back to root, returning the path entries."""
        path: list[BranchEntry] = []
        lookup = {e.id: e for e in self._entries}

        current_id = self._leaf_id
        while current_id != "root" and current_id:
            entry = lookup.get(current_id)
            if not entry:
                break
            path.insert(0, entry)
            current_id = entry.parent_id

        return path

    def get_messages(self, max_count: int = 0) -> list[dict[str, str]]:
        """Get the message chain from root to leaf as role/content dicts.

        If max_count > 0, returns only the last N messages.
        """
        path = self.get_path_to_leaf()
        messages = [
            {"role": e.role, "content": e.content}
            for e in path
            if e.type == "message" and e.role and e.content
        ]
        if max_count > 0 and len(messages) > max_count:
            messages = messages[-max_count:]
        return messages

    # ── Persistence (JSONL) ────────────────────────────────────────

    def save(self) -> Path:
        """Persist the session to a JSONL file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            for entry in self._entries:
                f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        self._dirty = False
        return self._path

    @classmethod
    def open(cls, path: Path) -> BranchingSession:
        """Open an existing session file."""
        path = Path(path)
        data = path.read_text(encoding="utf-8").strip()
        first_line = data.split("\n")[0] if data else "{}"
        first = json.loads(first_line)
        session_id = first.get("metadata", {}).get("session_id", path.stem)
        return cls(session_id=session_id, path=path)

    def get_export_json(self) -> list[dict[str, Any]]:
        """Export the session as a JSON array."""
        return [asdict(e) for e in self._entries]

    def get_export_markdown(self) -> str:
        """Export the session as readable markdown."""
        lines = [f"# Session: {self.session_id}\n"]
        for entry in self.get_path_to_leaf():
            if entry.type == "message":
                role = entry.role.upper()
                lines.append(f"## {role}\n{entry.content}\n")
            elif entry.type == "compaction":
                lines.append(f"## COMPACTION\n{entry.content}\n")
            elif entry.type == "label":
                lines.append(f"> **Label**: {entry.content}\n")
        return "\n".join(lines)

    # ── Internals ──────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    entry = BranchEntry(**{k: v for k, v in data.items() if k in BranchEntry.__dataclass_fields__})
                    self._entries.append(entry)
            if self._entries:
                self._leaf_id = self._entries[-1].id
        except Exception as exc:
            logger.warning("Failed to load session %s: %s", self._path, exc)

    def _has_entry(self, entry_id: str) -> bool:
        return any(e.id == entry_id for e in self._entries)
