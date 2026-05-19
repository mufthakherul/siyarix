"""Manage reusable command profiles / templates for NexSec."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
import re
import logging

logger = logging.getLogger(__name__)

try:
    from jinja2 import Template

    JINJA_AVAILABLE = True
except Exception as exc:
    logger = logging.getLogger(__name__)
    logger.debug("Jinja2 not available: %s", exc)
    JINJA_AVAILABLE = False


def _config_dir() -> Path:
    override = os.getenv("SIYARIX_CONFIG_DIR")
    return Path(override).expanduser() if override else Path.home() / ".siyarix"


@dataclass
class CommandProfile:
    name: str
    command: str
    description: str | None = None
    created_at: str | None = None


class CommandProfileStore:
    def __init__(self) -> None:
        self._dir = _config_dir()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._file = self._dir / "command_profiles.json"

    def _load(self) -> dict[str, Any]:
        if not self._file.exists():
            return {}
        try:
            return json.loads(self._file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.exception("Failed to load command profiles: %s", exc)
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self._file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def list_profiles(self) -> list[CommandProfile]:
        data = self._load()
        rows: list[CommandProfile] = []
        for name, entry in data.items():
            rows.append(
                CommandProfile(
                    name=name,
                    command=entry.get("command", ""),
                    description=entry.get("description"),
                    created_at=entry.get("created_at"),
                )
            )
        return rows

    # Backwards-compatible alias used by CLI
    def list_credentials(self) -> list[CommandProfile]:
        # Backwards-compatible alias for CLI callers
        return self.list_profiles()

    def get(self, name: str) -> CommandProfile | None:
        data = self._load()
        entry = data.get(name)
        if not entry:
            return None
        return CommandProfile(
            name=name,
            command=entry.get("command", ""),
            description=entry.get("description"),
            created_at=entry.get("created_at"),
        )

    def save(self, profile: CommandProfile) -> CommandProfile:
        data = self._load()
        profile.created_at = profile.created_at or datetime.utcnow().isoformat()
        data[profile.name] = {
            "command": profile.command,
            "description": profile.description,
            "created_at": profile.created_at,
        }
        self._save(data)
        return profile

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        data.pop(name)
        self._save(data)
        return True

    # ------------------------- templating helpers -------------------------
    _PLACEHOLDER_RE = re.compile(r"\{\{\s*(?P<j>[^}\s]+)\s*\}\}|\{(?P<f>[^}]+)\}")

    def extract_placeholders(self, command: str) -> list[str]:
        """Return a list of unique placeholder names found in the command.

        Supports both Jinja2-style {{ name }} and Python .format {name} placeholders.
        """
        names = []
        for m in self._PLACEHOLDER_RE.finditer(command):
            name = m.group("j") or m.group("f")
            if name and name not in names:
                names.append(name)
        return names

    def render(self, command: str, params: dict[str, Any] | None = None) -> str:
        """Render *command* using Jinja2 if available, else use str.format fallback.

        Params is a mapping of placeholder names to values.
        """
        params = params or {}
        if JINJA_AVAILABLE:
            try:
                tpl = Template(command)
                return tpl.render(**params)
            except Exception as exc:
                logger.exception("Jinja render failed: %s", exc)
                # Fall back to simple format
                pass
        try:
            return command.format(**params)
        except Exception as exc:
            logger.exception("Format render failed for command: %s (%s)", command, exc)
            # Last resort: return original string
            return command
