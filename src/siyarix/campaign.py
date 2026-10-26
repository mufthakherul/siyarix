# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent multi-target campaign registry for researcher workflows.

Campaigns store engagement target lists under the config dir so ``/campaign``
in the REPL and CLI tips can round-trip without inventing ephemeral state.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siyarix.config import get_config_dir

__all__ = [
    "Campaign",
    "CampaignStore",
    "load_targets_file",
    "sanitize_campaign_name",
]

_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def sanitize_campaign_name(name: str) -> str:
    """Normalize a campaign name to a safe filesystem slug."""
    cleaned = _NAME_RE.sub("-", (name or "").strip()).strip("-._")
    return cleaned[:80] or "campaign"


def load_targets_file(path: Path) -> list[str]:
    """Load non-empty, non-comment target lines from a text file."""
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Campaign:
    """A named multi-target engagement campaign."""

    name: str
    targets: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    status: str = "ready"  # ready | running | completed
    notes: str = ""
    last_run_at: str | None = None
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Campaign:
        targets = data.get("targets") or []
        if not isinstance(targets, list):
            targets = []
        return cls(
            name=str(data.get("name") or "campaign"),
            targets=[str(t) for t in targets if str(t).strip()],
            created_at=str(data.get("created_at") or ""),
            updated_at=str(data.get("updated_at") or ""),
            status=str(data.get("status") or "ready"),
            notes=str(data.get("notes") or ""),
            last_run_at=(str(data["last_run_at"]) if data.get("last_run_at") else None),
            run_count=int(data.get("run_count") or 0),
        )


class CampaignStore:
    """JSON-backed campaign store under ``~/.siyarix/campaigns/``."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._dir = Path(base_dir) if base_dir is not None else get_config_dir() / "campaigns"
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, name: str) -> Path:
        slug = sanitize_campaign_name(name)
        return self._dir / f"{slug}.json"

    def targets_file(self, name: str) -> Path:
        """Path to the plain-text targets file used with ``@file`` scan syntax."""
        slug = sanitize_campaign_name(name)
        return self._dir / f"{slug}.targets.txt"

    def list_campaigns(self) -> list[Campaign]:
        items: list[Campaign] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                items.append(Campaign.from_dict(data))
        items.sort(key=lambda c: c.updated_at or c.created_at, reverse=True)
        return items

    def get(self, name: str) -> Campaign | None:
        path = self._path_for(name)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return Campaign.from_dict(data)

    def create(
        self,
        name: str,
        targets: Iterable[str],
        *,
        notes: str = "",
    ) -> Campaign:
        slug = sanitize_campaign_name(name)
        if self.get(slug) is not None:
            raise ValueError(f"Campaign already exists: {slug}")
        now = _utc_now()
        unique_targets: list[str] = []
        seen: set[str] = set()
        for raw in targets:
            t = str(raw).strip()
            if not t or t in seen:
                continue
            seen.add(t)
            unique_targets.append(t)
        camp = Campaign(
            name=slug,
            targets=unique_targets,
            created_at=now,
            updated_at=now,
            status="ready" if unique_targets else "ready",
            notes=notes.strip(),
        )
        self._write(camp)
        return camp

    def save(self, campaign: Campaign) -> Campaign:
        campaign.updated_at = _utc_now()
        self._write(campaign)
        return campaign

    def mark_run(self, name: str) -> Campaign | None:
        camp = self.get(name)
        if camp is None:
            return None
        camp.last_run_at = _utc_now()
        camp.run_count = int(camp.run_count) + 1
        camp.status = "running"
        return self.save(camp)

    def set_status(self, name: str, status: str) -> Campaign | None:
        camp = self.get(name)
        if camp is None:
            return None
        camp.status = status
        return self.save(camp)

    def delete(self, name: str) -> bool:
        path = self._path_for(name)
        targets = self.targets_file(name)
        removed = False
        if path.is_file():
            path.unlink()
            removed = True
        if targets.is_file():
            targets.unlink(missing_ok=True)
            removed = True
        return removed

    def write_targets_file(self, campaign: Campaign) -> Path:
        path = self.targets_file(campaign.name)
        body = "\n".join(campaign.targets) + ("\n" if campaign.targets else "")
        path.write_text(body, encoding="utf-8")
        return path

    def _write(self, campaign: Campaign) -> None:
        path = self._path_for(campaign.name)
        path.write_text(
            json.dumps(campaign.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.write_targets_file(campaign)
