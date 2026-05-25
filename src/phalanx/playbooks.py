"""Siyarix Playbook System — Reusable multi-step workflow playbook coordinator."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Standard playbooks path
PLAYBOOKS_DIR = Path.home() / ".siyarix" / "playbooks"


@dataclass
class Playbook:
    """A reusable security scan playbook."""

    name: str
    description: str
    steps: List[Dict[str, Any]]
    variables: List[str] = field(default_factory=list)
    risk_level: str = "low"
    estimated_duration: str = "5 min"
    created_at: str = field(
        default_factory=lambda: str(Path().stat().st_ctime) if Path().exists() else ""
    )

    def render(self, vars_dict: Dict[str, str]) -> List[Dict[str, Any]]:
        """Render steps replacing variables of the form ${var}."""
        steps_json = json.dumps(self.steps)
        for key, val in vars_dict.items():
            steps_json = steps_json.replace(f"${{{key}}}", val)
            steps_json = steps_json.replace(f"$({key})", val)
        return json.loads(steps_json)


class PlaybookManager:
    """Manages saved security playbooks on the system."""

    def __init__(self, directory: Path = PLAYBOOKS_DIR) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Seed default templates into playbooks directory."""
        from siyarix.workflow_generator import BUILTIN_TEMPLATES

        for key, t in BUILTIN_TEMPLATES.items():
            path = self.directory / f"{key}.json"
            if not path.exists():
                pb = Playbook(
                    name=t.name,
                    description=t.description,
                    steps=t.steps,
                    variables=t.variables,
                    risk_level=t.risk_level,
                    estimated_duration=t.estimated_duration,
                )
                self.save(key, pb)

    def save(self, key: str, playbook: Playbook) -> Path:
        """Save a playbook to file."""
        path = self.directory / f"{key}.json"
        data = {
            "name": playbook.name,
            "description": playbook.description,
            "risk_level": playbook.risk_level,
            "estimated_duration": playbook.estimated_duration,
            "variables": playbook.variables,
            "steps": playbook.steps,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def load(self, key: str) -> Playbook | None:
        """Load a playbook by key."""
        path = self.directory / f"{key}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Playbook(
                name=data.get("name", ""),
                description=data.get("description", ""),
                steps=data.get("steps", []),
                variables=data.get("variables", []),
                risk_level=data.get("risk_level", "low"),
                estimated_duration=data.get("estimated_duration", "5 min"),
            )
        except Exception as exc:
            logger.error("Error loading playbook %s: %s", key, exc)
            return None

    def list_all(self) -> Dict[str, Dict[str, Any]]:
        """List all available playbooks."""
        result = {}
        for path in self.directory.glob("*.json"):
            key = path.stem
            pb = self.load(key)
            if pb:
                result[key] = {
                    "name": pb.name,
                    "description": pb.description,
                    "risk_level": pb.risk_level,
                    "estimated_duration": pb.estimated_duration,
                    "variables": pb.variables,
                    "step_count": len(pb.steps),
                }
        return result


playbook_manager = PlaybookManager()
