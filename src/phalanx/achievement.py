"""Achievement & gamification system — tracks user milestones, unlocks, and progress.

Awards badges for tool usage, finding severity milestones, learning progress,
and community participation. Persisted to ~/.phalanx/achievements/
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ACHIEVEMENTS_DIR = Path.home() / ".phalanx" / "achievements"


@dataclass
class Achievement:
    id: str
    name: str
    description: str
    icon: str = "🏆"
    category: str = "general"
    tier: str = "bronze"  # bronze, silver, gold, platinum
    unlocked_at: str = ""
    progress: int = 0
    target: int = 1

    @property
    def unlocked(self) -> bool:
        return bool(self.unlocked_at) and self.progress >= self.target


BUILTIN_ACHIEVEMENTS: list[Achievement] = [
    Achievement(id="first_scan", name="First Blood", description="Run your first security scan", icon="🎯", category="scanning", tier="bronze", target=1),
    Achievement(id="ten_scans", name="Scanner", description="Run 10 security scans", icon="🔍", category="scanning", tier="silver", target=10),
    Achievement(id="hundred_scans", name="Power Scanner", description="Run 100 security scans", icon="⚡", category="scanning", tier="gold", target=100),
    Achievement(id="first_vuln", name="Bug Hunter", description="Discover your first vulnerability", icon="🐛", category="finding", tier="bronze", target=1),
    Achievement(id="ten_vulns", name="Vulnerability Collector", description="Discover 10 vulnerabilities", icon="🔬", category="finding", tier="silver", target=10),
    Achievement(id="hundred_vulns", name="Vulnerability Expert", description="Discover 100 vulnerabilities", icon="🧪", category="finding", tier="gold", target=100),
    Achievement(id="first_critical", name="Critical Thinker", description="Find your first critical severity vulnerability", icon="💀", category="finding", tier="silver", target=1),
    Achievement(id="first_tool", name="Tool User", description="Use your first security tool", icon="🛠️", category="tools", tier="bronze", target=1),
    Achievement(id="ten_tools", name="Tool Collector", description="Use 10 different security tools", icon="🧰", category="tools", tier="silver", target=10),
    Achievement(id="twenty_tools", name="Tool Master", description="Use 20 different security tools", icon="🔧", category="tools", tier="gold", target=20),
    Achievement(id="fifty_tools", name="Tool Guru", description="Use 50 different security tools", icon="⚙️", category="tools", tier="platinum", target=50),
    Achievement(id="stealth_ten", name="Stealth Operator", description="Complete 10 scans without IDS triggers", icon="👻", category="stealth", tier="silver", target=10),
    Achievement(id="first_learning", name="Student", description="Complete your first learning module", icon="📚", category="learning", tier="bronze", target=1),
    Achievement(id="ten_learning", name="Scholar", description="Complete 10 learning modules", icon="🎓", category="learning", tier="silver", target=10),

    Achievement(id="first_plugin", name="Extensible", description="Install your first plugin", icon="🔌", category="plugins", tier="bronze", target=1),
    Achievement(id="first_report", name="Reporter", description="Generate your first report", icon="📊", category="reporting", tier="bronze", target=1),
    Achievement(id="first_playbook", name="Playbook Author", description="Create your first playbook", icon="📖", category="playbooks", tier="silver", target=1),

    Achievement(id="first_agent", name="Commander", description="Spawn your first sub-agent", icon="🤖", category="agents", tier="bronze", target=1),
    Achievement(id="perfect_scan", name="Perfectionist", description="Complete a scan with zero failed steps", icon="✨", category="scanning", tier="silver", target=1),
    Achievement(id="first_mobile", name="Mobile Hunter", description="Scan your first mobile application", icon="📱", category="mobile", tier="bronze", target=1),
    Achievement(id="first_iot", name="IoT Explorer", description="Scan your first IoT device", icon="🔌", category="iot", tier="bronze", target=1),
    Achievement(id="first_iac", name="Infrastructure Guardian", description="Scan your first IaC template", icon="🏗️", category="iac", tier="bronze", target=1),
    Achievement(id="first_cloud", name="Cloud Watcher", description="Scan your first cloud environment", icon="☁️", category="cloud", tier="bronze", target=1),
    Achievement(id="compliance_first", name="Compliance Officer", description="Run your first compliance assessment", icon="📋", category="compliance", tier="silver", target=1),
    Achievement(id="first_opsec", name="Ghost", description="Activate OPSEC isolation", icon="👤", category="opsec", tier="silver", target=1),
    Achievement(id="all_modes", name="Chameleon", description="Use all execution modes", icon="🦎", category="general", tier="gold", target=9),
    Achievement(id="all_personas", name="Shapeshifter", description="Use all built-in personas", icon="🌀", category="general", tier="gold", target=9),
    Achievement(id="persistence", name="Persistent", description="Run Phalanx for 7 consecutive days", icon="📅", category="general", tier="platinum", target=7),
]


class AchievementSystem:
    """Tracks and awards achievements for user milestones."""

    def __init__(self) -> None:
        self._file = ACHIEVEMENTS_DIR / "achievements.json"
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._achievements: dict[str, Achievement] = {}
        self._load()

    def _load(self) -> None:
        if not self._file.exists():
            for a in BUILTIN_ACHIEVEMENTS:
                self._achievements[a.id] = Achievement(**{k: v for k, v in a.__dict__.items() if k != "unlocked_at"})
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            for a in BUILTIN_ACHIEVEMENTS:
                saved = data.get(a.id, {})
                self._achievements[a.id] = Achievement(
                    id=a.id, name=saved.get("name", a.name),
                    description=saved.get("description", a.description),
                    icon=saved.get("icon", a.icon), category=saved.get("category", a.category),
                    tier=saved.get("tier", a.tier), unlocked_at=saved.get("unlocked_at", ""),
                    progress=saved.get("progress", 0), target=saved.get("target", a.target),
                )
        except Exception as exc:
            logger.error("Failed to load achievements: %s", exc)
            for a in BUILTIN_ACHIEVEMENTS:
                self._achievements[a.id] = Achievement(**{k: v for k, v in a.__dict__.items() if k != "unlocked_at"})

    def _save(self) -> None:
        try:
            data = {aid: {
                "name": a.name, "description": a.description, "icon": a.icon,
                "category": a.category, "tier": a.tier, "unlocked_at": a.unlocked_at,
                "progress": a.progress, "target": a.target,
            } for aid, a in self._achievements.items()}
            self._file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to save achievements: %s", exc)

    def list_all(self) -> list[Achievement]:
        return list(self._achievements.values())

    def list_unlocked(self) -> list[Achievement]:
        return [a for a in self._achievements.values() if a.unlocked]

    def list_locked(self) -> list[Achievement]:
        return [a for a in self._achievements.values() if not a.unlocked]

    def get_by_category(self, category: str) -> list[Achievement]:
        return [a for a in self._achievements.values() if a.category == category]

    def progress(self, achievement_id: str, amount: int = 1) -> Achievement | None:
        ach = self._achievements.get(achievement_id)
        if not ach or ach.unlocked:
            return ach
        ach.progress = min(ach.progress + amount, ach.target)
        if ach.progress >= ach.target and not ach.unlocked_at:
            ach.unlocked_at = datetime.now(UTC).isoformat()
            logger.info("🏆 Achievement unlocked: %s — %s", ach.icon, ach.name)
        self._save()
        return ach

    def check_and_award(self, event_type: str, value: int = 1, metadata: dict[str, Any] | None = None) -> list[Achievement]:
        """Check all relevant achievements for an event and award progress."""
        newly_unlocked: list[Achievement] = []
        meta = metadata or {}

        if event_type == "scan":
            ach = self.progress("first_scan")
            if ach and ach.unlocked:
                newly_unlocked.append(ach)
            self.progress("ten_scans")
            self.progress("hundred_scans")
            if meta.get("all_success"):
                ach2 = self.progress("perfect_scan")
                if ach2 and ach2.unlocked:
                    newly_unlocked.append(ach2)

        elif event_type == "finding":
            self.progress("first_vuln")
            self.progress("ten_vulns")
            self.progress("hundred_vulns")
            if meta.get("severity") == "critical":
                self.progress("first_critical")

        elif event_type == "tool_used":
            # Progress toward multi-tool achievements
            self.progress("first_tool")
            self.progress("ten_tools")
            self.progress("twenty_tools")
            self.progress("fifty_tools")

        elif event_type == "stealth_scan":
            self.progress("stealth_ten")

        elif event_type == "learning_module":
            self.progress("first_learning")
            self.progress("ten_learning")

        elif event_type == "plugin_install":
            self.progress("first_plugin")

        elif event_type == "report_generated":
            self.progress("first_report")

        elif event_type == "playbook_created":
            self.progress("first_playbook")

        elif event_type == "ctf_joined":
            self.progress("first_ctf")

        elif event_type == "agent_spawned":
            self.progress("first_agent")

        elif event_type == "mobile_scan":
            self.progress("first_mobile")

        elif event_type == "iot_scan":
            self.progress("first_iot")

        elif event_type == "iac_scan":
            self.progress("first_iac")

        elif event_type == "cloud_scan":
            self.progress("first_cloud")

        elif event_type == "compliance_run":
            self.progress("compliance_first")

        elif event_type == "opsec_activated":
            self.progress("first_opsec")

        self._save()
        return newly_unlocked

    def summary(self) -> dict[str, Any]:
        unlocked = self.list_unlocked()
        return {
            "total": len(self._achievements),
            "unlocked": len(unlocked),
            "locked": len(self._achievements) - len(unlocked),
            "by_tier": {
                "bronze": len([a for a in unlocked if a.tier == "bronze"]),
                "silver": len([a for a in unlocked if a.tier == "silver"]),
                "gold": len([a for a in unlocked if a.tier == "gold"]),
                "platinum": len([a for a in unlocked if a.tier == "platinum"]),
            },
        }


achievement_system = AchievementSystem()


__all__ = ["AchievementSystem", "Achievement", "achievement_system", "BUILTIN_ACHIEVEMENTS"]
