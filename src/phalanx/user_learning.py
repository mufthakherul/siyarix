"""
User Learning — Adaptive pedagogical output and experience profiling.

As described in Chapter 10.2 with enterprise-grade enhancements:

  • Auto-detect experience level from usage patterns (tool diversity,
    command complexity, error rates, advanced feature adoption)
  • Command complexity tracking (flags, pipes, chaining)
  • Category diversity tracking (recon, exploit, web, wireless, etc.)
  • Learning goals and milestone achievements
  • Structured output formatting based on experience level
  • Multi-session persistence with full session history
  • Preference learning (color themes, output formats, verbosity)
  • Integration with XI SkillProfiler for bidirectional state sync
  • Progress metrics and personalized improvement suggestions
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_LEARNING_DIR = _PHALANX_HOME / "learning"

# Command complexity features
_COMPLEXITY_FLAGS = frozenset({"--dry-run", "--parallel", "--persist", "-v", "-vv", "-vvv"})
_COMPLEXITY_OPERATORS = frozenset({"&&", "||", "|", ";", "|&"})

# Tool categories for diversity tracking
_TOOL_CATEGORIES: dict[str, str] = {
    "nmap": "recon",
    "masscan": "recon",
    "whois": "recon",
    "dig": "recon",
    "nslookup": "recon",
    "theHarvester": "recon",
    "amass": "recon",
    "subfinder": "recon",
    "assetfinder": "recon",
    "dnsx": "recon",
    "httpx": "recon",
    "waybackurls": "recon",
    "gau": "recon",
    "katana": "recon",
    "shodan": "recon",
    "gobuster": "web",
    "ffuf": "web",
    "dirb": "web",
    "dirsearch": "web",
    "nikto": "web",
    "wpscan": "web",
    "nuclei": "web",
    "sqlmap": "web",
    "zap": "web",
    "burpsuite": "web",
    "hydra": "exploit",
    "john": "exploit",
    "hashcat": "exploit",
    "msfconsole": "exploit",
    "metasploit": "exploit",
    "bettercap": "exploit",
    "aircrack-ng": "wireless",
    "reaver": "wireless",
    "wifite": "wireless",
    "kismet": "wireless",
    "impacket": "exploit",
    "responder": "exploit",
    "crackmapexec": "exploit",
    "evil-winrm": "exploit",
    "bloodhound": "exploit",
    "volatility": "forensics",
    "binwalk": "forensics",
    "sleuthkit": "forensics",
    "docker": "infra",
    "kubectl": "infra",
    "terraform": "infra",
    "ansible": "infra",
}

# Milestone definitions
_MILESTONES = [
    {"id": "first_command", "name": "First Command", "icon": "", "cond": lambda p: p.total_commands >= 1},
    {"id": "tool_diversity_3", "name": "Tool Explorer", "icon": "", "cond": lambda p: p.category_count >= 2 and p.unique_tools >= 3},
    {"id": "ten_commands", "name": "Getting Started", "icon": "", "cond": lambda p: p.total_commands >= 10},
    {"id": "all_categories", "name": "Tool Master", "icon": "", "cond": lambda p: p.category_count >= 4},
    {"id": "advanced_user", "name": "Power User", "icon": "", "cond": lambda p: p.advanced_command_count >= 5},
    {"id": "hundred_commands", "name": "Centurion", "icon": "", "cond": lambda p: p.total_commands >= 100},
    {"id": "exploit_initiated", "name": "First Exploit", "icon": "", "cond": lambda p: p.category_counts.get("exploit", 0) >= 1},
    {"id": "recon_specialist", "name": "Recon Specialist", "icon": "", "cond": lambda p: p.category_counts.get("recon", 0) >= 10},
    {"id": "web_expert", "name": "Web Expert", "icon": "", "cond": lambda p: p.category_counts.get("web", 0) >= 10},
    {"id": "wireless_pioneer", "name": "Wireless Pioneer", "icon": "", "cond": lambda p: p.category_counts.get("wireless", 0) >= 1},
    {"id": "forensics_investigator", "name": "Forensics Investigator", "icon": "", "cond": lambda p: p.category_counts.get("forensics", 0) >= 1},
    {"id": "expert_level", "name": "Expert Status", "icon": "", "cond": lambda p: p.experience == "expert"},
]


class ExperienceLevel:
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

    @classmethod
    def all(cls) -> list[str]:
        return [cls.NOVICE, cls.INTERMEDIATE, cls.ADVANCED, cls.EXPERT]

    @classmethod
    def auto_detect(cls, profile: UserProfile) -> str:
        """Auto-detect experience level from user profile metrics."""
        score = 0.0

        # Tool diversity (0-30 points)
        score += min(profile.unique_tools * 3, 30)

        # Category diversity (0-20 points)
        score += min(profile.category_count * 5, 20)

        # Advanced commands (0-25 points)
        score += min(profile.advanced_command_count * 5, 25)

        # Command volume (0-15 points)
        if profile.total_commands > 100:
            score += 15
        elif profile.total_commands > 50:
            score += 10
        elif profile.total_commands > 20:
            score += 5

        # Error rate penalty (0 to -15)
        error_rate = profile.error_rate if profile.total_commands > 0 else 0
        if error_rate > 0.4:
            score -= 15
        elif error_rate > 0.25:
            score -= 8
        elif error_rate > 0.1:
            score -= 3

        score = max(0, min(100, score))

        if score >= 80:
            return cls.EXPERT
        elif score >= 55:
            return cls.ADVANCED
        elif score >= 30:
            return cls.INTERMEDIATE
        return cls.NOVICE


@dataclass
class SessionRecord:
    """Record of a single learning session."""
    session_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    command_count: int = 0
    tools_used: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    findings_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "command_count": self.command_count,
            "tools_used": self.tools_used,
            "categories": self.categories,
            "findings_found": self.findings_found,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 1),
        }

    @classmethod
    def from_dict(cls, data: dict) -> SessionRecord:
        return cls(**{k: v for k, v in data.items() if k in {
            "session_id", "started_at", "ended_at", "command_count",
            "tools_used", "categories", "findings_found", "errors", "duration_seconds",
        }})


@dataclass
class UserProfile:
    """Comprehensive user profile with learning metrics."""
    username: str = ""
    experience: str = ExperienceLevel.INTERMEDIATE
    auto_detect: bool = True
    total_commands: int = 0
    unique_tools: int = 0
    advanced_command_count: int = 0
    category_count: int = 0
    category_counts: dict[str, int] = field(default_factory=dict)
    error_rate: float = 0.0
    total_errors: int = 0
    total_findings: int = 0
    session_count: int = 0
    milestones: list[str] = field(default_factory=list)
    preferences: dict = field(default_factory=lambda: {
        "verbosity": "adaptive",
        "show_hints": True,
        "auto_confirm_safe": False,
        "output_format": "rich",
        "color_theme": "",
        "show_timestamps": True,
        "compact_mode": False,
    })
    recent_tools: list[str] = field(default_factory=list)
    sessions: list[SessionRecord] = field(default_factory=list)
    updated_at: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "experience": self.experience,
            "auto_detect": self.auto_detect,
            "total_commands": self.total_commands,
            "unique_tools": self.unique_tools,
            "advanced_command_count": self.advanced_command_count,
            "category_count": self.category_count,
            "category_counts": self.category_counts,
            "error_rate": round(self.error_rate, 4),
            "total_errors": self.total_errors,
            "total_findings": self.total_findings,
            "session_count": self.session_count,
            "milestones": self.milestones,
            "preferences": self.preferences,
            "recent_tools": self.recent_tools[-50:],
            "sessions": [s.to_dict() for s in self.sessions[-50:]],
            "updated_at": self.updated_at,
            "created_at": self.created_at or datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> UserProfile:
        sessions = [SessionRecord.from_dict(s) for s in data.get("sessions", [])]
        return cls(
            username=data.get("username", ""),
            experience=data.get("experience", ExperienceLevel.INTERMEDIATE),
            auto_detect=data.get("auto_detect", True),
            total_commands=data.get("total_commands", 0),
            unique_tools=data.get("unique_tools", 0),
            advanced_command_count=data.get("advanced_command_count", 0),
            category_count=data.get("category_count", 0),
            category_counts=data.get("category_counts", {}),
            error_rate=data.get("error_rate", 0.0),
            total_errors=data.get("total_errors", 0),
            total_findings=data.get("total_findings", 0),
            session_count=data.get("session_count", 0),
            milestones=data.get("milestones", []),
            preferences=data.get("preferences", {
                "verbosity": "adaptive",
                "show_hints": True,
                "auto_confirm_safe": False,
                "output_format": "rich",
                "color_theme": "",
                "show_timestamps": True,
                "compact_mode": False,
            }),
            recent_tools=data.get("recent_tools", []),
            sessions=sessions,
            updated_at=data.get("updated_at", ""),
            created_at=data.get("created_at", ""),
        )


class UserLearning:
    """Adaptive learning system for user experience profiling and pedagogical output.

    Features:
      - Auto-detection of experience level from usage patterns
      - Command complexity analysis (flags, chaining)
      - Tool category diversity tracking
      - Milestone achievement system
      - Multi-session history with analytics
      - Preference learning and adaptation
      - Integration with XI SkillProfiler
    """

    def __init__(self, xi_skill_profiler: Any = None) -> None:
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        self._profile_path = _LEARNING_DIR / "user_profile.json"
        self._profile = UserProfile()
        self._skill_profiler = xi_skill_profiler
        self._current_session: SessionRecord | None = None
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._profile_path.exists():
            return
        try:
            with open(str(self._profile_path)) as f:
                data = json.load(f)
            self._profile = UserProfile.from_dict(data)
        except Exception as exc:
            logger.warning("Failed to load user profile: %s", exc)

    def _save(self) -> None:
        self._profile.updated_at = datetime.now(timezone.utc).isoformat()
        try:
            with open(str(self._profile_path), "w") as f:
                json.dump(self._profile.to_dict(), f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Failed to save user profile: %s", exc)

    # ── Profile Access ───────────────────────────────────────────────────

    @property
    def profile(self) -> UserProfile:
        return self._profile

    @property
    def experience(self) -> str:
        return self._profile.experience

    @experience.setter
    def experience(self, level: str) -> None:
        if level in ExperienceLevel.all():
            self._profile.experience = level
            self._profile.auto_detect = False
            self._save()

    @property
    def auto_detect_enabled(self) -> bool:
        return self._profile.auto_detect

    def enable_auto_detect(self) -> None:
        self._profile.auto_detect = True
        self._reassess()
        self._save()

    def disable_auto_detect(self) -> None:
        self._profile.auto_detect = False
        self._save()

    # ── Preference Management ────────────────────────────────────────────

    def set_preference(self, key: str, value: Any) -> None:
        valid_keys = {
            "verbosity", "show_hints", "auto_confirm_safe",
            "output_format", "color_theme", "show_timestamps", "compact_mode",
        }
        if key not in valid_keys:
            logger.warning("Unknown preference key: %s", key)
            return
        self._profile.preferences[key] = value
        self._save()

    def get_preference(self, key: str, default: Any = None) -> Any:
        return self._profile.preferences.get(key, default)

    @property
    def preferences(self) -> dict:
        return dict(self._profile.preferences)

    # ── Session Management ───────────────────────────────────────────────

    def start_session(self, session_id: str = "") -> None:
        """Begin a new learning session."""
        self._current_session = SessionRecord(
            session_id=session_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._profile.session_count += 1
        self._save()

    def end_session(self) -> SessionRecord | None:
        """Finalize the current learning session."""
        if not self._current_session:
            return None
        self._current_session.ended_at = datetime.now(timezone.utc).isoformat()
        self._profile.sessions.append(self._current_session)
        self._reassess()
        self._save()
        session = self._current_session
        self._current_session = None
        return session

    # ── Command Recording ────────────────────────────────────────────────

    def record_command(
        self,
        command: str,
        tool: str = "",
        success: bool = True,
        findings_count: int = 0,
    ) -> None:
        """Record a command execution and update the learning profile."""
        p = self._profile
        p.total_commands += 1

        if not success:
            p.total_errors += 1

        p.total_findings += findings_count

        # Track tool usage
        if tool:
            if tool not in p.recent_tools:
                pass
            p.recent_tools.append(tool)
            p.recent_tools = p.recent_tools[-50:]

            # Track category
            category = _TOOL_CATEGORIES.get(tool.lower(), "other")
            p.category_counts[category] = p.category_counts.get(category, 0) + 1
            p.category_count = len(p.category_counts)

            # Track unique tools
            unique = set(p.recent_tools)
            p.unique_tools = len(unique)

        # Command complexity analysis
        complexity_score = self._analyze_complexity(command)
        if complexity_score >= 3:
            p.advanced_command_count += 1

        # Update current session
        if self._current_session:
            self._current_session.command_count += 1
            if tool and tool not in self._current_session.tools_used:
                self._current_session.tools_used.append(tool)
            if not success:
                self._current_session.errors += 1
            self._current_session.findings_found += findings_count
            if tool:
                cat = _TOOL_CATEGORIES.get(tool.lower(), "other")
                if cat not in self._current_session.categories:
                    self._current_session.categories.append(cat)

        # Auto-reassess if auto-detect enabled
        if p.auto_detect and p.total_commands % 5 == 0:
            self._reassess()

        # Sync with SkillProfiler
        self._sync_skill_profiler(command, tool, success)

        # Check milestones
        self._check_milestones()

        self._save()

    def _analyze_complexity(self, command: str) -> int:
        """Score command complexity: 0=simple, 5+=advanced."""
        score = 0
        parts = command.split()

        # Flag count
        flag_count = sum(1 for p in parts if p.startswith("-"))
        score += min(flag_count, 3)

        # Pipe/chaining operators
        for op in _COMPLEXITY_OPERATORS:
            if op in parts:
                score += 2

        # Long command
        if len(parts) > 10:
            score += 1
        if len(parts) > 20:
            score += 1

        # Complex flags
        for flag in _COMPLEXITY_FLAGS:
            if flag in parts:
                score += 1

        return score

    # ── Experience Assessment ────────────────────────────────────────────

    def _reassess(self) -> None:
        """Re-evaluate experience level based on profile metrics."""
        if not self._profile.auto_detect:
            return

        p = self._profile
        new_level = ExperienceLevel.auto_detect(p)

        if new_level != p.experience:
            old = p.experience
            p.experience = new_level
            logger.info("Experience level auto-updated: %s -> %s", old, new_level)

    # ── Milestones ──────────────────────────────────────────────────────

    def _check_milestones(self) -> list[dict]:
        """Check and record any newly achieved milestones."""
        newly_achieved = []
        for m in _MILESTONES:
            if m["id"] not in self._profile.milestones and m["cond"](self._profile):
                self._profile.milestones.append(m["id"])
                newly_achieved.append(m)
                logger.info("Milestone achieved: %s", m["name"])
        if newly_achieved:
            self._save()
        return newly_achieved

    def get_milestones(self) -> list[dict]:
        """Return all milestones with achievement status."""
        result = []
        for m in _MILESTONES:
            achieved = m["id"] in self._profile.milestones
            result.append({
                "id": m["id"],
                "name": m["name"],
                "icon": m["icon"],
                "achieved": achieved,
            })
        return result

    # ── XI Integration ───────────────────────────────────────────────────

    def _sync_skill_profiler(self, command: str, tool: str, success: bool) -> None:
        """Sync command data to XI SkillProfiler if available."""
        if self._skill_profiler and hasattr(self._skill_profiler, "record_command"):
            try:
                self._skill_profiler.record_command(command, tool=tool, success=success)
            except Exception as exc:
                logger.debug("SkillProfiler sync failed: %s", exc)

    def sync_from_skill_profiler(self) -> None:
        """Import assessment from SkillProfiler into our profile."""
        if not self._skill_profiler:
            return
        try:
            sp_profile = self._skill_profiler.profile
            if sp_profile and hasattr(sp_profile, "level"):
                self._profile.experience = sp_profile.level
                self._save()
        except Exception as exc:
            logger.debug("SkillProfiler import failed: %s", exc)

    # ── Output Formatting ────────────────────────────────────────────────

    def should_show_explanation(self) -> bool:
        if self._profile.auto_detect:
            return self._profile.experience in (ExperienceLevel.NOVICE, ExperienceLevel.INTERMEDIATE)
        return self._profile.preferences.get("show_hints", True)

    def verbosity_level(self) -> int:
        if not self._profile.auto_detect:
            pref = self._profile.preferences.get("verbosity", "adaptive")
            return {"minimal": 0, "compact": 1, "normal": 1, "verbose": 2}.get(pref, 1)
        return {
            ExperienceLevel.NOVICE: 2,
            ExperienceLevel.INTERMEDIATE: 1,
            ExperienceLevel.ADVANCED: 1,
            ExperienceLevel.EXPERT: 0,
        }.get(self._profile.experience, 1)

    def auto_confirm_safe(self) -> bool:
        return self._profile.experience == ExperienceLevel.EXPERT

    def format_output(self, content: str, title: str = "") -> Panel | str:
        """Format output appropriately for the user's experience level."""
        verbosity = self.verbosity_level()
        if verbosity == 0:
            return content if len(content) < 200 else content[:200] + "..."
        return Panel(content, title=title or "Output", border_style="green")

    # ── Analytics ────────────────────────────────────────────────────────

    def get_profile_panel(self) -> Panel:
        p = self._profile
        tree = Tree(f"[bold cyan]User: {p.username or 'anonymous'}[/bold cyan]")
        tree.add(f"[bold]Experience:[/bold] [magenta]{p.experience}[/magenta]")
        tree.add(f"[bold]Auto-detect:[/bold] {'[green]On[/green]' if p.auto_detect else '[yellow]Off[/yellow]'}")
        tree.add(f"[bold]Total Commands:[/bold] {p.total_commands}")
        tree.add(f"[bold]Unique Tools:[/bold] {p.unique_tools}")
        tree.add(f"[bold]Categories:[/bold] {p.category_count} ({', '.join(p.category_counts.keys()) or 'none'})")
        tree.add(f"[bold]Advanced Commands:[/bold] {p.advanced_command_count}")
        tree.add(f"[bold]Error Rate:[/bold] {p.error_rate:.1%}")
        tree.add(f"[bold]Findings Found:[/bold] {p.total_findings}")
        tree.add(f"[bold]Sessions:[/bold] {p.session_count}")
        tree.add(f"[bold]Verbosity:[/bold] {self.verbosity_level()}/2")
        tree.add(f"[bold]Explanations:[/bold] {'[green]On[/green]' if self.should_show_explanation() else '[red]Off[/red]'}")

        # Milestones
        achieved = [m for m in _MILESTONES if m["id"] in p.milestones]
        if achieved:
            m_branch = tree.add("[bold]Milestones:[/bold]")
            for m in achieved:
                m_branch.add(f"[green]{m['name']}[/green]")

        return Panel(
            tree,
            title="User Learning Profile",
            border_style="cyan",
            padding=(1, 2),
        )

    def get_milestones_panel(self) -> Panel:
        milestones = self.get_milestones()
        achieved_count = sum(1 for m in milestones if m["achieved"])
        table = Table(title=f"Milestones ({achieved_count}/{len(milestones)})", header_style="bold cyan")
        table.add_column("Status", width=4)
        table.add_column("Name", style="white")
        table.add_column("ID", style="dim")

        for m in milestones:
            status = "[green]" if m["achieved"] else "[dim]"
            table.add_row(
                f"{status}{'[green]' if m['achieved'] else '[dim]'}[/]",
                f"{status}{m['name']}[/]",
                f"[dim]{m['id']}[/]" if m["achieved"] else f"[dim]{m['id']}[/]",
            )
        return Panel(table, title="Learning Milestones", border_style="green")

    def get_sessions_panel(self, limit: int = 10) -> Panel:
        sessions = self._profile.sessions[-limit:]
        if not sessions:
            return Panel("[dim]No sessions recorded yet.[/dim]", title="Session History", border_style="dim")

        table = Table(title=f"Recent Sessions ({len(sessions)})", header_style="bold cyan")
        table.add_column("ID", style="cyan", width=16)
        table.add_column("Cmds", justify="right")
        table.add_column("Tools", style="green")
        table.add_column("Findings", justify="right")
        table.add_column("Errors", justify="right")
        table.add_column("Duration", style="dim")

        for s in reversed(sessions):
            dur = f"{s.duration_seconds:.0f}s" if s.duration_seconds else "-"
            tools = ", ".join(s.tools_used[:3])
            if len(s.tools_used) > 3:
                tools += "..."
            table.add_row(
                s.session_id[:12],
                str(s.command_count),
                tools,
                str(s.findings_found),
                str(s.errors),
                dur,
            )
        return Panel(table, title="Session History", border_style="cyan")

    def get_improvement_suggestions(self) -> list[str]:
        """Generate personalized improvement suggestions."""
        suggestions = []
        p = self._profile

        # Tool diversity
        if p.unique_tools < 5:
            suggestions.append("Try more tools: explore nmap, whois, gobuster, nuclei, hydra")
        elif p.unique_tools < 15:
            suggestions.append("Good tool diversity! Try advanced tools like bloodhound, impacket")

        # Category diversity
        missing_categories = [c for c in ("recon", "web", "exploit", "wireless", "forensics")
                              if c not in p.category_counts]
        if missing_categories:
            suggestions.append(f"Explore new areas: {'/'.join(missing_categories)}")

        # Advanced features
        if p.advanced_command_count < 3 and p.total_commands > 10:
            suggestions.append("Try advanced flags: --dry-run, --parallel, or chain commands with &&")

        # Error rate
        if p.error_rate > 0.2 and p.total_commands > 10:
            suggestions.append(f"Error rate is {p.error_rate:.0%}. Try using --dry-run to preview commands")

        # Command volume
        if p.total_commands < 20:
            suggestions.append("Keep practising! Run more commands to build skill")

        return suggestions

    def clear_history(self) -> None:
        """Reset all user learning data."""
        self._profile = UserProfile()
        self._save()
        logger.info("User learning history cleared")


__all__ = [
    "UserLearning",
    "UserProfile",
    "SessionRecord",
    "ExperienceLevel",
]
