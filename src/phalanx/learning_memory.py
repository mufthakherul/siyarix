"""
Learning Memory — Complete tool learning system per Chapter 10.1.

Features:
  • User correction tracking: learns from modifications to AI-generated commands
  • Task-type aware: classifies commands into web_scan, port_scan, subdomain_enum, etc.
  • Platform-specific optimization: tracks which flags perform best per OS
  • Tool flag effectiveness: measures which flags produce the most findings
  • Execution timing: fast vs. thorough categorization
  • N-gram pattern learning (up to order 5)
  • Exponential time-based decay for stale patterns
  • Bayesian confidence scoring (success-rate x sample-size)
  • Anti-pattern detection for failed chains
  • Context-weighted suggestions (phase, target, session recency)
  • Learning event output: natural-language explanation of insights
  • Full export/import + XI Predictor integration
"""

from __future__ import annotations

import difflib
import json
import logging
import platform
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_MEMORY_DIR = _PHALANX_HOME / "memory"
_LEARNING_DIR = _PHALANX_HOME / "learning"

_PATTERN_HALF_LIFE = 2592000.0  # 30 days
_MAX_NGRAM_ORDER = 5
_MIN_CONFIDENCE_SAMPLES = 3

# ── Classification ───────────────────────────────────────────────────────

_TASK_KEYWORDS: dict[str, list[str]] = {
    "port_scan": ["nmap", "masscan", "rustscan", "port scan", "portscan"],
    "subdomain_enum": ["subfinder", "amass", "assetfinder", "subdomain", "dns"],
    "web_scan": [
        "nuclei",
        "nikto",
        "gobuster",
        "ffuf",
        "feroxbuster",
        "wpscan",
        "web",
        "http",
    ],
    "dir_enum": ["gobuster dir", "ffuf", "dirb", "dirsearch", "directory"],
    "vuln_scan": ["nuclei", "vuln", "cve", "nikto"],
    "exploit": ["hydra", "sqlmap", "msfconsole", "metasploit", "exploit"],
    "password_attack": ["hydra", "john", "hashcat", "password", "brute"],
    "osint": ["theHarvester", "shodan", "whois", "dig", "osint"],
    "wireless": ["aircrack", "reaver", "wifite", "kismet", "wireless"],
    "forensics": ["volatility", "binwalk", "sleuthkit", "forensic"],
    "cloud_enum": ["aws", "az", "gcloud", "cloud"],
    "recon": ["recon", "enumerate", "discover", "gather"],
}

# Timing thresholds in seconds
_FAST_THRESHOLD = 30.0  # Under 30s = "fast"
_THOROUGH_THRESHOLD = 300.0  # Over 5min = "thorough"

# ── Dataclasses ───────────────────────────────────────────────────────────


@dataclass
class ToolPattern:
    """A learned tool-usage pattern per Chapter 10.1 schema."""

    ngram: list[str]
    task_type: str = ""
    persona: str = ""
    platform: str = ""
    count: int = 1
    success_count: int = 1
    last_used: str = ""
    total_duration_ms: float = 0.0
    total_findings: int = 0
    context_tags: list[str] = field(default_factory=list)
    phase: str = ""
    is_anti_pattern: bool = False
    decay_score: float = 1.0

    # ── Correction tracking (10.1) ───────────────────────────────────────
    original_command: str = ""  # AI-generated command
    user_correction: str = ""  # User-modified command
    correction_findings_delta: int = 0  # Extra findings from correction
    correction_count: int = 0

    # ── Flag effectiveness (10.1) ────────────────────────────────────────
    effective_flags: list[str] = field(default_factory=list)
    ineffective_flags: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """Bayesian confidence combining rate and sample size."""
        if self.count < _MIN_CONFIDENCE_SAMPLES:
            ratio = self.success_count / max(self.count, 1)
            return ratio * (self.count / _MIN_CONFIDENCE_SAMPLES)
        rate = self.success_count / max(self.count, 1)
        return rate * min(self.decay_score, 1.0)

    @property
    def success_rate(self) -> float:
        return self.success_count / max(self.count, 1)

    @property
    def avg_duration_ms(self) -> float:
        return self.total_duration_ms / max(self.count, 1)

    @property
    def avg_findings(self) -> float:
        return self.total_findings / max(self.count, 1)

    @property
    def timing_category(self) -> str:
        """Categorize execution as 'fast' or 'thorough'."""
        sec = self.avg_duration_ms / 1000.0
        if sec <= 0:
            return "unknown"
        if sec <= _FAST_THRESHOLD:
            return "fast"
        if sec >= _THOROUGH_THRESHOLD:
            return "thorough"
        return "balanced"

    @property
    def has_correction(self) -> bool:
        return (
            bool(self.user_correction) and self.user_correction != self.original_command
        )

    @property
    def flag_effectiveness_score(self) -> float:
        """Ratio of effective to total tracked flags."""
        total = len(self.effective_flags) + len(self.ineffective_flags)
        if total == 0:
            return 0.0
        return len(self.effective_flags) / total

    def apply_decay(self, reference_time: float | None = None) -> None:
        if not self.last_used:
            self.decay_score = 1.0
            return
        try:
            last = datetime.fromisoformat(self.last_used).timestamp()
        except (ValueError, TypeError):
            self.decay_score = 1.0
            return
        ref = reference_time or time.time()
        half_lives = max(0.0, ref - last) / _PATTERN_HALF_LIFE
        self.decay_score = 2.0 ** (-half_lives)

    def to_dict(self) -> dict:
        return {
            "ngram": self.ngram,
            "task_type": self.task_type,
            "persona": self.persona,
            "platform": self.platform,
            "count": self.count,
            "success_count": self.success_count,
            "last_used": self.last_used,
            "total_duration_ms": self.total_duration_ms,
            "total_findings": self.total_findings,
            "context_tags": self.context_tags,
            "phase": self.phase,
            "is_anti_pattern": self.is_anti_pattern,
            "original_command": self.original_command,
            "user_correction": self.user_correction,
            "correction_findings_delta": self.correction_findings_delta,
            "correction_count": self.correction_count,
            "effective_flags": self.effective_flags,
            "ineffective_flags": self.ineffective_flags,
            "timing_category": self.timing_category,
            "confidence": round(self.confidence, 4),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolPattern:
        return cls(
            ngram=data.get("ngram", []),
            task_type=data.get("task_type", ""),
            persona=data.get("persona", ""),
            platform=data.get("platform", ""),
            count=data.get("count", 1),
            success_count=data.get("success_count", 1),
            last_used=data.get("last_used", ""),
            total_duration_ms=data.get("total_duration_ms", 0.0),
            total_findings=data.get("total_findings", 0),
            context_tags=data.get("context_tags", []),
            phase=data.get("phase", ""),
            is_anti_pattern=data.get("is_anti_pattern", False),
            original_command=data.get("original_command", ""),
            user_correction=data.get("user_correction", ""),
            correction_findings_delta=data.get("correction_findings_delta", 0),
            correction_count=data.get("correction_count", 0),
            effective_flags=data.get("effective_flags", []),
            ineffective_flags=data.get("ineffective_flags", []),
        )


@dataclass
class LearningEvent:
    """A human-readable learning event emitted when a pattern is recorded."""

    task: str
    generated: str  # AI-generated command
    user_modified: str  # User-modified version (if any)
    result: str  # Outcome description
    insight: str  # Natural-language lesson
    delta_findings: int = 0

    def format_message(self, persona: str = "Phalanx") -> str:
        lines = [
            f'[{persona}] Task: "{self.task}"',
            f"[{persona}] Generated: {self.generated}",
        ]
        if self.user_modified and self.user_modified != self.generated:
            lines.append(f"[{persona}] User modified: {self.user_modified}")
        lines.append(f"[{persona}] Result: {self.result}")
        lines.append(f'[{persona}] Learning: "{self.insight}"')
        lines.append(
            f"[{persona}] Pattern saved. Future similar tasks will suggest this."
        )
        return "\n".join(lines)


# ── Main Engine ──────────────────────────────────────────────────────────


class LearningMemory:
    """Persistent learning engine for tool patterns per Chapter 10.1.

    Activation::

        lm = LearningMemory()
        lm.set_tool_learning(True)   # /config learning tool on

    Recording a user correction::

        lm.record_with_correction(
            tools=["nuclei"],
            original="nuclei -u xyz.com",
            corrected="nuclei -u xyz.com -t ~/custom-templates/",
            task="Scan xyz.com for web vulns",
            findings_before=2,
            findings_after=5,
        )
        # → emits LearningEvent with delta_findings=+3 and insight
    """

    def __init__(self, xi_predictor: Any = None, xi_context: Any = None) -> None:
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)

        self._patterns_path = _LEARNING_DIR / "tool_patterns.json"
        self._patterns: list[ToolPattern] = []
        self._anti_patterns: list[ToolPattern] = []
        self._recent_tools: list[str] = []
        self._session_start: float = time.time()
        self._tool_learning_enabled: bool = True
        self._correction_events: list[LearningEvent] = []

        self._predictor = xi_predictor
        self._context_tracker = xi_context
        self._ngram_index: dict[str, list[int]] = defaultdict(list)

        self._load()

    # ── Config ───────────────────────────────────────────────────────────

    @property
    def tool_learning_enabled(self) -> bool:
        return self._tool_learning_enabled

    def set_tool_learning(self, enabled: bool) -> None:
        self._tool_learning_enabled = enabled
        logger.info("Tool learning %s", "enabled" if enabled else "disabled")

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._patterns_path.exists():
            return
        try:
            with open(str(self._patterns_path)) as f:
                data = json.load(f)
            raw = data.get("patterns", [])
            self._patterns = [
                ToolPattern.from_dict(d) for d in raw if not d.get("is_anti_pattern")
            ]
            self._anti_patterns = [
                ToolPattern.from_dict(d) for d in raw if d.get("is_anti_pattern")
            ]
            self._rebuild_index()
        except Exception as exc:
            logger.warning("Failed to load learning patterns: %s", exc)

    def _save(self) -> None:
        try:
            combined = [p.to_dict() for p in self._patterns] + [
                p.to_dict() for p in self._anti_patterns
            ]
            with open(str(self._patterns_path), "w") as f:
                json.dump({"patterns": combined}, f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Failed to save learning patterns: %s", exc)

    def _rebuild_index(self) -> None:
        self._ngram_index.clear()
        for idx, p in enumerate(self._patterns):
            for token in p.ngram:
                self._ngram_index[token].append(idx)

    # ── Task Type Classification ─────────────────────────────────────────

    @staticmethod
    def classify_task(tools: list[str], command: str = "") -> str:
        """Classify a command into a task type."""
        combined = " ".join(tools).lower() + " " + command.lower()
        for task_type, keywords in _TASK_KEYWORDS.items():
            if any(kw in combined for kw in keywords):
                return task_type
        return "general"

    @staticmethod
    def extract_flags(command: str) -> list[str]:
        """Extract CLI flags from a command string."""
        return [p for p in command.split() if p.startswith("-")]

    @staticmethod
    def extract_platform() -> str:
        """Detect current platform."""
        sys = platform.system().lower()
        if sys == "linux":
            return "linux"
        if sys == "darwin":
            return "macos"
        if sys == "windows":
            return "windows"
        return sys

    # ── Timing Categories ────────────────────────────────────────────────

    @staticmethod
    def categorize_timing(duration_ms: float) -> str:
        sec = duration_ms / 1000.0
        if sec <= 0:
            return "unknown"
        if sec <= _FAST_THRESHOLD:
            return "fast"
        if sec >= _THOROUGH_THRESHOLD:
            return "thorough"
        return "balanced"

    # ── Core Recording ───────────────────────────────────────────────────

    def record(
        self,
        tools: list[str],
        duration_ms: float = 0.0,
        success: bool = True,
        findings_count: int = 0,
        phase: str = "",
        target: str = "",
        session_id: str = "",
        command: str = "",
        persona: str = "",
    ) -> None:
        """Record a tool execution pattern.

        This is the base recorder.  For correction-aware recording
        see :meth:`record_with_correction`.
        """
        if not self._tool_learning_enabled or not tools:
            return

        task_type = self.classify_task(tools, command)
        platform_name = self.extract_platform()
        flags = self.extract_flags(command)

        for order in range(1, min(len(tools), _MAX_NGRAM_ORDER) + 1):
            for i in range(len(tools) - order + 1):
                ngram = tools[i : i + order]
                tags = []
                if phase:
                    tags.append(f"phase:{phase}")
                if target:
                    tags.append(f"target:{target}")
                if session_id:
                    tags.append(f"session:{session_id}")

                if success:
                    self._upsert_pattern(
                        ngram,
                        duration_ms,
                        findings_count,
                        tags,
                        phase,
                        task_type,
                        platform_name,
                        flags,
                        persona,
                        command,
                        "",
                        0,
                        False,
                    )
                else:
                    self._upsert_pattern(
                        ngram,
                        duration_ms,
                        findings_count,
                        tags,
                        phase,
                        task_type,
                        platform_name,
                        flags,
                        persona,
                        command,
                        "",
                        0,
                        True,
                    )

        self._recent_tools.extend(tools)
        self._recent_tools = self._recent_tools[-50:]

        if self._predictor and hasattr(self._predictor, "learn"):
            for tool in tools:
                self._predictor.learn(tool)

        self._save()

    def record_with_correction(
        self,
        tools: list[str],
        original: str,
        corrected: str,
        task: str = "",
        findings_before: int = 0,
        findings_after: int = 0,
        duration_ms: float = 0.0,
        success: bool = True,
        phase: str = "",
        target: str = "",
        persona: str = "",
    ) -> LearningEvent | None:
        """Record a user correction to an AI-generated command (Chapter 10.1).

        Returns a LearningEvent with a natural-language insight message.
        """
        if not self._tool_learning_enabled or not tools:
            return None

        delta = findings_after - findings_before
        insight = self._generate_insight(tools, original, corrected, delta)

        # Record the corrected pattern
        self.record(
            tools=tools,
            duration_ms=duration_ms,
            success=success,
            findings_count=findings_after,
            phase=phase,
            target=target,
            command=corrected,
            persona=persona,
        )

        # Update the specific pattern with correction metadata
        key = "|".join(tools)
        for p in self._patterns:
            if "|".join(p.ngram) == key:
                p.original_command = original
                p.user_correction = corrected
                p.correction_findings_delta = delta
                p.correction_count += 1

                # Track which flags were added/removed
                orig_flags = set(self.extract_flags(original))
                corr_flags = set(self.extract_flags(corrected))
                added = corr_flags - orig_flags
                removed = orig_flags - corr_flags
                if delta > 0:
                    p.effective_flags.extend(added)
                elif delta < 0:
                    p.ineffective_flags.extend(added)
                p.effective_flags = list(set(p.effective_flags))
                p.ineffective_flags = list(set(p.ineffective_flags))
                break

        self._save()

        event = LearningEvent(
            task=task or f"{' -> '.join(tools)} scan",
            generated=original,
            user_modified=corrected,
            result=(
                f"{abs(delta)} {'more' if delta > 0 else 'fewer'} findings than default."
                if delta != 0
                else "No change in findings."
            ),
            insight=insight,
            delta_findings=delta,
        )
        self._correction_events.append(event)
        return event

    def _generate_insight(
        self, tools: list[str], original: str, corrected: str, delta: int
    ) -> str:
        """Generate a natural-language insight from a correction."""
        diff = list(
            difflib.unified_diff(original.split(), corrected.split(), lineterm="")
        )
        added = [w for w in corrected.split() if w not in original.split()]
        removed = [w for w in original.split() if w not in corrected.split()]

        tool_name = tools[0] if tools else "command"

        if delta > 2:
            return f"Custom flags {' '.join(added)} significantly improve {tool_name} results"
        if delta > 0:
            return f"Modified {tool_name} flags produced {delta} more findings"
        if delta < 0:
            return (
                f"Simpler {tool_name} command was sufficient — extra flags added noise"
            )
        return f"Alternative {tool_name} flags produce equivalent results"

    def _upsert_pattern(
        self,
        ngram: list[str],
        duration_ms: float,
        findings_count: int,
        tags: list[str],
        phase: str,
        task_type: str,
        platform_name: str,
        flags: list[str],
        persona: str,
        command: str,
        correction: str,
        correction_delta: int,
        is_anti: bool,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        key = "|".join(ngram)
        pattern_list = self._anti_patterns if is_anti else self._patterns

        for p in pattern_list:
            if "|".join(p.ngram) == key:
                p.count += 1
                if not is_anti:
                    p.success_count += 1
                p.last_used = now
                p.total_duration_ms += duration_ms
                p.total_findings += findings_count
                p.task_type = p.task_type or task_type
                p.persona = p.persona or persona
                p.platform = p.platform or platform_name
                for t in tags:
                    if t not in p.context_tags:
                        p.context_tags.append(t)
                if phase and not p.phase:
                    p.phase = phase
                if command and not p.original_command:
                    p.original_command = command
                return

        new_pattern = ToolPattern(
            ngram=ngram,
            task_type=task_type,
            persona=persona,
            platform=platform_name,
            count=1,
            success_count=0 if is_anti else 1,
            last_used=now,
            total_duration_ms=duration_ms,
            total_findings=findings_count,
            context_tags=tags[:10],
            phase=phase,
            is_anti_pattern=is_anti,
            original_command=command,
            user_correction=correction,
            correction_findings_delta=correction_delta,
        )
        pattern_list.append(new_pattern)

        if not is_anti:
            for token in ngram:
                self._ngram_index[token].append(len(self._patterns) - 1)

        if len(self._patterns) > 500:
            self._prune_patterns()

    def _prune_patterns(self) -> None:
        self._patterns.sort(key=lambda p: p.confidence * p.count, reverse=True)
        self._patterns = self._patterns[:500]
        self._rebuild_index()

    # ── Suggestions ──────────────────────────────────────────────────────

    def suggest(
        self,
        current_tool: str,
        phase: str = "",
        target: str = "",
        max_suggestions: int = 5,
        min_confidence: float = 0.15,
    ) -> list[dict]:
        """Suggest next tools with context weighting."""
        now = time.time()
        scored: dict[str, dict] = {}

        for p in self._patterns:
            p.apply_decay(now)

        candidate_indices = self._ngram_index.get(current_tool, [])
        for idx in candidate_indices:
            p = self._patterns[idx]
            tool_positions = [i for i, t in enumerate(p.ngram) if t == current_tool]
            for pos in tool_positions:
                if pos + 1 < len(p.ngram):
                    next_tool = p.ngram[pos + 1]
                    base_conf = p.confidence * p.decay_score

                    context_boost = 1.0
                    if phase and f"phase:{phase}" in p.context_tags:
                        context_boost *= 1.5
                    if target and any("target:" in t for t in p.context_tags):
                        context_boost *= 1.2

                    session_boost = 1.0
                    if next_tool in self._recent_tools:
                        recency = self._recent_tools[::-1].index(next_tool)
                        session_boost = max(1.0, 2.0 - recency * 0.1)
                    if current_tool in self._recent_tools:
                        session_boost *= 1.3

                    efficiency = (
                        1.0 + (1.0 - min(p.avg_duration_ms / 300000.0, 1.0)) * 0.5
                    )
                    final_confidence = (
                        base_conf * context_boost * session_boost * efficiency
                    )

                    if final_confidence < min_confidence:
                        continue

                    if (
                        next_tool not in scored
                        or final_confidence > scored[next_tool]["confidence"]
                    ):
                        scored[next_tool] = {
                            "tool": next_tool,
                            "confidence": round(min(final_confidence, 1.0), 4),
                            "reason": f"Learned from {p.count} uses",
                            "task_type": p.task_type,
                            "success_rate": round(p.success_rate, 2),
                            "timing": p.timing_category,
                            "has_correction": p.has_correction,
                        }

        warnings = self._check_anti_patterns(current_tool)
        result = sorted(scored.values(), key=lambda x: x["confidence"], reverse=True)[
            :max_suggestions
        ]
        result.extend(warnings)
        return result

    def _check_anti_patterns(self, tool: str) -> list[dict]:
        warnings = []
        for ap in self._anti_patterns:
            if tool in ap.ngram and ap.count >= 2:
                warnings.append(
                    {
                        "tool": f"⚠ {tool}",
                        "confidence": round(ap.confidence, 4),
                        "reason": f"Anti-pattern: {'→'.join(ap.ngram)} failed {ap.count - ap.success_count}/{ap.count}",
                        "success_rate": round(ap.success_rate, 2),
                        "warning": True,
                    }
                )
        return warnings

    def suggest_for_task_type(
        self, task_type: str, max_suggestions: int = 5
    ) -> list[dict]:
        """Suggest tools optimized for a specific task type."""
        now = time.time()
        scored: dict[str, dict] = {}
        for p in self._patterns:
            if p.task_type != task_type:
                continue
            p.apply_decay(now)
            for tool in p.ngram:
                if (
                    tool not in scored
                    or p.confidence * p.decay_score > scored[tool]["confidence"]
                ):
                    scored[tool] = {
                        "tool": tool,
                        "confidence": round(p.confidence * p.decay_score, 4),
                        "reason": f"Best for '{task_type}' ({p.count} uses)",
                        "task_type": task_type,
                        "timing": p.timing_category,
                        "platform": p.platform,
                    }
        return sorted(scored.values(), key=lambda x: x["confidence"], reverse=True)[
            :max_suggestions
        ]

    def suggest_platform_optimizations(self, platform_name: str = "") -> list[dict]:
        """Suggest platform-specific optimizations."""
        platform_name = platform_name or self.extract_platform()
        optimizations = []
        for p in self._patterns:
            if p.platform == platform_name and p.has_correction:
                if p.effective_flags:
                    flag_str = " ".join(p.effective_flags[:3])
                    optimizations.append(
                        {
                            "tool": " -> ".join(p.ngram),
                            "optimization": f"Use flags {flag_str} on {platform_name}",
                            "findings_improvement": f"+{p.correction_findings_delta} findings",
                            "confidence": round(p.confidence, 2),
                        }
                    )
        return sorted(optimizations, key=lambda x: x["confidence"], reverse=True)[:10]

    # ── Analytics ────────────────────────────────────────────────────────

    def top_patterns(self, n: int = 10, min_count: int = 1) -> list[ToolPattern]:
        now = time.time()
        for p in self._patterns:
            p.apply_decay(now)
        filtered = [p for p in self._patterns if p.count >= min_count]
        filtered.sort(key=lambda p: p.confidence * p.count, reverse=True)
        return filtered[:n]

    def top_anti_patterns(self, n: int = 5) -> list[ToolPattern]:
        self._anti_patterns.sort(key=lambda p: p.count, reverse=True)
        return self._anti_patterns[:n]

    def corrections(self, n: int = 10) -> list[ToolPattern]:
        """Return patterns with the most user corrections."""
        with_corrections = [p for p in self._patterns if p.has_correction]
        with_corrections.sort(key=lambda p: p.correction_count, reverse=True)
        return with_corrections[:n]

    def platform_insights(self) -> list[dict]:
        """Return per-platform optimization insights."""
        by_platform: dict[str, dict] = {}
        for p in self._patterns:
            plat = p.platform or "unknown"
            if plat not in by_platform:
                by_platform[plat] = {
                    "patterns": 0,
                    "corrections": 0,
                    "total_findings": 0,
                }
            by_platform[plat]["patterns"] += 1
            by_platform[plat]["corrections"] += p.correction_count
            by_platform[plat]["total_findings"] += p.total_findings
        return [{"platform": k, **v} for k, v in by_platform.items()]

    def flag_effectiveness_report(self) -> list[dict]:
        """Return per-tool flag effectiveness analysis."""
        report: dict[str, dict] = {}
        for p in self._patterns:
            tool = p.ngram[0] if p.ngram else "unknown"
            if tool not in report:
                report[tool] = {"effective": set(), "ineffective": set()}
            report[tool]["effective"].update(p.effective_flags)
            report[tool]["ineffective"].update(p.ineffective_flags)
        return [
            {
                "tool": tool,
                "effective_flags": sorted(v["effective"]),
                "ineffective_flags": sorted(v["ineffective"]),
                "score": round(
                    len(v["effective"])
                    / max(len(v["effective"]) + len(v["ineffective"]), 1),
                    2,
                ),
            }
            for tool, v in sorted(report.items())
        ]

    def timing_distribution(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for p in self._patterns:
            cat = p.timing_category
            dist[cat] = dist.get(cat, 0) + 1
        return dist

    def task_type_summary(self) -> dict[str, dict]:
        summary: dict[str, dict] = {}
        for p in self._patterns:
            tt = p.task_type or "general"
            if tt not in summary:
                summary[tt] = {"patterns": 0, "total_findings": 0, "corrections": 0}
            summary[tt]["patterns"] += 1
            summary[tt]["total_findings"] += p.total_findings
            summary[tt]["corrections"] += p.correction_count
        return summary

    def most_learned_tools(self, n: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for p in self._patterns:
            for tool in p.ngram:
                counts[tool] = counts.get(tool, 0) + p.count
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def phase_distribution(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for p in self._patterns:
            ph = p.phase or "unknown"
            dist[ph] = dist.get(ph, 0) + 1
        return dist

    def pattern_network(self) -> dict[str, list[tuple[str, float]]]:
        graph: dict[str, dict[str, float]] = {}
        for p in self._patterns:
            for i in range(len(p.ngram) - 1):
                src, dst = p.ngram[i], p.ngram[i + 1]
                if src not in graph:
                    graph[src] = {}
                graph[src][dst] = graph[src].get(dst, 0) + p.count * p.confidence
        return {
            src: sorted(dst.items(), key=lambda x: x[1], reverse=True)[:5]
            for src, dst in graph.items()
        }

    @property
    def recent_correction_events(self) -> list[LearningEvent]:
        return list(self._correction_events[-20:])

    @property
    def summary(self) -> dict:
        return {
            "total_patterns": len(self._patterns),
            "total_anti_patterns": len(self._anti_patterns),
            "unique_tools": len(self.most_learned_tools(100)),
            "task_types": list(self.task_type_summary().keys()),
            "phase_coverage": self.phase_distribution(),
            "timing": self.timing_distribution(),
            "corrections_recorded": sum(p.correction_count for p in self._patterns),
            "platforms": self.platform_insights(),
        }

    @property
    def total_records(self) -> int:
        return len(self._patterns)

    # ── Session Management ───────────────────────────────────────────────

    def start_session(self) -> None:
        self._session_start = time.time()
        self._recent_tools.clear()

    def end_session(self) -> list[ToolPattern]:
        self._save()
        return self._patterns

    # ── Export / Import ──────────────────────────────────────────────────

    def export_patterns(self, filepath: str | Path | None = None) -> dict:
        data = {
            "version": 3,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "pattern_count": len(self._patterns),
            "patterns": [p.to_dict() for p in self._patterns],
        }
        if filepath:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(str(path), "w") as f:
                json.dump(data, f, indent=2, default=str)
        return data

    def import_patterns(self, source: str | Path | dict, merge: bool = True) -> int:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                return 0
            with open(str(path)) as f:
                data = json.load(f)
        else:
            data = source
        raw = data.get("patterns", [])
        imported = 0
        for item in raw:
            pattern = ToolPattern.from_dict(item)
            if not pattern.ngram:
                continue
            if merge and not pattern.is_anti_pattern:
                self._upsert_pattern(
                    pattern.ngram,
                    pattern.total_duration_ms,
                    int(pattern.avg_findings),
                    pattern.context_tags,
                    pattern.phase,
                    pattern.task_type,
                    pattern.platform,
                    [],
                    pattern.persona,
                    pattern.original_command,
                    pattern.user_correction,
                    pattern.correction_findings_delta,
                    False,
                )
            else:
                (
                    self._anti_patterns if pattern.is_anti_pattern else self._patterns
                ).append(pattern)
            imported += 1
        self._rebuild_index()
        self._save()
        return imported

    def clear(self) -> None:
        self._patterns.clear()
        self._anti_patterns.clear()
        self._ngram_index.clear()
        self._recent_tools.clear()
        self._correction_events.clear()
        self._save()

    def reset(self) -> None:
        self.clear()


__all__ = [
    "LearningMemory",
    "ToolPattern",
    "LearningEvent",
]
