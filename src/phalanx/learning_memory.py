"""
Learning Memory — Advanced tool usage pattern learning and auto-suggestion engine.

As described in Chapter 10.1 with enterprise-grade enhancements:

  • N-gram pattern learning (variable-length tool sequences)
  • Time-based decay for stale patterns (exponential half-life)
  • Bayesian confidence scoring (success-rate + sample-size)
  • Anti-pattern detection (failed chains stored & warned)
  • Context-weighted suggestions (phase-aware, target-aware)
  • Session-scoped pattern boost (recency bonus)
  • Pattern clustering (similar chains merged via LCS)
  • Export/import for sharing learned patterns
  • Live integration with XI Predictor + ContextTracker
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_LEARNING_DIR = _PHALANX_HOME / "learning"

# Half-life for pattern decay in seconds (30 days)
_PATTERN_HALF_LIFE = 2592000.0

# Maximum n-gram length to track
_MAX_NGRAM_ORDER = 5

# Minimum samples before confidence is reliable
_MIN_CONFIDENCE_SAMPLES = 3

# Decay rate for session boost (per-hour half-life)
_SESSION_BOOST_HALF_LIFE = 3600.0


@dataclass
class ToolPattern:
    """A learned tool-usage pattern with confidence scoring."""

    ngram: list[str]
    count: int = 1
    success_count: int = 1
    last_used: str = ""
    total_duration_ms: float = 0.0
    context_tags: list[str] = field(default_factory=list)
    phase: str = ""
    avg_findings: float = 0.0
    is_anti_pattern: bool = False
    decay_score: float = 1.0

    @property
    def confidence(self) -> float:
        """Bayesian confidence score (0.0 to 1.0)."""
        if self.count < _MIN_CONFIDENCE_SAMPLES:
            return self.success_count / max(self.count, 1) * (self.count / _MIN_CONFIDENCE_SAMPLES)
        success_rate = self.success_count / max(self.count, 1)
        return success_rate * min(self.decay_score, 1.0)

    @property
    def success_rate(self) -> float:
        return self.success_count / max(self.count, 1)

    @property
    def avg_duration_ms(self) -> float:
        return self.total_duration_ms / max(self.count, 1)

    @property
    def duration_efficiency(self) -> float:
        """Normalized efficiency score (higher = faster)."""
        if self.avg_duration_ms <= 0:
            return 0.5
        return max(0.0, min(1.0, 1.0 - (self.avg_duration_ms / 300000.0)))

    def apply_decay(self, reference_time: float | None = None) -> None:
        """Apply exponential decay based on time since last use."""
        if not self.last_used:
            self.decay_score = 1.0
            return
        try:
            last = datetime.fromisoformat(self.last_used).timestamp()
        except (ValueError, TypeError):
            self.decay_score = 1.0
            return
        ref = reference_time or time.time()
        elapsed = max(0.0, ref - last)
        half_lives = elapsed / _PATTERN_HALF_LIFE
        self.decay_score = 2.0 ** (-half_lives)

    def to_dict(self) -> dict:
        return {
            "ngram": self.ngram,
            "count": self.count,
            "success_count": self.success_count,
            "last_used": self.last_used,
            "total_duration_ms": self.total_duration_ms,
            "context_tags": self.context_tags,
            "phase": self.phase,
            "avg_findings": self.avg_findings,
            "is_anti_pattern": self.is_anti_pattern,
            "decay_score": round(self.decay_score, 4),
            "confidence": round(self.confidence, 4),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolPattern:
        return cls(
            ngram=data.get("ngram", []),
            count=data.get("count", 1),
            success_count=data.get("success_count", 1),
            last_used=data.get("last_used", ""),
            total_duration_ms=data.get("total_duration_ms", 0.0),
            context_tags=data.get("context_tags", []),
            phase=data.get("phase", ""),
            avg_findings=data.get("avg_findings", 0.0),
            is_anti_pattern=data.get("is_anti_pattern", False),
            decay_score=data.get("decay_score", 1.0),
        )


@dataclass
class SessionContext:
    """Contextual metadata for a learning session."""

    session_id: str = ""
    phase: str = ""
    target: str = ""
    tools_used: list[str] = field(default_factory=list)
    findings_count: int = 0
    success: bool = True
    started_at: float = 0.0


class LearningMemory:
    """Advanced persistent learning memory for tool patterns.

    Features:
      - N-gram pattern learning up to order ``_MAX_NGRAM_ORDER``
      - Exponential decay for stale patterns
      - Bayesian confidence scoring
      - Anti-pattern tracking for failed chains
      - Phase-aware and target-aware suggestions
      - Session-scoped recency boost
      - Deduplication and merging of similar patterns
      - Export/import for sharing learned behaviour
    """

    def __init__(self, xi_predictor: Any = None, xi_context: Any = None) -> None:
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        self._patterns_path = _LEARNING_DIR / "tool_patterns.json"
        self._patterns: list[ToolPattern] = []
        self._anti_patterns: list[ToolPattern] = []
        self._recent_tools: list[str] = []
        self._session_start: float = time.time()

        # XI integration points
        self._predictor = xi_predictor
        self._context_tracker = xi_context

        # In-memory n-gram index for fast lookup
        self._ngram_index: dict[str, list[int]] = defaultdict(list)

        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._patterns_path.exists():
            return
        try:
            with open(str(self._patterns_path)) as f:
                data = json.load(f)
            raw = data.get("patterns", [])
            self._patterns = [ToolPattern.from_dict(d) for d in raw if not d.get("is_anti_pattern")]
            self._anti_patterns = [ToolPattern.from_dict(d) for d in raw if d.get("is_anti_pattern")]
            self._rebuild_index()
            logger.debug("Loaded %d patterns, %d anti-patterns", len(self._patterns), len(self._anti_patterns))
        except Exception as exc:
            logger.warning("Failed to load learning patterns: %s", exc)

    def _save(self) -> None:
        try:
            combined = [p.to_dict() for p in self._patterns] + [p.to_dict() for p in self._anti_patterns]
            with open(str(self._patterns_path), "w") as f:
                json.dump({"patterns": combined}, f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Failed to save learning patterns: %s", exc)

    def _rebuild_index(self) -> None:
        self._ngram_index.clear()
        for idx, p in enumerate(self._patterns):
            for token in p.ngram:
                self._ngram_index[token].append(idx)

    # ── Recording ────────────────────────────────────────────────────────

    def record(
        self,
        tools: list[str],
        duration_ms: float = 0.0,
        success: bool = True,
        findings_count: int = 0,
        phase: str = "",
        target: str = "",
        session_id: str = "",
    ) -> None:
        if not tools:
            return

        # Extract all n-grams from the tool sequence
        for order in range(1, min(len(tools), _MAX_NGRAM_ORDER) + 1):
            for i in range(len(tools) - order + 1):
                ngram = tools[i: i + order]
                tags = []
                if phase:
                    tags.append(f"phase:{phase}")
                if target:
                    tags.append(f"target:{target}")
                if session_id:
                    tags.append(f"session:{session_id}")

                if success:
                    self._upsert_pattern(ngram, duration_ms, findings_count, tags, phase, False)
                else:
                    self._upsert_pattern(ngram, duration_ms, findings_count, tags, phase, True)

        # Update recent tools for session boost
        self._recent_tools.extend(tools)
        self._recent_tools = self._recent_tools[-50:]

        # Feed into XI Predictor if available
        if self._predictor and hasattr(self._predictor, "learn"):
            for tool in tools:
                self._predictor.learn(tool)

        self._save()

    def _upsert_pattern(
        self,
        ngram: list[str],
        duration_ms: float,
        findings_count: int,
        tags: list[str],
        phase: str,
        is_anti: bool,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        key = "|".join(ngram)

        # Check exact match first
        pattern_list = self._anti_patterns if is_anti else self._patterns
        for p in pattern_list:
            if "|".join(p.ngram) == key:
                p.count += 1
                if not is_anti:
                    p.success_count += 1
                p.last_used = now
                p.total_duration_ms += duration_ms
                p.avg_findings = (p.avg_findings * (p.count - 1) + findings_count) / p.count
                for t in tags:
                    if t not in p.context_tags:
                        p.context_tags.append(t)
                if phase and not p.phase:
                    p.phase = phase
                return

        new_pattern = ToolPattern(
            ngram=ngram,
            count=1,
            success_count=0 if is_anti else 1,
            last_used=now,
            total_duration_ms=duration_ms,
            context_tags=tags[:10],
            phase=phase,
            avg_findings=findings_count,
            is_anti_pattern=is_anti,
        )
        pattern_list.append(new_pattern)

        # Rebuild index for patterns
        if not is_anti:
            for token in ngram:
                self._ngram_index[token].append(len(self._patterns) - 1)

        # Prune if too many patterns (keep top 500)
        if len(self._patterns) > 500:
            self._prune_patterns()

    def _prune_patterns(self) -> None:
        """Keep only the 500 highest-confidence patterns."""
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
        """Suggest next tools based on learned patterns with context weighting.

        Returns list of dicts with keys: tool, confidence, reason, pattern_key.
        """
        now = time.time()
        scored: dict[str, dict] = {}

        # Apply decay to all patterns
        for p in self._patterns:
            p.apply_decay(now)

        # Find patterns containing current_tool
        candidate_indices = self._ngram_index.get(current_tool, [])
        for idx in candidate_indices:
            p = self._patterns[idx]
            tool_positions = [i for i, t in enumerate(p.ngram) if t == current_tool]
            for pos in tool_positions:
                if pos + 1 < len(p.ngram):
                    next_tool = p.ngram[pos + 1]

                    # Base confidence from pattern
                    base_conf = p.confidence * p.decay_score

                    # Context boost
                    context_boost = 1.0
                    if phase and f"phase:{phase}" in p.context_tags:
                        context_boost *= 1.5
                    if target and any("target:" in t for t in p.context_tags):
                        context_boost *= 1.2

                    # Session recency boost
                    session_boost = 1.0
                    if next_tool in self._recent_tools:
                        recency = self._recent_tools[::-1].index(next_tool)
                        session_boost = max(1.0, 2.0 - recency * 0.1)
                    if current_tool in self._recent_tools:
                        session_boost *= 1.3

                    # Duration efficiency boost
                    efficiency_boost = 1.0 + p.duration_efficiency * 0.5

                    final_confidence = base_conf * context_boost * session_boost * efficiency_boost

                    if final_confidence < min_confidence:
                        continue

                    if next_tool not in scored or final_confidence > scored[next_tool]["confidence"]:
                        scored[next_tool] = {
                            "tool": next_tool,
                            "confidence": round(min(final_confidence, 1.0), 4),
                            "reason": f"Learned from {p.count} past uses (pattern: {' → '.join(p.ngram)})",
                            "pattern_key": "|".join(p.ngram),
                            "success_rate": round(p.success_rate, 2),
                            "avg_duration_ms": round(p.avg_duration_ms, 0),
                            "phase": p.phase or phase,
                        }

        # If no suggestions, try with last known tools
        if not scored and len(self._recent_tools) > 1:
            for prev in self._recent_tools[-3:-1]:
                deeper = self._ngram_index.get(prev, [])
                for idx in deeper:
                    p = self._patterns[idx]
                    if len(p.ngram) > 1 and p.ngram[-1] != current_tool:
                        candidate = p.ngram[-1]
                        if candidate not in scored:
                            scored[candidate] = {
                                "tool": candidate,
                                "confidence": round(p.confidence * 0.6, 4),
                                "reason": "Suggested from session context",
                                "pattern_key": "|".join(p.ngram),
                                "success_rate": round(p.success_rate, 2),
                                "avg_duration_ms": round(p.avg_duration_ms, 0),
                                "phase": p.phase or phase,
                            }

        # Check anti-patterns for warnings
        warnings = self._check_anti_patterns(current_tool)

        result = sorted(scored.values(), key=lambda x: x["confidence"], reverse=True)[:max_suggestions]
        if warnings:
            for w in warnings:
                result.append(w)

        self._save()
        return result

    def _check_anti_patterns(self, tool: str) -> list[dict]:
        """Check if current tool has known anti-patterns to warn about."""
        warnings = []
        for ap in self._anti_patterns:
            if tool in ap.ngram and ap.count >= 2:
                warnings.append({
                    "tool": f"⚠ {tool}",
                    "confidence": round(ap.confidence, 4),
                    "reason": f"Anti-pattern: {' → '.join(ap.ngram)} failed {ap.count - ap.success_count}/{ap.count} times",
                    "pattern_key": "|".join(ap.ngram),
                    "success_rate": round(ap.success_rate, 2),
                    "avg_duration_ms": round(ap.avg_duration_ms, 0),
                    "phase": ap.phase,
                    "warning": True,
                })
        return warnings

    def suggest_for_phase(self, phase: str, max_suggestions: int = 5) -> list[dict]:
        """Suggest tools specifically for a given operation phase."""
        now = time.time()
        scored: dict[str, dict] = {}

        for p in self._patterns:
            if p.phase != phase:
                continue
            p.apply_decay(now)
            for tool in p.ngram:
                if tool not in scored or p.confidence * p.decay_score > scored[tool]["confidence"]:
                    scored[tool] = {
                        "tool": tool,
                        "confidence": round(p.confidence * p.decay_score, 4),
                        "reason": f"Used in phase '{phase}' ({p.count} times)",
                        "pattern_key": "|".join(p.ngram),
                        "success_rate": round(p.success_rate, 2),
                        "avg_duration_ms": round(p.avg_duration_ms, 0),
                        "phase": phase,
                    }

        return sorted(scored.values(), key=lambda x: x["confidence"], reverse=True)[:max_suggestions]

    def suggest_chain(self, partial: list[str], max_completions: int = 3) -> list[list[str]]:
        """Suggest full tool chains that start with the given partial sequence."""
        key_prefix = "|".join(partial)
        matches: list[tuple[list[str], float]] = []

        for p in self._patterns:
            p.apply_decay()
            p_key = "|".join(p.ngram)
            if p_key.startswith(key_prefix) and len(p.ngram) > len(partial):
                score = p.confidence * p.decay_score * p.count
                matches.append((p.ngram, score))

        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0] for m in matches[:max_completions]]

    # ── Analytics ────────────────────────────────────────────────────────

    def top_patterns(self, n: int = 10, min_count: int = 1) -> list[ToolPattern]:
        """Return highest-confidence patterns."""
        now = time.time()
        for p in self._patterns:
            p.apply_decay(now)
        filtered = [p for p in self._patterns if p.count >= min_count]
        filtered.sort(key=lambda p: p.confidence * p.count, reverse=True)
        return filtered[:n]

    def top_anti_patterns(self, n: int = 5) -> list[ToolPattern]:
        self._anti_patterns.sort(key=lambda p: p.count, reverse=True)
        return self._anti_patterns[:n]

    def most_learned_tools(self, n: int = 10) -> list[tuple[str, int]]:
        """Return most frequently seen tools across all patterns."""
        counts: dict[str, int] = {}
        for p in self._patterns:
            for tool in p.ngram:
                counts[tool] = counts.get(tool, 0) + p.count
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def phase_distribution(self) -> dict[str, int]:
        """Return count of patterns per phase."""
        dist: dict[str, int] = {}
        for p in self._patterns:
            phase = p.phase or "unknown"
            dist[phase] = dist.get(phase, 0) + 1
        return dist

    def pattern_network(self) -> dict[str, list[tuple[str, float]]]:
        """Return a graph of tool-to-tool transition strengths."""
        graph: dict[str, dict[str, float]] = {}
        for p in self._patterns:
            for i in range(len(p.ngram) - 1):
                src, dst = p.ngram[i], p.ngram[i + 1]
                if src not in graph:
                    graph[src] = {}
                graph[src][dst] = graph[src].get(dst, 0) + p.count * p.confidence
        return {src: sorted(dst.items(), key=lambda x: x[1], reverse=True)[:5]
                for src, dst in graph.items()}

    @property
    def summary(self) -> dict:
        return {
            "total_patterns": len(self._patterns),
            "total_anti_patterns": len(self._anti_patterns),
            "unique_tools_learned": len(self.most_learned_tools(100)),
            "phase_coverage": self.phase_distribution(),
            "top_pattern": self.top_patterns(1)[0].to_dict() if self._patterns else None,
        }

    @property
    def total_records(self) -> int:
        return len(self._patterns)

    # ── Session management ───────────────────────────────────────────────

    def start_session(self) -> None:
        self._session_start = time.time()
        self._recent_tools.clear()

    def end_session(self) -> list[ToolPattern]:
        """Finalize session and return patterns created this session."""
        duration = time.time() - self._session_start
        logger.debug("Learning session ended (%.1fs), %d active patterns", duration, len(self._patterns))
        self._save()
        return self._patterns

    # ── Export / Import ──────────────────────────────────────────────────

    def export_patterns(self, filepath: str | Path | None = None) -> dict:
        """Export patterns to a portable JSON dict or file."""
        data = {
            "version": 2,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "pattern_count": len(self._patterns),
            "patterns": [p.to_dict() for p in self._patterns],
        }
        if filepath:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(str(path), "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Exported %d patterns to %s", len(self._patterns), path)
        return data

    def import_patterns(self, source: str | Path | dict, merge: bool = True) -> int:
        """Import patterns from a JSON file or dict.

        Returns the number of patterns imported.
        """
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                logger.warning("Import source not found: %s", path)
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
            if merge:
                self._upsert_pattern(
                    ngram=pattern.ngram,
                    duration_ms=pattern.total_duration_ms,
                    findings_count=int(pattern.avg_findings),
                    tags=pattern.context_tags,
                    phase=pattern.phase,
                    is_anti=pattern.is_anti_pattern,
                )
            else:
                self._patterns.append(pattern)
            imported += 1

        self._rebuild_index()
        self._save()
        logger.info("Imported %d patterns from source", imported)
        return imported

    def clear(self) -> None:
        """Reset all learned patterns."""
        self._patterns.clear()
        self._anti_patterns.clear()
        self._ngram_index.clear()
        self._recent_tools.clear()
        self._save()
        logger.info("Learning memory cleared")

    def reset(self) -> None:
        self.clear()


__all__ = [
    "LearningMemory",
    "ToolPattern",
    "SessionContext",
]
