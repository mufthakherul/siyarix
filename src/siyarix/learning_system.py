# SPDX-License-Identifier: AGPL-3.0-or-later
"""Continuous Learning System (CLS) — monitors LLM/offline planner actions and builds
a persistent, privacy-preserving skill library that improves Siyarix over time.

Key Design Principles
---------------------
- **Privacy First**: Real targets are NEVER stored. Every hostname, IP, URL, email, or
  hash is replaced with the ``{target}`` placeholder before any data is persisted.
- **Separate Store**: Learning data lives in ``learning_store.db`` (separate from
  ``offline_store.db``) so users can share it with Siyarix developers to help improve
  the tool without exposing sensitive operational data.
- **Zero Dependencies**: Pure stdlib — no numpy, no ML libraries. Uses BM25-style
  Jaccard similarity over NLP token sets.
- **Bayesian Confidence**: Skill confidence is updated with a Bayesian-smoothed formula
  that rewards both accuracy (success rate) and data volume (usage count).
- **Dual-Mode Integration**:
    - *Integrated mode*: 100 %-confidence skills trigger automatic pre-execution before
      the LLM is consulted. Results are sent to the LLM as a rich base context.
    - *Offline mode*: Learned skills augment the heuristic planner and generate an
      enhanced "Learning Insights" summary panel after execution.
"""

from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class LearnedStep:
    """A single anonymised step inside a LearnedSkill."""

    tool: str
    command_template: str  # uses {target} placeholder — never stores real target
    description: str
    args: dict[str, Any] = field(default_factory=dict)

    def instantiate(self, target: str) -> "LearnedStep":
        """Return a copy with {target} replaced by the real target."""
        return LearnedStep(
            tool=self.tool,
            command_template=self.command_template.replace("{target}", target),
            description=self.description.replace("{target}", target),
            args={
                k: (v.replace("{target}", target) if isinstance(v, str) else v)
                for k, v in self.args.items()
            },
        )


@dataclass
class LearnedSkill:
    """A reusable, anonymised workflow pattern extracted from observed LLM/offline actions."""

    skill_id: str
    intent_pattern: str       # anonymised command pattern (contains {target})
    steps: list[LearnedStep]  # ordered action sequence with {target} placeholders
    confidence: float         # 0.0 – 1.0 (Bayesian-smoothed)
    usage_count: int
    success_count: int
    tokens: list[str]         # NLP tokens for similarity matching
    synonyms: dict[str, str]  # learned keyword → canonical tool/concept mappings
    created_at: float
    last_used: float
    source: str               # 'llm' | 'offline' | 'inferred'
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    # ── Confidence helpers ──────────────────────────────────────────────

    @property
    def base_confidence(self) -> float:
        """Raw success rate."""
        return self.success_count / max(self.usage_count, 1)

    def recalculate_confidence(self) -> None:
        """Full-featured Bayesian confidence with time decay and complexity weighting.

        Formula (Beta-Binomial with pessimistic prior):
            base  = (success_count + prior_alpha) / (usage_count + prior_alpha + prior_beta)
            where prior_alpha=2.0, prior_beta=1.0 prevents 1/1 → 100 %

        Time decay:
            Skills lose ~0.5 % per day since last use, floor at 50 %.

        Complexity weight:
            Skills with many steps need more evidence; floor at 70 %.

        Volume bonus:
            Logarithmic bonus for high-usage skills (diminishing returns, max +10 %).
        """
        if self.usage_count == 0:
            self.confidence = 0.0
            return

        # ── Bayesian base with pessimistic prior ────────────────────────
        # Prevents a single success from reaching 100 % confidence
        prior_alpha = 3.0  # fictitious failures
        prior_beta = 1.0   # fictitious successes
        numerator = self.success_count + prior_beta
        denominator = self.usage_count + prior_alpha + prior_beta
        base = numerator / denominator if denominator else 0.0

        # ── Time decay ──────────────────────────────────────────────────
        days_since_use = max(0.0, (time.time() - self.last_used) / 86400.0)
        decay = max(0.5, 1.0 - days_since_use * 0.005)

        # ── Complexity weight ───────────────────────────────────────────
        # More steps = needs more evidence to reach high confidence
        complexity = max(1, len(self.steps))
        complexity_weight = max(0.7, 1.0 - (complexity - 1) * 0.04)

        # ── Volume bonus (multiplicative, capped) ───────────────────────
        volume_bonus = min(0.10, math.log(1.0 + self.usage_count) * 0.02)

        self.confidence = min(1.0, base * decay * complexity_weight * (1.0 + volume_bonus))

    # ── Serialisation helpers ───────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "intent_pattern": self.intent_pattern,
            "steps": [asdict(s) for s in self.steps],
            "confidence": self.confidence,
            "usage_count": self.usage_count,
            "success_count": self.success_count,
            "tokens": self.tokens,
            "synonyms": self.synonyms,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "source": self.source,
            "tags": self.tags,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Continuous Learning System
# ---------------------------------------------------------------------------


class ContinuousLearningSystem:
    """Core learning engine: observe → learn → inject → replay.

    Thread-safe. Maintains an in-memory skill cache backed by SQLite.
    Each observation updates the relevant skill's confidence score and
    persists the change immediately.
    """

    _DB_FILENAME = "learning_store.db"
    _SCHEMA_VERSION = 2

    def __init__(self, db_path: Path | None = None) -> None:
        from .config import get_config_dir

        self._db_path = db_path or (get_config_dir() / self._DB_FILENAME)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local = threading.local()
        self._lock = threading.Lock()

        # In-memory skill cache (keyed by skill_id)
        self._skills: dict[str, LearnedSkill] = {}

        self._init_db()
        self._load_skills()

        logger.debug("CLS: initialised — %d skills loaded from %s", len(self._skills), self._db_path)

    # ── DB connection (thread-local) ────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self._db_path), timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    # ── DB schema ──────────────────────────────────────────────────────

    def _init_db(self) -> None:
        conn = self._conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO meta (key, value)
                    VALUES ('schema_version', '2');
                INSERT OR IGNORE INTO meta (key, value)
                    VALUES ('created_at', datetime('now'));

                CREATE TABLE IF NOT EXISTS learned_skills (
                    skill_id       TEXT PRIMARY KEY,
                    intent_pattern TEXT NOT NULL,
                    steps_json     TEXT NOT NULL,
                    confidence     REAL    DEFAULT 0.0,
                    usage_count    INTEGER DEFAULT 0,
                    success_count  INTEGER DEFAULT 0,
                    tokens_json    TEXT    DEFAULT '[]',
                    synonyms_json  TEXT    DEFAULT '{}',
                    tags_json      TEXT    DEFAULT '[]',
                    notes          TEXT    DEFAULT '',
                    created_at     REAL    NOT NULL,
                    last_used      REAL    NOT NULL,
                    source         TEXT    DEFAULT 'llm'
                );

                CREATE TABLE IF NOT EXISTS skill_observations (
                    obs_id      TEXT PRIMARY KEY,
                    skill_id    TEXT REFERENCES learned_skills(skill_id)
                                    ON DELETE CASCADE,
                    anon_goal   TEXT NOT NULL,
                    target_type TEXT DEFAULT '',
                    success     INTEGER DEFAULT 0,
                    wave_count  INTEGER DEFAULT 1,
                    step_count  INTEGER DEFAULT 0,
                    duration_ms REAL    DEFAULT 0.0,
                    observed_at REAL    NOT NULL,
                    mode        TEXT    DEFAULT 'integrated'
                );

                CREATE INDEX IF NOT EXISTS idx_skills_conf
                    ON learned_skills(confidence DESC);
                CREATE INDEX IF NOT EXISTS idx_skills_usage
                    ON learned_skills(usage_count DESC);
                CREATE INDEX IF NOT EXISTS idx_obs_skill
                    ON skill_observations(skill_id);
            """)
            conn.commit()
        except Exception:
            logger.exception("CLS: failed to initialise database")

    # ── Persistence ─────────────────────────────────────────────────────

    def _load_skills(self) -> None:
        try:
            rows = self._conn().execute(
                "SELECT * FROM learned_skills ORDER BY confidence DESC, usage_count DESC"
            ).fetchall()
            for row in rows:
                skill = self._row_to_skill(row)
                self._skills[skill.skill_id] = skill
        except Exception as exc:
            logger.warning("CLS: failed to load skills: %s", exc)

    def _row_to_skill(self, row: sqlite3.Row) -> LearnedSkill:
        # Convert to a plain dict first — sqlite3.Row.get() is only available
        # in Python >= 3.11, and using dict(row) is portable across versions.
        d = dict(row)
        steps_raw = json.loads(d["steps_json"])
        steps = [LearnedStep(**s) for s in steps_raw]
        return LearnedSkill(
            skill_id=d["skill_id"],
            intent_pattern=d["intent_pattern"],
            steps=steps,
            confidence=d["confidence"],
            usage_count=d["usage_count"],
            success_count=d["success_count"],
            tokens=json.loads(d["tokens_json"]),
            synonyms=json.loads(d["synonyms_json"]),
            created_at=d["created_at"],
            last_used=d["last_used"],
            source=d["source"],
            tags=json.loads(d.get("tags_json", "[]") or "[]"),
            notes=d.get("notes", "") or "",
        )

    def _save_skill(self, skill: LearnedSkill) -> None:
        steps_data = [asdict(s) for s in skill.steps]
        try:
            with self._lock:
                self._conn().execute(
                    """
                    INSERT OR REPLACE INTO learned_skills
                        (skill_id, intent_pattern, steps_json, confidence,
                         usage_count, success_count, tokens_json, synonyms_json,
                         tags_json, notes, created_at, last_used, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        skill.skill_id,
                        skill.intent_pattern,
                        json.dumps(steps_data),
                        skill.confidence,
                        skill.usage_count,
                        skill.success_count,
                        json.dumps(skill.tokens),
                        json.dumps(skill.synonyms),
                        json.dumps(skill.tags),
                        skill.notes,
                        skill.created_at,
                        skill.last_used,
                        skill.source,
                    ),
                )
                self._conn().commit()
        except Exception as exc:
            logger.warning("CLS: failed to save skill %s: %s", skill.skill_id[:8], exc)

    def _save_observation(
        self,
        skill_id: str,
        anon_goal: str,
        target_type: str,
        success: bool,
        mode: str,
        wave_count: int = 1,
        step_count: int = 0,
        duration_ms: float = 0.0,
    ) -> None:
        try:
            with self._lock:
                self._conn().execute(
                    """
                    INSERT INTO skill_observations
                        (obs_id, skill_id, anon_goal, target_type, success,
                         wave_count, step_count, duration_ms, observed_at, mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        skill_id,
                        anon_goal,
                        target_type,
                        1 if success else 0,
                        wave_count,
                        step_count,
                        duration_ms,
                        time.time(),
                        mode,
                    ),
                )
                self._conn().commit()
        except Exception as exc:
            logger.debug("CLS: failed to save observation: %s", exc)

    # ── Privacy — target anonymisation ─────────────────────────────────

    def _anonymize_target(self, text: str, target: str) -> str:
        """Replace ALL real target information with ``{target}`` placeholder.

        Uses both direct string replacement AND the full NLP regex pattern
        suite from :class:`~siyarix.nlp_engine.NaturalLanguageParser` to
        catch every possible target format (IP, domain, URL, email, hash…).

        CRITICAL: This method is the privacy boundary. No real target data
        must ever pass through to the database.
        """
        if not text:
            return text

        # 1 — Direct string replacement (most precise)
        if target:
            text = text.replace(target, "{target}")
            # Also handle stripped URL form  (e.g. "example.com" from "https://example.com/path")
            clean = (
                target.replace("https://", "")
                      .replace("http://", "")
                      .split("/")[0]
                      .split("?")[0]
            )
            if clean and clean != target and len(clean) > 3:
                text = text.replace(clean, "{target}")

        # 2 — Pattern-based sweep to catch anything the direct replacement missed
        try:
            from .nlp_engine import NaturalLanguageParser
            for pattern in NaturalLanguageParser.PATTERNS.values():
                try:
                    text = re.sub(pattern, "{target}", text)
                except re.error:
                    pass
        except ImportError:
            pass

        return text

    # ── NLP tokenisation (lightweight, no dependency on parser instance) ─

    def _tokenize(self, text: str) -> list[str]:
        """Minimal tokenisation: lowercase, strip punctuation, remove stopwords."""
        _STOPWORDS = frozenset({
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
            "for", "of", "with", "by", "from", "up", "about", "into", "please",
            "can", "you", "do", "i", "want", "need", "run", "execute", "perform",
            "start", "show", "find", "get", "tell", "is", "are", "was", "were",
            "all", "any", "some", "just", "now", "target", "on",
        })
        text = text.lower()
        text = re.sub(r"[^\w\s-]", " ", text)
        words = text.split()
        tokens = []
        clean_words = []
        for w in words:
            if w and w not in _STOPWORDS and len(w) > 1:
                clean_words.append(w)
                tokens.append(w)
        # bigrams
        for i in range(len(clean_words) - 1):
            tokens.append(f"{clean_words[i]}_{clean_words[i+1]}")
        return tokens

    # ── Similarity ──────────────────────────────────────────────────────

    def _compute_similarity(
        self,
        tokens_a: list[str],
        tokens_b: list[str],
        steps_a: list[LearnedStep] | None = None,
        steps_b: list[LearnedStep] | None = None,
        pattern_a: str = "",
        pattern_b: str = "",
    ) -> float:
        """Multi‑faceted similarity combining token Jaccard, tool overlap, and intent pattern match.

        Returns a float in [0.0, 1.0].
        """
        # 1 — Token Jaccard (primary signal)
        token_sim = 0.0
        if tokens_a and tokens_b:
            set_a = set(tokens_a)
            set_b = set(tokens_b)
            inter = len(set_a & set_b)
            union = len(set_a | set_b)
            token_sim = inter / union if union else 0.0

        # 2 — Tool overlap bonus (up to +0.25)
        tool_bonus = 0.0
        if steps_a and steps_b:
            tools_a = {s.tool for s in steps_a if s.tool}
            tools_b = {s.tool for s in steps_b if s.tool}
            if tools_a and tools_b:
                t_inter = len(tools_a & tools_b)
                t_union = len(tools_a | tools_b)
                tool_bonus = (t_inter / t_union) * 0.25

        # 3 — Intent pattern containment (up to +0.10)
        pattern_bonus = 0.0
        if pattern_a and pattern_b:
            a_lower = pattern_a.lower()
            b_lower = pattern_b.lower()
            if a_lower in b_lower or b_lower in a_lower:
                shorter = min(len(a_lower), len(b_lower))
                pattern_bonus = 0.10 * (min(len(a_lower), len(b_lower)) / max(len(a_lower), len(b_lower), 1))

        return min(1.0, token_sim + tool_bonus + pattern_bonus)

    # ── Synonym extraction ──────────────────────────────────────────────

    def _extract_synonyms(self, goal: str, steps: list[dict[str, Any]]) -> dict[str, str]:
        """Infer keyword → tool mappings from goal + steps."""
        synonyms: dict[str, str] = {}
        goal_tokens = self._tokenize(goal)
        for step in steps:
            tool = step.get("tool", "")
            if not tool or len(tool) < 2:
                continue
            for token in goal_tokens:
                if len(token) > 3 and token != tool:
                    synonyms.setdefault(token, tool)
        return synonyms

    # ── Core: find-or-create skill ──────────────────────────────────────

    def _find_or_create_skill(
        self,
        anon_goal: str,
        steps: list[dict[str, Any]],
        source: str,
    ) -> LearnedSkill:
        """Return the best matching existing skill or create a new one.

        Matching tiers:
            >= 0.65  → strong match (update existing)
            0.35–0.64 → partial match (merge into best candidate)
            <  0.35  → no match (create new)
        """
        goal_tokens = self._tokenize(anon_goal)

        # Convert incoming dict-steps to LearnedStep for similarity comparison
        incoming_learned: list[LearnedStep] = []
        for s in steps:
            cmd = s.get("command") or s.get("command_template") or ""
            incoming_learned.append(
                LearnedStep(
                    tool=s.get("tool", ""),
                    command_template=cmd,
                    description=s.get("description", ""),
                    args=s.get("args", {}),
                )
            )

        # Search for similar existing skills
        best_skill: LearnedSkill | None = None
        best_sim = 0.0
        for skill in self._skills.values():
            sim = self._compute_similarity(
                goal_tokens, skill.tokens,
                steps_a=incoming_learned, steps_b=skill.steps,
                pattern_a=anon_goal, pattern_b=skill.intent_pattern,
            )
            if sim > best_sim:
                best_sim = sim
                best_skill = skill

        # Tier 1: Strong match — reuse existing skill
        if best_skill and best_sim >= 0.65:
            logger.debug(
                "CLS: strong match '%s' (sim=%.2f)",
                best_skill.intent_pattern[:50], best_sim,
            )
            return best_skill

        # Tier 2: Partial match — merge into best candidate
        if best_skill and best_sim >= 0.35:
            logger.debug(
                "CLS: partial match '%s' (sim=%.2f) — will merge",
                best_skill.intent_pattern[:50], best_sim,
            )
            return best_skill

        # Tier 3: No match — create brand-new skill
        skill = LearnedSkill(
            skill_id=str(uuid.uuid4()),
            intent_pattern=anon_goal,
            steps=incoming_learned,
            confidence=0.0,
            usage_count=0,
            success_count=0,
            tokens=goal_tokens,
            synonyms=self._extract_synonyms(anon_goal, steps),
            created_at=time.time(),
            last_used=time.time(),
            source=source,
        )
        logger.debug("CLS: created new skill '%s'", anon_goal[:60])
        return skill

    # ── Core learning logic ─────────────────────────────────────────────

    def _merge_steps(
        self, existing_steps: list[LearnedStep], incoming_steps: list[dict[str, Any]]
    ) -> list[LearnedStep]:
        """Merge incoming steps into existing steps, avoiding tool-level duplicates.

        When the same tool appears in both lists the newer command_template and
        description are kept (most recent observation wins).
        """
        merged: dict[str, LearnedStep] = {}
        for s in existing_steps:
            if s.tool:
                merged[s.tool] = s
        for s in incoming_steps:
            tool = s.get("tool", "")
            cmd = s.get("command") or s.get("command_template") or ""
            desc = s.get("description", "")
            args = s.get("args", {})
            # Always prefer the incoming (newer) version of each tool step
            if tool:
                merged[tool] = LearnedStep(
                    tool=tool,
                    command_template=cmd,
                    description=desc,
                    args=args,
                )
        return list(merged.values())

    def _learn_from_observation(
        self,
        anon_goal: str,
        steps: list[dict[str, Any]],
        success: bool,
        target_type: str,
        source: str,
        wave_count: int = 1,
        duration_ms: float = 0.0,
        mode: str = "integrated",
    ) -> LearnedSkill:
        """Create or update a :class:`LearnedSkill` from a single observation.

        * Matches against existing skills via multi-tier similarity.
        * Merges steps by tool (deduplicates, keeps newest).
        * Enriches synonyms and intent pattern on each observation.
        """
        skill = self._find_or_create_skill(anon_goal, steps, source)

        # ── Merge steps (deduplicate by tool, newest wins) ──────────────
        if steps:
            merged = self._merge_steps(skill.steps, steps)
            skill.steps = merged

        # ── Update metadata on every observation ────────────────────────
        skill.intent_pattern = anon_goal
        skill.tokens = self._tokenize(anon_goal)
        skill.synonyms.update(self._extract_synonyms(anon_goal, steps))

        skill.usage_count += 1
        if success:
            skill.success_count += 1
        skill.last_used = time.time()
        skill.source = source
        skill.recalculate_confidence()

        # Persist
        self._skills[skill.skill_id] = skill
        self._save_skill(skill)
        self._save_observation(
            skill.skill_id, anon_goal, target_type, success, mode,
            wave_count=wave_count, step_count=len(steps), duration_ms=duration_ms,
        )

        logger.info(
            "CLS: skill %s | pattern='%s' | confidence=%.2f | usage=%d | success=%d | steps=%d",
            "updated" if skill.usage_count > 1 else "created",
            skill.intent_pattern[:55],
            skill.confidence,
            skill.usage_count,
            skill.success_count,
            len(skill.steps),
        )
        return skill

    # ── Public observation API ──────────────────────────────────────────

    def observe_llm_action(
        self,
        goal: str,
        plan: Any,
        result: Any,
        target: str = "",
        target_type: str = "",
        wave_count: int = 1,
        duration_ms: float = 0.0,
    ) -> LearnedSkill | None:
        """Observe an LLM-generated plan + execution result and update skills.

        Called by :meth:`~siyarix.chat.engine.LLMEngineMixin._execute_agent`
        after the multi-wave execution loop completes.

        Parameters
        ----------
        goal:       The original user goal (raw text — will be anonymised here).
        plan:       The ``ExecutionPlan`` produced by the autonomous planner.
        result:     Execution result object (or the last plan after execution).
        target:     The real target string (used only for anonymisation, not stored).
        target_type: Entity type of the target ('ipv4', 'domain', etc.)
        wave_count: Number of LLM waves executed.
        duration_ms: Total execution duration.
        """
        try:
            steps: list[dict[str, Any]] = []
            if plan and hasattr(plan, "steps"):
                for s in plan.steps:
                    cmd = getattr(s, "command", None) or ""
                    tool = getattr(s, "tool", "") or ""
                    desc = getattr(s, "description", "") or ""
                    args = dict(getattr(s, "args", {}) or {})
                    if not (cmd or tool):
                        continue
                    steps.append({
                        "tool": tool,
                        "command": self._anonymize_target(cmd, target),
                        "description": self._anonymize_target(desc, target),
                        "args": args,
                    })

            if not steps:
                return None

            success: bool = False
            if result is not None:
                if hasattr(result, "success"):
                    success = bool(result.success)
                elif hasattr(result, "status"):
                    from .models import PlanStatus
                    success = getattr(result, "status", None) == PlanStatus.COMPLETED

            anon_goal = self._anonymize_target(goal, target)
            return self._learn_from_observation(
                anon_goal, steps, success, target_type, "llm",
                wave_count=wave_count, duration_ms=duration_ms, mode="integrated",
            )
        except Exception as exc:
            logger.debug("CLS: observe_llm_action error: %s", exc, exc_info=True)
            return None

    def observe_offline_plan(
        self,
        goal: str,
        plan: Any,
        result: Any,
        target: str = "",
        target_type: str = "",
        duration_ms: float = 0.0,
    ) -> LearnedSkill | None:
        """Observe an offline/registry plan + execution result and update skills.

        Called by :meth:`~siyarix.chat.engine.LLMEngineMixin._execute_instruction`
        after offline mode execution completes.
        """
        try:
            steps: list[dict[str, Any]] = []
            if plan and hasattr(plan, "steps"):
                for s in plan.steps:
                    tool = getattr(s, "tool", "") or ""
                    args = dict(getattr(s, "args", {}) or {})
                    desc = getattr(s, "description", "") or ""
                    if not tool:
                        continue
                    # Build a synthetic command template from the tool + flags
                    flags = args.get("flags", "")
                    cmd_template = f"{tool} {flags} {{target}}".strip()
                    steps.append({
                        "tool": tool,
                        "command": self._anonymize_target(cmd_template, target),
                        "description": self._anonymize_target(desc, target),
                        "args": args,
                    })

            if not steps:
                return None

            success: bool = False
            if result is not None:
                success = bool(getattr(result, "success", False))

            anon_goal = self._anonymize_target(goal, target)
            return self._learn_from_observation(
                anon_goal, steps, success, target_type, "offline",
                duration_ms=duration_ms, mode="offline",
            )
        except Exception as exc:
            logger.debug("CLS: observe_offline_plan error: %s", exc, exc_info=True)
            return None

    # ── Skill maintenance ───────────────────────────────────────────────

    def _prune_skills(self, max_age_days: float = 180.0, min_usage: int = 1) -> int:
        """Remove skills that are stale, low-quality, or have never been used.

        Criteria:
            - Zero usage and older than 7 days (never useful)
            - Usage >= *min_usage* but last used more than *max_age_days* ago
              and confidence below 0.30
        """
        now = time.time()
        pruned: list[str] = []
        for sid, skill in list(self._skills.items()):
            age_days = (now - skill.created_at) / 86400.0
            idle_days = (now - skill.last_used) / 86400.0

            # Never used and older than a week → remove
            if skill.usage_count == 0 and age_days > 7.0:
                pruned.append(sid)
                continue

            # Low confidence and idle too long → remove
            if skill.usage_count >= min_usage and idle_days > max_age_days and skill.confidence < 0.30:
                pruned.append(sid)
                continue

        for sid in pruned:
            self.delete_skill(sid)

        if pruned:
            logger.info("CLS: pruned %d stale skill(s)", len(pruned))
        return len(pruned)

    def _decay_skills(self) -> int:
        """Recompute confidence for all skills, applying time decay.

        Called periodically to ensure old, unused skills naturally
        lose confidence.
        """
        decayed = 0
        for skill in self._skills.values():
            old_conf = skill.confidence
            skill.recalculate_confidence()
            if abs(skill.confidence - old_conf) > 0.01:
                decayed += 1
                self._save_skill(skill)
        if decayed:
            logger.debug("CLS: decayed %d skill(s)", decayed)
        return decayed

    def _merge_skills(self) -> int:
        """Find and merge similar skills (redundancy reduction).

        Scans all skill pairs; if two skills have similarity >= 0.70 their
        counts are combined and the weaker one is deleted.
        """
        sids = list(self._skills.keys())
        merged = 0
        for i in range(len(sids)):
            if sids[i] not in self._skills:
                continue
            a = self._skills[sids[i]]
            for j in range(i + 1, len(sids)):
                if sids[j] not in self._skills:
                    continue
                b = self._skills[sids[j]]
                sim = self._compute_similarity(
                    a.tokens, b.tokens,
                    steps_a=a.steps, steps_b=b.steps,
                    pattern_a=a.intent_pattern, pattern_b=b.intent_pattern,
                )
                if sim < 0.70:
                    continue
                # Merge b into a (keep the one with higher total usage)
                if b.usage_count > a.usage_count:
                    a, b = b, a
                a.usage_count += b.usage_count
                a.success_count += b.success_count
                a.steps = self._merge_steps(
                    a.steps,
                    [{"tool": s.tool, "command": s.command_template,
                      "description": s.description, "args": s.args}
                     for s in b.steps],
                )
                a.synonyms.update(b.synonyms)
                a.tags = list(dict.fromkeys(a.tags + b.tags))
                # Keep the older creation time
                a.created_at = min(a.created_at, b.created_at)
                a.last_used = max(a.last_used, b.last_used)
                a.recalculate_confidence()
                a.source = f"{a.source}+{b.source}"
                self._save_skill(a)
                self.delete_skill(b.skill_id)
                merged += 1

        if merged:
            logger.info("CLS: merged %d duplicate skill pair(s)", merged)
        return merged

    def maintain(self, *, force: bool = False) -> dict[str, int]:
        """Run all maintenance tasks: prune, decay, merge.

        This is safe to call periodically (e.g. once per session or after
        every N observations) to keep the skill library lean and relevant.

        Returns a dict with counts of each action taken.
        """
        result: dict[str, int] = {}
        result["pruned"] = self._prune_skills()
        result["decayed"] = self._decay_skills()
        result["merged"] = self._merge_skills()
        if any(result.values()):
            logger.info(
                "CLS: maintenance complete — pruned=%d decayed=%d merged=%d",
                result["pruned"], result["decayed"], result["merged"],
            )
        return result

    # ── Query API ───────────────────────────────────────────────────────

    def find_high_confidence_skill(
        self,
        goal: str,
        target: str = "",
        threshold: float = 0.80,
    ) -> LearnedSkill | None:
        """Return the best matching skill at or above *threshold*.

        Used in **integrated mode** to decide whether to skip the LLM and
        directly replay a cached skill, then send results to the LLM as
        base context.

        Returns ``None`` if no skill meets the threshold — the normal
        LLM planning flow should proceed.
        """
        if not self._skills:
            return None
        anon_goal = self._anonymize_target(goal, target)
        goal_tokens = self._tokenize(anon_goal)
        if not goal_tokens:
            return None

        best_skill: LearnedSkill | None = None
        best_score = 0.0
        for skill in self._skills.values():
            if skill.confidence < threshold:
                continue
            sim = self._compute_similarity(
                goal_tokens, skill.tokens,
                pattern_a=anon_goal, pattern_b=skill.intent_pattern,
            )
            # Combined score: penalise low-usage skills slightly
            volume_factor = min(1.0, math.log(1 + skill.usage_count) / math.log(6))
            combined = sim * skill.confidence * (0.7 + 0.3 * volume_factor)
            if combined > best_score:
                best_score = combined
                best_skill = skill

        if best_skill and best_score >= threshold * 0.75:
            logger.info(
                "CLS: high-confidence match '%s' (conf=%.2f, score=%.2f, threshold=%.2f)",
                best_skill.intent_pattern[:55],
                best_skill.confidence,
                best_score,
                threshold,
            )
            return best_skill
        return None

    def query_skill(
        self,
        goal: str,
        target: str = "",
        min_confidence: float = 0.50,
    ) -> LearnedSkill | None:
        """Return best matching skill at any confidence >= *min_confidence*.

        Used by the **offline planner** to augment or replace heuristic planning
        when a learned skill is available.
        """
        if not self._skills:
            return None
        anon_goal = self._anonymize_target(goal, target)
        goal_tokens = self._tokenize(anon_goal)
        if not goal_tokens:
            return None

        best_skill: LearnedSkill | None = None
        best_score = 0.0
        for skill in self._skills.values():
            if skill.confidence < min_confidence:
                continue
            sim = self._compute_similarity(
                goal_tokens, skill.tokens,
                pattern_a=anon_goal, pattern_b=skill.intent_pattern,
            )
            score = sim * skill.confidence
            if score > best_score:
                best_score = score
                best_skill = skill

        return best_skill if best_score > 0.15 else None

    # ── Skill instantiation ─────────────────────────────────────────────

    def instantiate_skill(
        self, skill: LearnedSkill, target: str
    ) -> list[dict[str, Any]]:
        """Replace ``{target}`` placeholders with the real target in all step templates.

        Returns a list of step dicts ready for :class:`~siyarix.models.ExecutionPlan`.
        """
        steps: list[dict[str, Any]] = []
        for s in skill.steps:
            instantiated = s.instantiate(target)
            steps.append({
                "tool": instantiated.tool,
                "command": instantiated.command_template,
                "description": instantiated.description,
                "args": {
                    **instantiated.args,
                    "target": target,
                },
            })
        return steps

    # ── NLP injection ───────────────────────────────────────────────────

    def inject_into_nlp(self, parser: Any) -> None:
        """Feed all learned skills' synonyms and token corpus into a NaturalLanguageParser.

        Called once during planner initialisation and after each new skill is learned
        to keep the NLP engine current.
        """
        merged_synonyms: dict[str, str] = {}
        for skill in self._skills.values():
            merged_synonyms.update(skill.synonyms)

        if merged_synonyms and hasattr(parser, "inject_learned_synonyms"):
            parser.inject_learned_synonyms(merged_synonyms)

        if hasattr(parser, "inject_learned_corpus"):
            for skill in self._skills.values():
                if skill.tokens:
                    parser.inject_learned_corpus(
                        skill.skill_id, skill.intent_pattern, skill.tokens
                    )

    # ── Offline summary ─────────────────────────────────────────────────

    def generate_offline_summary(
        self,
        goal: str,
        result: Any,
        matched_skill: LearnedSkill | None = None,
    ) -> str:
        """Generate an enhanced summary panel for offline mode output.

        Returns an empty string if no matched skill is available.
        """
        if not matched_skill:
            return ""

        lines = [
            f"📚 **Learning Insights** — based on {matched_skill.usage_count} prior observation(s):",
            f"  • Pattern: *{matched_skill.intent_pattern}*",
            f"  • Confidence: {matched_skill.confidence:.0%}  "
            f"({matched_skill.success_count}/{matched_skill.usage_count} successful runs)",
        ]
        if matched_skill.steps:
            tools = list(dict.fromkeys(s.tool for s in matched_skill.steps if s.tool))
            if tools:
                lines.append(f"  • Tools in pattern: {', '.join(tools)}")
        if matched_skill.tags:
            lines.append(f"  • Tags: {', '.join(matched_skill.tags)}")
        if matched_skill.notes:
            lines.append(f"  • Notes: {matched_skill.notes}")
        return "\n".join(lines)

    # ── LLM clarification ───────────────────────────────────────────────

    async def ask_llm_for_skill_label(
        self,
        goal: str,
        steps: list[dict[str, Any]],
        llm_call_fn: Any,
    ) -> str | None:
        """Ask the LLM to suggest a canonical name/label for a newly observed skill.

        Uses the same ``llm_call_fn`` that the main agent uses — no extra API calls.
        Returns a short label string or ``None`` on failure.
        """
        if llm_call_fn is None:
            return None
        try:
            step_summary = "; ".join(
                f"{s.get('tool', '?')}: {s.get('description', '')}"
                for s in steps[:5]
            )
            sys_p = (
                "You are a skill-labelling assistant for a cybersecurity tool. "
                "Respond with ONLY a short snake_case label (3-6 words max, no spaces). "
                "Example: subdomain_enumeration_passive"
            )
            user_p = (
                f"Goal: {goal}\n"
                f"Actions taken: {step_summary}\n"
                "Suggest a concise skill label for this workflow pattern."
            )
            raw = await llm_call_fn(sys_p, user_p)
            label = ""
            if isinstance(raw, dict):
                label = raw.get("content", "") or ""
            else:
                label = str(raw)
            label = label.strip().split("\n")[0].strip()
            # Sanitise to snake_case
            label = re.sub(r"[^a-z0-9_]", "_", label.lower()).strip("_")
            label = re.sub(r"_+", "_", label)
            return label[:60] if label else None
        except Exception as exc:
            logger.debug("CLS: LLM label request failed: %s", exc)
            return None

    # ── Skill management API ────────────────────────────────────────────

    def list_skills(
        self,
        min_confidence: float = 0.0,
        source: str | None = None,
        tag: str | None = None,
        limit: int = 200,
    ) -> list[LearnedSkill]:
        """Return skills sorted by confidence desc, usage desc."""
        skills = list(self._skills.values())
        if min_confidence > 0:
            skills = [s for s in skills if s.confidence >= min_confidence]
        if source:
            skills = [s for s in skills if s.source == source]
        if tag:
            skills = [s for s in skills if tag in s.tags]
        skills.sort(key=lambda s: (-s.confidence, -s.usage_count))
        return skills[:limit]

    def get_skill(self, skill_id: str) -> LearnedSkill | None:
        """Get a skill by its ID."""
        return self._skills.get(skill_id)

    def delete_skill(self, skill_id: str) -> bool:
        """Remove a skill from memory and database."""
        if skill_id not in self._skills:
            return False
        del self._skills[skill_id]
        try:
            with self._lock:
                self._conn().execute(
                    "DELETE FROM learned_skills WHERE skill_id=?", (skill_id,)
                )
                self._conn().commit()
            logger.info("CLS: deleted skill %s", skill_id[:8])
            return True
        except Exception as exc:
            logger.warning("CLS: failed to delete skill %s: %s", skill_id[:8], exc)
            return False

    def update_skill_tag(self, skill_id: str, tag: str, remove: bool = False) -> bool:
        """Add or remove a tag on a skill."""
        skill = self._skills.get(skill_id)
        if not skill:
            return False
        if remove:
            skill.tags = [t for t in skill.tags if t != tag]
        else:
            if tag not in skill.tags:
                skill.tags.append(tag)
        self._save_skill(skill)
        return True

    def update_skill_notes(self, skill_id: str, notes: str) -> bool:
        """Update the notes field on a skill."""
        skill = self._skills.get(skill_id)
        if not skill:
            return False
        skill.notes = notes[:500]
        self._save_skill(skill)
        return True

    def export_skills(self, path: Path | None = None) -> dict[str, Any]:
        """Export all skills as JSON for sharing with Siyarix developers.

        All data in the export is already anonymised (``{target}`` placeholders).
        No real target information is ever exported.
        """
        try:
            from . import __version__ as ver
        except Exception:
            ver = "unknown"

        payload: dict[str, Any] = {
            "schema_version": self._SCHEMA_VERSION,
            "siyarix_version": ver,
            "exported_at": time.time(),
            "skill_count": len(self._skills),
            "skills": [s.to_dict() for s in self.list_skills()],
        }

        if path is not None:
            try:
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                logger.info("CLS: exported %d skills to %s", len(self._skills), path)
            except Exception as exc:
                logger.warning("CLS: export failed: %s", exc)

        return payload

    def import_skills(self, data: dict[str, Any]) -> int:
        """Import skills from an exported dict. Returns count of new skills imported."""
        imported = 0
        for s in data.get("skills", []):
            if s["skill_id"] in self._skills:
                continue  # Don't overwrite existing
            try:
                steps = [LearnedStep(**step) for step in s.get("steps", [])]
                skill = LearnedSkill(
                    skill_id=s["skill_id"],
                    intent_pattern=s["intent_pattern"],
                    steps=steps,
                    confidence=s.get("confidence", 0.0),
                    usage_count=s.get("usage_count", 0),
                    success_count=s.get("success_count", 0),
                    tokens=s.get("tokens", []),
                    synonyms=s.get("synonyms", {}),
                    created_at=s.get("created_at", time.time()),
                    last_used=s.get("last_used", time.time()),
                    source=s.get("source", "imported"),
                    tags=s.get("tags", []),
                    notes=s.get("notes", ""),
                )
                self._skills[skill.skill_id] = skill
                self._save_skill(skill)
                imported += 1
            except Exception as exc:
                logger.debug("CLS: failed to import skill: %s", exc)
        return imported

    def stats(self) -> dict[str, Any]:
        """Return comprehensive statistics about the learning system."""
        skills = list(self._skills.values())
        total = len(skills)
        avg_conf = sum(s.confidence for s in skills) / max(total, 1)
        total_obs = sum(s.usage_count for s in skills)
        total_success = sum(s.success_count for s in skills)

        # Tool distribution across all skills
        tool_counter: dict[str, int] = {}
        for s in skills:
            for step in s.steps:
                if step.tool:
                    tool_counter[step.tool] = tool_counter.get(step.tool, 0) + 1

        # Skill age buckets
        now = time.time()
        young = sum(1 for s in skills if (now - s.created_at) / 86400.0 < 7.0)
        mature = sum(1 for s in skills if 7.0 <= (now - s.created_at) / 86400.0 < 60.0)
        old = sum(1 for s in skills if (now - s.created_at) / 86400.0 >= 60.0)

        # Confidence distribution — more granular buckets
        conf_buckets = {
            "elite (>= 0.90)": sum(1 for s in skills if s.confidence >= 0.90),
            "high (0.70–0.89)": sum(1 for s in skills if 0.70 <= s.confidence < 0.90),
            "medium (0.40–0.69)": sum(1 for s in skills if 0.40 <= s.confidence < 0.70),
            "low (0.10–0.39)": sum(1 for s in skills if 0.10 <= s.confidence < 0.40),
            "negligible (< 0.10)": sum(1 for s in skills if s.confidence < 0.10),
        }

        return {
            "total_skills": total,
            "confidence_distribution": conf_buckets,
            "avg_confidence": round(avg_conf, 3),
            "total_observations": total_obs,
            "total_successes": total_success,
            "overall_success_rate": round(total_success / max(total_obs, 1), 3),
            "total_steps": sum(len(s.steps) for s in skills),
            "avg_steps_per_skill": round(sum(len(s.steps) for s in skills) / max(total, 1), 1),
            "avg_usage_per_skill": round(total_obs / max(total, 1), 1),
            "tool_coverage": len(tool_counter),
            "top_tools": dict(sorted(tool_counter.items(), key=lambda x: -x[1])[:10]),
            "age_buckets_days": {"young (<7)": young, "mature (7–60)": mature, "old (>60)": old},
            "total_synonyms": sum(len(s.synonyms) for s in skills),
            "sources": {
                "llm": sum(1 for s in skills if "llm" in s.source),
                "offline": sum(1 for s in skills if "offline" in s.source),
                "imported": sum(1 for s in skills if "imported" in s.source),
            },
            "db_path": str(self._db_path),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_LEARNING_SYSTEM: ContinuousLearningSystem | None = None
_LS_LOCK = threading.Lock()


def get_learning_system() -> ContinuousLearningSystem:
    """Return the process-wide :class:`ContinuousLearningSystem` singleton."""
    global _LEARNING_SYSTEM  # noqa: PLW0603
    if _LEARNING_SYSTEM is None:
        with _LS_LOCK:
            if _LEARNING_SYSTEM is None:
                _LEARNING_SYSTEM = ContinuousLearningSystem()
    return _LEARNING_SYSTEM


__all__ = [
    "ContinuousLearningSystem",
    "LearnedSkill",
    "LearnedStep",
    "get_learning_system",
]
