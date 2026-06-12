from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from .types import FailoverReason
from ..events import Event, EventType, emit_sync

logger = logging.getLogger(__name__)


class ProviderStateManager:
    """Persists provider cooldown/failure state across restarts.

    Enhanced with OpenClaw patterns:
      - Exponential backoff cooldown (30s → 1min → 5min)
      - Per-reason cooldown tracking
      - Skip-known-bad cache per session
    """

    COOLDOWN_STEPS = [30.0, 60.0, 300.0]
    MAX_COOLDOWN = 300.0

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._disabled: dict[str, float] = {}
        self._failure_counts: dict[str, int] = {}
        self._last_fail_time: dict[str, float] = {}
        self._cooldown_secs = 30.0
        self._skip_cache: dict[str, dict[str, float]] = {}
        if path:
            self._load()

    def _load(self) -> None:
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("disabled", {})
            if isinstance(raw, dict):
                self._disabled = {k: float(v) for k, v in raw.items()}
            elif isinstance(raw, list):
                self._disabled = {p: 0.0 for p in raw}
            self._failure_counts = data.get("failure_counts", {})
            self._last_fail_time = {k: float(v) for k, v in data.get("last_fail_time", {}).items()}
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self) -> None:
        if not self.path:
            return
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "disabled": self._disabled,
                        "failure_counts": self._failure_counts,
                        "last_fail_time": self._last_fail_time,
                    },
                    f,
                    indent=2,
                )
        except Exception as exc:
            logger.debug("Failed to save provider state: %s", exc)

    def _compute_cooldown(self, provider: str) -> float:
        """Exponential backoff: 30s → 60s → 300s based on failure count.

        OpenClaw pattern: calculateAuthProfileCooldownMs().
        """
        count = self._failure_counts.get(provider, 0)
        step_idx = min(count - 1, len(self.COOLDOWN_STEPS) - 1)
        if step_idx < 0:
            return self.COOLDOWN_STEPS[0]
        return self.COOLDOWN_STEPS[step_idx]

    def is_disabled(self, provider: str) -> bool:
        if provider not in self._disabled:
            return False
        expires = self._disabled[provider]
        if time.time() >= expires:
            del self._disabled[provider]
            self._failure_counts[provider] = 0
            self.save()
            return False
        return True

    def cooldown_remaining(self, provider: str) -> float:
        """Seconds remaining until cooldown expires."""
        if provider not in self._disabled:
            return 0.0
        remaining = self._disabled[provider] - time.time()
        return max(0.0, remaining)

    def record_failure(self, provider: str, reason: FailoverReason | None = None) -> None:
        self._failure_counts[provider] = self._failure_counts.get(provider, 0) + 1
        cooldown = self._compute_cooldown(provider)
        self._disabled[provider] = time.time() + cooldown
        self._last_fail_time[provider] = time.time()
        self.save()
        emit_sync(
            Event(
                type=EventType.PROVIDER_ERROR,
                source="providers",
                data={
                    "provider": provider,
                    "failure_count": self._failure_counts[provider],
                    "cooldown": cooldown,
                    "reason": reason.value if reason else "unknown",
                },
            )
        )

    def record_success(self, provider: str) -> None:
        self._disabled.pop(provider, None)
        self._failure_counts[provider] = 0
        self.save()
        emit_sync(
            Event(
                type=EventType.PROVIDER_SELECTED,
                source="providers",
                data={"provider": provider, "status": "recovered"},
            )
        )

    def mark_skip_candidate(self, session_id: str, provider: str, model: str) -> None:
        """Skip-known-bad cache: remember a failing (provider, model) pair.

        OpenClaw pattern: fallback-skip-cache.ts.
        """
        if session_id not in self._skip_cache:
            self._skip_cache[session_id] = {}
        key = f"{provider}/{model}"
        self._skip_cache[session_id][key] = time.time() + 300.0

    def is_candidate_skipped(self, session_id: str, provider: str, model: str) -> bool:
        """Check if a candidate is in the skip-known-bad cache."""
        cache = self._skip_cache.get(session_id, {})
        key = f"{provider}/{model}"
        if key not in cache:
            return False
        if time.time() >= cache[key]:
            del cache[key]
            return False
        return True

    def get_available_providers(self, preferred: list[str] | None = None) -> list[str]:
        """Return list of non-disabled providers, with preferred ones first.

        OpenClaw pattern: resolveModelCandidateChain() simplified.
        """
        available = [
            p
            for p in (preferred or [])
            if p not in self._disabled or time.time() >= self._disabled[p]
        ]
        return available
