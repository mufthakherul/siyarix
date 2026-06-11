# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-provider LLM abstraction with fallback and credential pooling.

Supports 24 providers with capability flags, cost tiers, and smart failover.
"""

from __future__ import annotations

import enum
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .events import Event, EventType, emit_sync
from .model_aliases import normalize_model_id

logger = logging.getLogger(__name__)


class FailoverReason(enum.Enum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    BILLING = "billing"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server_error"
    CONTEXT_OVERFLOW = "context_overflow"
    MODEL_NOT_FOUND = "model_not_found"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedError:
    reason: FailoverReason
    retryable: bool = True
    should_rotate_credential: bool = False
    should_fallback: bool = False
    should_compress: bool = False
    message: str = ""


@dataclass
class ProviderCredential:
    provider: str
    api_key: str = ""
    base_url: str = ""
    status: str = "active"
    cooldown_until: float = 0.0
    failure_count: int = 0
    last_used: float = 0.0

    @property
    def is_available(self) -> bool:
        if self.status == "dead":
            return False
        if self.cooldown_until > time.time():
            return False
        return bool(self.api_key) or bool(self.base_url)


class CostTier(enum.StrEnum):
    FREE = "free"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def sort_key(self) -> int:
        return {"free": 0, "low": 1, "medium": 2, "high": 3}.get(self.value, 99)


class ProviderType(enum.StrEnum):
    CLOUD = "cloud"
    LOCAL = "local"


@dataclass
class ModelInfo:
    name: str
    supports_vision: bool = False
    supports_tools: bool = True
    supports_structured_output: bool = False
    supports_function_calling: bool = True
    context_window: int = 8192
    cost_tier: CostTier = CostTier.MEDIUM


@dataclass
class ProviderProfile:
    name: str
    display_name: str = ""
    models: list[ModelInfo] = field(default_factory=list)
    default_model: str = ""
    api_key_env: str = ""
    base_url: str = ""
    supports_streaming: bool = True
    supports_tools: bool = True
    supports_vision: bool = False
    supports_structured_output: bool = False
    sdk_dependency: str = ""
    max_tokens: int = 4096
    max_context_tokens: int = 128000
    priority: int = 0
    cost_tier: CostTier = CostTier.MEDIUM
    provider_type: ProviderType = ProviderType.CLOUD
    fallback_models: list[str] = field(default_factory=list)
    docs_url: str = ""

    def __post_init__(self) -> None:
        if not self.display_name:
            self.display_name = self.name.title()
        if not self.default_model and self.models:
            self.default_model = self.models[0].name
        if self.models and not self.fallback_models:
            self.fallback_models = [m.name for m in self.models[1:]]
        if self.models:
            self.supports_structured_output = any(m.supports_structured_output for m in self.models)
            self.supports_vision = any(m.supports_vision for m in self.models)
            self.supports_tools = any(m.supports_tools for m in self.models)

    def get_model_names(self) -> list[str]:
        return [m.name for m in self.models]


@dataclass
class UsageRecord:
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    call_count: int = 0
    total_cost_estimated: float = 0.0

    def record(
        self, input_tokens: int, output_tokens: int, cost_tier: CostTier = CostTier.MEDIUM
    ) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.call_count += 1
        rates = {
            CostTier.FREE: 0.0,
            CostTier.LOW: 0.15e-6,
            CostTier.MEDIUM: 2.0e-6,
            CostTier.HIGH: 10.0e-6,
        }
        rate = rates.get(cost_tier, 2.0e-6)
        self.total_cost_estimated += (input_tokens + output_tokens * 4) * rate

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "call_count": self.call_count,
            "total_cost_estimated": round(self.total_cost_estimated, 6),
        }

    @classmethod
    def from_dict(cls, d: dict) -> UsageRecord:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class UsageTracker:
    """Tracks token usage and cost per provider across a session."""

    def __init__(self, path: str | None = None) -> None:
        self._records: dict[str, UsageRecord] = {}
        self._path = path

    def record_call(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_tier: CostTier = CostTier.MEDIUM,
    ) -> None:
        key = f"{provider}/{model}"
        if key not in self._records:
            self._records[key] = UsageRecord(provider=provider, model=model)
        self._records[key].record(input_tokens, output_tokens, cost_tier)

    def summary(self) -> str:
        if not self._records:
            return "No LLM usage this session."
        total_cost = sum(r.total_cost_estimated for r in self._records.values())
        total_in = sum(r.input_tokens for r in self._records.values())
        total_out = sum(r.output_tokens for r in self._records.values())
        total_calls = sum(r.call_count for r in self._records.values())
        return (
            f"LLM calls: {total_calls} | Tokens: {total_in}↑ {total_out}↓ "
            f"| Est. cost: ${total_cost:.4f}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {k: v.to_dict() for k, v in self._records.items()}

    def save(self) -> None:
        if not self._path:
            return
        try:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception as exc:
            logger.debug("Failed to save usage tracker: %s", exc)

    @classmethod
    def load(cls, path: str) -> UsageTracker:
        tracker = cls(path=path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for key, record in data.items():
                tracker._records[key] = UsageRecord.from_dict(record)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return tracker


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

    def record_failure(
        self, provider: str, reason: FailoverReason | None = None
    ) -> None:
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

    def get_available_providers(
        self, preferred: list[str] | None = None
    ) -> list[str]:
        """Return list of non-disabled providers, with preferred ones first.

        OpenClaw pattern: resolveModelCandidateChain() simplified.
        """
        available = [
            p for p in (preferred or [])
            if p not in self._disabled or time.time() >= self._disabled[p]
        ]
        return available


class ProviderManager:
    _instance: ProviderManager | None = None
    _instance_lock: Any = None

    @classmethod
    def get_instance(cls) -> ProviderManager:
        """Return the shared singleton, creating it once on first access."""
        if cls._instance is None:
            if cls._instance_lock is None:
                import threading
                cls._instance_lock = threading.Lock()
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._profiles: dict[str, ProviderProfile] = {}
        self._credentials: dict[str, list[ProviderCredential]] = {}
        self._error_counts: dict[str, int] = {}
        self._init_default_profiles()

    def _init_default_profiles(self) -> None:
        # ── OpenAI ──────────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="openai",
                display_name="OpenAI",
                models=[
                    ModelInfo(
                        "gpt-5.5",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.5-pro",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=1000000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.4",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=272000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.4-pro",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1050000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.4-mini",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=400000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gpt-5.4-nano",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=400000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "gpt-5.3-codex",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=400000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.2",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=400000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gpt-4.1",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gpt-4.1-mini",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "gpt-4.1-nano",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "o4-mini",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "o4-mini-deep-research",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "o3",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "o3-mini",
                        supports_vision=False,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "o3-pro",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "o3-deep-research",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "o1",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "o1-pro",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                ],
                api_key_env="OPENAI_API_KEY",
                max_context_tokens=1000000,
                supports_streaming=True,
                supports_vision=True,
                priority=10,
                cost_tier=CostTier.HIGH,
                docs_url="https://platform.openai.com/docs/models",
            )
        )

        # ── Anthropic ───────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="anthropic",
                display_name="Anthropic",
                models=[
                    ModelInfo(
                        "claude-opus-4-8",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "claude-opus-4-7",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "claude-opus-4-6",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "claude-sonnet-4-6",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "claude-haiku-4-5",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=200000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                ],
                api_key_env="ANTHROPIC_API_KEY",
                max_context_tokens=1048576,
                supports_streaming=True,
                supports_vision=True,
                priority=10,
                cost_tier=CostTier.HIGH,
                docs_url="https://docs.anthropic.com/en/docs/about-claude/models",
            )
        )

        # ── Google Gemini ──────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="gemini",
                display_name="Google Gemini",
                models=[
                    ModelInfo(
                        "gemini-3.5-pro",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=2000000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gemini-3.5-flash",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gemini-3.1-pro-preview",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gemini-3.1-pro",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=2000000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gemini-3.1-flash",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gemini-3.1-flash-lite",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "gemini-3-flash-preview",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gemini-3.0-pro",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gemini-3.0-flash",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "gemini-2.5-pro",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gemini-2.5-flash",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "gemini-2.5-flash-lite",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.FREE,
                    ),
                    ModelInfo(
                        "gemini-2.0-flash",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1048576,
                        cost_tier=CostTier.FREE,
                    ),
                ],
                api_key_env="GEMINI_API_KEY",
                max_context_tokens=2000000,
                supports_streaming=True,
                supports_vision=True,
                priority=9,
                cost_tier=CostTier.LOW,
                docs_url="https://ai.google.dev/gemini-api/docs/models",
            )
        )

        # ── Groq ───────────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="groq",
                display_name="Groq",
                models=[
                    ModelInfo(
                        "groq/compound",
                        supports_tools=True,
                        context_window=131072,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "groq/compound-mini",
                        supports_tools=True,
                        context_window=131072,
                        cost_tier=CostTier.FREE,
                    ),
                    ModelInfo(
                        "llama-4-scout-17b-16e-instruct",
                        supports_vision=True,
                        context_window=262144,
                        cost_tier=CostTier.FREE,
                    ),
                    ModelInfo(
                        "llama-4-maverick-17b-128e-instruct",
                        supports_vision=True,
                        context_window=131072,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "llama-3.3-70b-versatile", context_window=32768, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "llama-3.1-8b-instant", context_window=128000, cost_tier=CostTier.FREE
                    ),
                    ModelInfo(
                        "mixtral-8x7b-32768", context_window=32768, cost_tier=CostTier.FREE
                    ),
                    ModelInfo(
                        "openai/gpt-oss-120b", context_window=128000, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "openai/gpt-oss-20b", context_window=128000, cost_tier=CostTier.FREE
                    ),
                    ModelInfo(
                        "qwen/qwen3-32b", context_window=128000, cost_tier=CostTier.FREE
                    ),
                ],
                api_key_env="GROQ_API_KEY",
                max_context_tokens=262144,
                supports_streaming=True,
                priority=8,
                cost_tier=CostTier.FREE,
                docs_url="https://console.groq.com/docs/models",
            )
        )

        # ── Together AI ────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="together",
                display_name="Together AI",
                models=[
                    ModelInfo(
                        "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8",
                        supports_vision=True,
                        context_window=512000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
                        supports_vision=True,
                        context_window=131072,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                        context_window=131072,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "deepseek-ai/DeepSeek-V4-Pro", context_window=1000000, cost_tier=CostTier.MEDIUM
                    ),
                    ModelInfo(
                        "deepseek-ai/DeepSeek-V3.1", context_window=128000, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "moonshotai/Kimi-K2.6",
                        supports_vision=True,
                        context_window=262144,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "Qwen/Qwen2.5-7B-Instruct-Turbo", context_window=32768, cost_tier=CostTier.FREE
                    ),
                    ModelInfo(
                        "zai-org/GLM-5.1", context_window=202800, cost_tier=CostTier.LOW
                    ),
                ],
                api_key_env="TOGETHER_API_KEY",
                max_context_tokens=512000,
                supports_streaming=True,
                supports_vision=True,
                priority=7,
                cost_tier=CostTier.LOW,
                docs_url="https://docs.together.ai/docs/inference-models",
            )
        )

        # ── OpenRouter ─────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="openrouter",
                display_name="OpenRouter",
                models=[
                    ModelInfo(
                        "openai/gpt-5.4",
                        supports_vision=True,
                        context_window=272000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "openai/gpt-5.5",
                        supports_vision=True,
                        context_window=1000000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "anthropic/claude-opus-4.8",
                        supports_vision=True,
                        context_window=1048576,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "anthropic/claude-sonnet-4.6",
                        supports_vision=True,
                        context_window=200000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "google/gemini-2.5-pro",
                        supports_vision=True,
                        context_window=1048576,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "deepseek/deepseek-v4-flash", context_window=1000000, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "deepseek/deepseek-v4-pro",
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "meta-llama/llama-4-scout-17b-16e-instruct",
                        supports_vision=True,
                        context_window=262144,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "nvidia/nemotron-3-super-120b:free",
                        context_window=1000000,
                        cost_tier=CostTier.FREE,
                    ),
                    ModelInfo(
                        "minimax/minimax-m2.7", context_window=204000, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "ai21/jamba-large-1.7", context_window=256000, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "qwen/qwen3.5-9b", context_window=32768, cost_tier=CostTier.FREE
                    ),
                    ModelInfo(
                        "z-ai/glm-5.1", context_window=202800, cost_tier=CostTier.LOW
                    ),
                ],
                api_key_env="OPENROUTER_API_KEY",
                max_context_tokens=2000000,
                supports_streaming=True,
                supports_vision=True,
                priority=6,
                cost_tier=CostTier.MEDIUM,
                docs_url="https://openrouter.ai/models",
            )
        )

        # ── DeepSeek ───────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="deepseek",
                display_name="DeepSeek",
                models=[
                    ModelInfo(
                        "deepseek-v4-flash",
                        supports_tools=True,
                        context_window=1000000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "deepseek-v4-pro",
                        supports_tools=True,
                        supports_structured_output=False,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo("deepseek-chat", context_window=131072, cost_tier=CostTier.LOW),
                    ModelInfo(
                        "deepseek-reasoner",
                        supports_tools=False,
                        context_window=131072,
                        cost_tier=CostTier.LOW,
                    ),
                ],
                api_key_env="DEEPSEEK_API_KEY",
                base_url="https://api.deepseek.com",
                max_context_tokens=1000000,
                supports_streaming=True,
                priority=8,
                cost_tier=CostTier.LOW,
                docs_url="https://platform.deepseek.com/docs",
            )
        )

        # ── xAI / Grok ────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="xai",
                display_name="xAI (Grok)",
                models=[
                    ModelInfo(
                        "grok-4.3",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "grok-4.1-fast",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=2000000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "grok-4.20-beta-latest-reasoning",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=2000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "grok-4.20-beta-latest-non-reasoning",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=2000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "grok-4.20",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=2000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "grok-build-0.1",
                        supports_vision=True,
                        supports_structured_output=False,
                        context_window=256000,
                        cost_tier=CostTier.LOW,
                    ),
                ],
                api_key_env="XAI_API_KEY",
                base_url="https://api.x.ai",
                max_context_tokens=2000000,
                supports_streaming=True,
                supports_vision=True,
                priority=7,
                cost_tier=CostTier.MEDIUM,
                docs_url="https://docs.x.ai/docs",
            )
        )

        # ── Mistral AI ─────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="mistral",
                display_name="Mistral AI",
                models=[
                    ModelInfo(
                        "mistral-large-latest",
                        supports_vision=True,
                        supports_function_calling=True,
                        supports_structured_output=True,
                        context_window=262000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "mistral-medium-3-5",
                        supports_vision=True,
                        supports_function_calling=True,
                        context_window=262000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "mistral-small-latest",
                        supports_vision=True,
                        supports_function_calling=True,
                        context_window=128000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "codestral-latest",
                        supports_function_calling=True,
                        context_window=256000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "pixtral-large-latest",
                        supports_vision=True,
                        supports_function_calling=True,
                        context_window=128000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "devstral-medium-latest",
                        supports_function_calling=True,
                        context_window=262000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "magistral-small",
                        supports_function_calling=True,
                        context_window=128000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                ],
                default_model="mistral-large-latest",
                api_key_env="MISTRAL_API_KEY",
                base_url="https://api.mistral.ai",
                max_context_tokens=262000,
                supports_streaming=True,
                supports_vision=True,
                priority=7,
                cost_tier=CostTier.MEDIUM,
                docs_url="https://docs.mistral.ai/platform/models",
            )
        )

        # ── Perplexity ─────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="perplexity",
                display_name="Perplexity",
                models=[
                    ModelInfo(
                        "sonar-pro",
                        supports_structured_output=False,
                        context_window=200000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "sonar",
                        supports_structured_output=False,
                        context_window=128000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "sonar-reasoning-pro",
                        supports_structured_output=False,
                        context_window=128000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "sonar-reasoning",
                        supports_structured_output=False,
                        context_window=128000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "sonar-deep-research",
                        supports_structured_output=False,
                        context_window=128000,
                        cost_tier=CostTier.HIGH,
                    ),
                ],
                api_key_env="PERPLEXITY_API_KEY",
                base_url="https://api.perplexity.ai",
                max_context_tokens=200000,
                supports_streaming=True,
                priority=6,
                cost_tier=CostTier.MEDIUM,
                docs_url="https://docs.perplexity.ai/docs/model-cards",
            )
        )

        # ── Cerebras ──────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="cerebras",
                display_name="Cerebras",
                models=[
                    ModelInfo("zai-glm-4.7", context_window=128000, cost_tier=CostTier.LOW),
                    ModelInfo("gpt-oss-120b", context_window=128000, cost_tier=CostTier.LOW),
                    ModelInfo("gpt-oss-20b", context_window=128000, cost_tier=CostTier.FREE),
                    ModelInfo("qwen-3-235b-a22b-instruct-2507", context_window=128000, cost_tier=CostTier.LOW),
                    ModelInfo("llama3.1-8b", context_window=128000, cost_tier=CostTier.FREE),
                ],
                default_model="zai-glm-4.7",
                api_key_env="CEREBRAS_API_KEY",
                base_url="https://api.cerebras.ai/v1",
                max_context_tokens=128000,
                supports_streaming=True,
                priority=6,
                cost_tier=CostTier.LOW,
                docs_url="https://cerebras.ai/inference",
            )
        )

        # ── Fireworks AI ──────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="fireworks",
                display_name="Fireworks AI",
                models=[
                    ModelInfo(
                        "accounts/fireworks/models/kimi-k2p6",
                        supports_vision=True,
                        context_window=262144,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo(
                        "accounts/fireworks/routers/kimi-k2p5-turbo",
                        supports_vision=True,
                        context_window=256000,
                        cost_tier=CostTier.LOW,
                    ),
                ],
                default_model="accounts/fireworks/routers/kimi-k2p5-turbo",
                api_key_env="FIREWORKS_API_KEY",
                base_url="https://api.fireworks.ai/inference/v1",
                max_context_tokens=262144,
                supports_streaming=True,
                supports_vision=True,
                priority=6,
                cost_tier=CostTier.LOW,
                docs_url="https://fireworks.ai/models",
            )
        )

        # ── Z.AI (GLM) ────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="zai",
                display_name="Z.AI (GLM)",
                models=[
                    ModelInfo("glm-5.1", context_window=202800, cost_tier=CostTier.LOW),
                    ModelInfo("glm-5", context_window=202800, cost_tier=CostTier.LOW),
                    ModelInfo("glm-5-turbo", context_window=202800, cost_tier=CostTier.LOW),
                    ModelInfo(
                        "glm-5v-turbo", supports_vision=True, context_window=202800, cost_tier=CostTier.LOW
                    ),
                    ModelInfo("glm-4.7", context_window=204800, cost_tier=CostTier.LOW),
                    ModelInfo("glm-4.7-flash", context_window=200000, cost_tier=CostTier.FREE),
                    ModelInfo(
                        "glm-4.6v", supports_vision=True, context_window=128000, cost_tier=CostTier.LOW
                    ),
                ],
                default_model="glm-5",
                api_key_env="ZAI_API_KEY",
                base_url="https://api.z.ai/api/paas/v4",
                max_context_tokens=202800,
                supports_streaming=True,
                priority=6,
                cost_tier=CostTier.LOW,
                docs_url="https://z.ai/docs",
            )
        )

        # ── MiniMax ───────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="minimax",
                display_name="MiniMax",
                models=[
                    ModelInfo(
                        "MiniMax-M3",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo("MiniMax-M2.7", context_window=204000, cost_tier=CostTier.LOW),
                    ModelInfo("MiniMax-M2.7-highspeed", context_window=204000, cost_tier=CostTier.LOW),
                ],
                default_model="MiniMax-M3",
                api_key_env="MINIMAX_API_KEY",
                base_url="https://api.minimax.io/v1",
                max_context_tokens=1000000,
                supports_streaming=True,
                supports_vision=True,
                priority=5,
                cost_tier=CostTier.MEDIUM,
                docs_url="https://platform.minimaxi.com",
            )
        )

        # ── Moonshot / Kimi ───────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="moonshot",
                display_name="Moonshot (Kimi)",
                models=[
                    ModelInfo(
                        "kimi-k2.6", supports_vision=True, context_window=262144, cost_tier=CostTier.LOW
                    ),
                    ModelInfo(
                        "kimi-k2.5", supports_vision=True, context_window=262144, cost_tier=CostTier.LOW
                    ),
                    ModelInfo("kimi-k2-thinking", context_window=262144, cost_tier=CostTier.LOW),
                    ModelInfo("kimi-k2-thinking-turbo", context_window=262144, cost_tier=CostTier.LOW),
                    ModelInfo("kimi-k2-turbo", context_window=256000, cost_tier=CostTier.LOW),
                ],
                default_model="kimi-k2.6",
                api_key_env="MOONSHOT_API_KEY",
                base_url="https://api.moonshot.ai/v1",
                max_context_tokens=262144,
                supports_streaming=True,
                supports_vision=True,
                priority=5,
                cost_tier=CostTier.LOW,
                docs_url="https://platform.moonshot.ai",
            )
        )

        # ── NVIDIA ────────────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="nvidia",
                display_name="NVIDIA",
                models=[
                    ModelInfo(
                        "nvidia/nemotron-3-super-120b-a12b",
                        context_window=1000000,
                        cost_tier=CostTier.LOW,
                    ),
                    ModelInfo("moonshotai/kimi-k2.5", supports_vision=True, context_window=262144, cost_tier=CostTier.LOW),
                    ModelInfo("minimaxai/minimax-m2.7", context_window=204000, cost_tier=CostTier.LOW),
                    ModelInfo("z-ai/glm-5.1", context_window=202800, cost_tier=CostTier.LOW),
                ],
                default_model="nvidia/nemotron-3-super-120b-a12b",
                api_key_env="NVIDIA_API_KEY",
                base_url="https://integrate.api.nvidia.com/v1",
                max_context_tokens=1000000,
                supports_streaming=True,
                priority=5,
                cost_tier=CostTier.LOW,
                docs_url="https://build.nvidia.com/explore/discover",
            )
        )

        # ── OpenCode Go ───────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="opencode-go",
                display_name="OpenCode Go",
                models=[
                    ModelInfo("deepseek-v4-pro", context_window=1000000, cost_tier=CostTier.MEDIUM),
                    ModelInfo("deepseek-v4-flash", context_window=1000000, cost_tier=CostTier.LOW),
                ],
                default_model="deepseek-v4-flash",
                api_key_env="OPENCODE_API_KEY",
                base_url="https://opencode.ai/zen/go/v1",
                max_context_tokens=1000000,
                supports_streaming=True,
                priority=5,
                cost_tier=CostTier.LOW,
                docs_url="https://opencode.ai",
            )
        )

        # ── Hugging Face ──────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="huggingface",
                display_name="Hugging Face",
                models=[],
                api_key_env="HF_TOKEN",
                base_url="https://api-inference.huggingface.co/v1",
                max_context_tokens=128000,
                supports_streaming=True,
                priority=4,
                cost_tier=CostTier.FREE,
                docs_url="https://huggingface.co/docs/api-inference/index",
            )
        )

        # ── Azure OpenAI ──────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="azure",
                display_name="Azure OpenAI",
                models=[
                    ModelInfo(
                        "gpt-5.4",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1050000,
                        cost_tier=CostTier.HIGH,
                    ),
                    ModelInfo(
                        "gpt-5.4-mini",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=400000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gpt-4.1",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.MEDIUM,
                    ),
                    ModelInfo(
                        "gpt-4.1-mini",
                        supports_vision=True,
                        supports_structured_output=True,
                        context_window=1000000,
                        cost_tier=CostTier.LOW,
                    ),
                ],
                api_key_env="AZURE_OPENAI_API_KEY",
                base_url="https://YOUR_RESOURCE.openai.azure.com",
                max_context_tokens=1050000,
                supports_streaming=True,
                supports_vision=True,
                priority=9,
                cost_tier=CostTier.HIGH,
                docs_url="https://learn.microsoft.com/en-us/azure/ai-services/openai/",
            )
        )

        # ── Ollama (Local) ─────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="ollama",
                display_name="Ollama (Local)",
                models=[
                    ModelInfo("llama3.1", context_window=8192, cost_tier=CostTier.FREE),
                    ModelInfo("mistral", context_window=8192, cost_tier=CostTier.FREE),
                    ModelInfo("codellama", context_window=16384, cost_tier=CostTier.FREE),
                    ModelInfo("phi4", context_window=16384, cost_tier=CostTier.FREE),
                ],
                base_url="http://localhost:11434",
                max_context_tokens=16384,
                supports_streaming=False,
                supports_tools=False,
                supports_vision=True,
                priority=5,
                cost_tier=CostTier.FREE,
                provider_type=ProviderType.LOCAL,
            )
        )

        # ── LM Studio (Local) ─────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="lmstudio",
                display_name="LM Studio (Local)",
                models=[],
                base_url="http://localhost:1234",
                max_context_tokens=8192,
                supports_streaming=False,
                supports_tools=False,
                priority=4,
                cost_tier=CostTier.FREE,
                provider_type=ProviderType.LOCAL,
                docs_url="https://lmstudio.ai/docs",
            )
        )

        # ── llama.cpp (Local) ─────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="llamacpp",
                display_name="llama.cpp",
                models=[],
                base_url="http://localhost:8080",
                max_context_tokens=8192,
                supports_streaming=True,
                supports_tools=False,
                priority=4,
                cost_tier=CostTier.FREE,
                provider_type=ProviderType.LOCAL,
                docs_url="https://github.com/ggml-org/llama.cpp",
            )
        )

        # ── vLLM (Local) ──────────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="vllm",
                display_name="vLLM",
                models=[],
                base_url="http://localhost:8000",
                max_context_tokens=32768,
                supports_streaming=True,
                supports_tools=True,
                priority=3,
                cost_tier=CostTier.FREE,
                provider_type=ProviderType.LOCAL,
                docs_url="https://docs.vllm.ai",
            )
        )

        # ── LocalAI (Local) ──────────────────────────────────────────
        self.register(
            ProviderProfile(
                name="localai",
                display_name="LocalAI",
                models=[],
                base_url="http://localhost:8080",
                max_context_tokens=8192,
                supports_streaming=True,
                supports_tools=False,
                priority=3,
                cost_tier=CostTier.FREE,
                provider_type=ProviderType.LOCAL,
                docs_url="https://localai.io",
            )
        )

    def register(self, profile: ProviderProfile) -> None:
        self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> ProviderProfile | None:
        return self._profiles.get(name)

    def list_profiles(self) -> list[ProviderProfile]:
        return sorted(self._profiles.values(), key=lambda p: -p.priority)

    def list_providers(self) -> list[str]:
        return sorted(self._profiles.keys())

    def get_models(self, provider: str) -> list[str]:
        profile = self._profiles.get(provider)
        return profile.get_model_names() if profile else []

    def add_credential(self, credential: ProviderCredential) -> None:
        self._credentials.setdefault(credential.provider, []).append(credential)

    def get_credential(self, provider: str) -> ProviderCredential | None:
        creds = self._credentials.get(provider, [])
        available = [c for c in creds if c.is_available]
        return min(available, key=lambda c: c.failure_count) if available else None

    def get_api_key(self, provider: str) -> str:
        cred = self.get_credential(provider)
        if cred and cred.api_key:
            return cred.api_key
        return resolve_api_key(provider) or ""

    def get_base_url(self, provider: str) -> str:
        cred = self.get_credential(provider)
        if cred and cred.base_url:
            return cred.base_url
        profile = self._profiles.get(provider)
        return profile.base_url if profile else ""

    def auto_detect_provider(self) -> str | None:
        for profile in sorted(self._profiles.values(), key=lambda p: -p.priority):
            if resolve_api_key(profile.name, profile.api_key_env):
                return profile.name
            if profile.provider_type == ProviderType.LOCAL and profile.base_url:
                return profile.name
        return None

    @staticmethod
    def _classify_by_http_status(status: int | None) -> FailoverReason | None:
        """Classify error by HTTP status code.

        OpenClaw pattern: classifyFailoverClassificationFromHttpStatus().
        """
        if status is None:
            return None
        if status == 402:
            return FailoverReason.BILLING
        if status == 429:
            return FailoverReason.RATE_LIMIT
        if status in (401, 403):
            return FailoverReason.AUTH
        if status == 408:
            return FailoverReason.TIMEOUT
        if status == 404:
            return FailoverReason.MODEL_NOT_FOUND
        if status == 503:
            return FailoverReason.SERVER_ERROR
        if status in (500, 502, 504):
            return FailoverReason.SERVER_ERROR
        if status == 529:
            return FailoverReason.SERVER_ERROR
        if status in (400, 422):
            return FailoverReason.AUTH
        return None

    @staticmethod
    def _classify_by_message(message: str) -> tuple[FailoverReason | None, bool]:
        """Classify error by message text patterns.

        OpenClaw pattern: classifyFailoverClassificationFromMessage() + failover-matches.ts.
        Returns (reason, should_rotate_credential).
        """
        msg = message.lower()
        if "401" in msg or "403" in msg or "unauthorized" in msg or "invalid api key" in msg:
            return FailoverReason.AUTH, True
        if "429" in msg or "rate limit" in msg or "rate_limit" in msg:
            return FailoverReason.RATE_LIMIT, False
        if "402" in msg or "billing" in msg or "quota" in msg or "insufficient" in msg:
            return FailoverReason.BILLING, True
        if "timeout" in msg or "timed out" in msg or "timedout" in msg:
            return FailoverReason.TIMEOUT, False
        if "econnreset" in msg or "econnrefused" in msg or "etimedout" in msg:
            return FailoverReason.TIMEOUT, False
        if "500" in msg or "502" in msg or "503" in msg or "504" in msg or "internal server" in msg:
            return FailoverReason.SERVER_ERROR, False
        if "overloaded" in msg or "at capacity" in msg:
            return FailoverReason.SERVER_ERROR, False
        if "context" in msg and ("too long" in msg or "overflow" in msg or "max length" in msg):
            return FailoverReason.CONTEXT_OVERFLOW, False
        if "404" in msg or "not found" in msg or "model not found" in msg:
            return FailoverReason.MODEL_NOT_FOUND, False
        return None, False

    def classify_error(
        self, provider: str, error: Exception, http_status: int | None = None
    ) -> ClassifiedError:
        """Multi-pass error classification with HTTP status + message patterns.

        OpenClaw pattern: three-route classification (status → code → message).
        """
        reason = self._classify_by_http_status(http_status)
        rotate = False
        if reason is None:
            reason, rotate = self._classify_by_message(str(error))

        if reason == FailoverReason.AUTH:
            return ClassifiedError(reason, should_rotate_credential=True, message=str(error))
        if reason == FailoverReason.RATE_LIMIT:
            return ClassifiedError(reason, message=str(error))
        if reason == FailoverReason.BILLING:
            return ClassifiedError(reason, should_rotate_credential=True, message=str(error))
        if reason == FailoverReason.TIMEOUT:
            return ClassifiedError(reason, message=str(error))
        if reason == FailoverReason.SERVER_ERROR:
            return ClassifiedError(reason, message=str(error))
        if reason == FailoverReason.CONTEXT_OVERFLOW:
            return ClassifiedError(reason, should_compress=True, message=str(error))
        if reason == FailoverReason.MODEL_NOT_FOUND:
            return ClassifiedError(reason, should_fallback=True, message=str(error))
        return ClassifiedError(FailoverReason.UNKNOWN, message=str(error))

    def record_failure(self, provider: str, reason: FailoverReason) -> None:
        self._error_counts[provider] = self._error_counts.get(provider, 0) + 1
        for cred in self._credentials.get(provider, []):
            if cred.is_available:
                cred.failure_count += 1
                if reason in (FailoverReason.AUTH, FailoverReason.BILLING):
                    cred.status = "dead"
                elif reason == FailoverReason.RATE_LIMIT:
                    cred.cooldown_until = time.time() + 60
                break

    def record_success(self, provider: str) -> None:
        self._error_counts[provider] = 0
        for cred in self._credentials.get(provider, []):
            if cred.is_available:
                cred.failure_count = 0
                cred.last_used = time.time()
                break

    def select_provider(self, preferred: str | None = None) -> tuple[str, str]:
        if preferred and preferred in self._profiles:
            profile = self._profiles[preferred]
            if self.get_api_key(preferred) or profile.base_url:
                return preferred, profile.default_model
        detected = self.auto_detect_provider()
        if detected:
            profile = self._profiles[detected]
            return detected, profile.default_model
        for profile in sorted(self._profiles.values(), key=lambda p: -p.priority):
            if self.get_api_key(profile.name) or profile.base_url:
                return profile.name, profile.default_model
        return "ollama", "llama3.1"

    def get_providers_by_capability(
        self, *, vision: bool = False, free: bool = False, local: bool = False
    ) -> list[ProviderProfile]:
        results = []
        for profile in sorted(self._profiles.values(), key=lambda p: -p.priority):
            if vision and not profile.supports_vision:
                continue
            if free and profile.cost_tier != CostTier.FREE:
                continue
            if local and profile.provider_type != ProviderType.LOCAL:
                continue
            if not local and profile.provider_type == ProviderType.LOCAL:
                continue
            results.append(profile)
        return results

    def resolve_model_id(self, provider: str, model_id: str) -> str:
        """Normalize a model ID using provider-specific aliases.

        OpenClaw pattern: provider-model-id-normalization.ts.
        Falls back to model_id if no normalization applies.
        """
        return normalize_model_id(provider, model_id)

    def stats(self) -> dict[str, Any]:
        return {
            "total_providers": len(self._profiles),
            "credentials": {p: len(c) for p, c in self._credentials.items()},
            "error_counts": dict(self._error_counts),
        }


def resolve_api_key(provider: str, env_var: str | None = None) -> str | None:
    """Resolve a provider API key from credential store → environment.

    This is the canonical key-resolution function.  All call sites that need
    a provider's API key should use this instead of ``os.getenv()`` directly.
    """
    key: str | None = None
    try:
        from .credential_store import CredentialStore  # noqa: PLC0415
        store = CredentialStore()
        key = store.retrieve(provider, "api_key")
    except Exception:
        pass
    if key:
        return key
    # Environment variable
    if not env_var:
        env_var = get_provider_env_var(provider)
    key = os.environ.get(env_var) if env_var else None
    if key:
        return key
    if provider == "gemini":
        key = os.environ.get("GOOGLE_API_KEY")
        if key:
            return key
    return None


def get_provider_env_var(provider: str) -> str:
    """Resolve the environment variable name for a provider's API key."""
    pm = ProviderManager()
    profile = pm.get_profile(provider)
    if profile and profile.api_key_env:
        return profile.api_key_env
    return f"{provider.upper()}_API_KEY"
