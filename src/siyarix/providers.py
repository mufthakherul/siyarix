# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-provider LLM abstraction with fallback and credential pooling."""

from __future__ import annotations

import enum
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

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


@dataclass
class ProviderProfile:
    name: str
    display_name: str = ""
    models: list[str] = field(default_factory=list)
    default_model: str = ""
    api_key_env: str = ""
    base_url: str = ""
    supports_streaming: bool = True
    supports_tools: bool = True
    supports_vision: bool = False
    max_tokens: int = 4096
    priority: int = 0
    fallback_models: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.display_name:
            self.display_name = self.name.title()


class ProviderManager:
    def __init__(self) -> None:
        self._profiles: dict[str, ProviderProfile] = {}
        self._credentials: dict[str, list[ProviderCredential]] = {}
        self._error_counts: dict[str, int] = {}
        self._init_default_profiles()

    def _init_default_profiles(self) -> None:
        self.register(ProviderProfile(name="openai", display_name="OpenAI",
            models=["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o1-mini", "o3-mini"],
            default_model="gpt-4o", api_key_env="OPENAI_API_KEY", supports_vision=True, priority=10))
        self.register(ProviderProfile(name="anthropic", display_name="Anthropic",
            models=["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-opus-4-20250514"],
            default_model="claude-sonnet-4-20250514", api_key_env="ANTHROPIC_API_KEY", supports_vision=True, priority=10))
        self.register(ProviderProfile(name="gemini", display_name="Google Gemini",
            models=["gemini-2.5-pro-preview-05-06", "gemini-2.5-flash-preview-04-17", "gemini-2.0-flash"],
            default_model="gemini-2.0-flash", api_key_env="GEMINI_API_KEY", supports_vision=True, priority=9))
        self.register(ProviderProfile(name="groq", display_name="Groq",
            models=["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
            default_model="llama-3.3-70b-versatile", api_key_env="GROQ_API_KEY", priority=7))
        self.register(ProviderProfile(name="together", display_name="Together AI",
            models=["mistralai/Mixtral-8x7B-Instruct-v0.1", "meta-llama/Llama-3-70b-chat-hf"],
            default_model="meta-llama/Llama-3-70b-chat-hf", api_key_env="TOGETHER_API_KEY", priority=6))
        self.register(ProviderProfile(name="ollama", display_name="Ollama (Local)",
            models=["llama3.1", "mistral", "codellama", "phi3"],
            default_model="llama3.1", base_url="http://localhost:11434", supports_streaming=False, priority=5))
        self.register(ProviderProfile(name="openrouter", display_name="OpenRouter",
            models=["nvidia/nemotron-3-super-120b-a12b:free", "meta-llama/llama-3.3-70b-instruct:free"],
            default_model="meta-llama/llama-3.3-70b-instruct:free", api_key_env="OPENROUTER_API_KEY", priority=6))
        self.register(ProviderProfile(name="lmstudio", display_name="LM Studio (Local)",
            models=[], default_model="", base_url="http://localhost:1234", supports_streaming=False, priority=4))

    def register(self, profile: ProviderProfile) -> None:
        self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> ProviderProfile | None:
        return self._profiles.get(name)

    def list_profiles(self) -> list[ProviderProfile]:
        return sorted(self._profiles.values(), key=lambda p: -p.priority)

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
        profile = self._profiles.get(provider)
        return os.getenv(profile.api_key_env, "") if profile and profile.api_key_env else ""

    def get_base_url(self, provider: str) -> str:
        cred = self.get_credential(provider)
        if cred and cred.base_url:
            return cred.base_url
        profile = self._profiles.get(provider)
        return profile.base_url if profile else ""

    def auto_detect_provider(self) -> str | None:
        for profile in sorted(self._profiles.values(), key=lambda p: -p.priority):
            if profile.api_key_env and os.getenv(profile.api_key_env):
                return profile.name
            if profile.base_url and profile.name in ("ollama", "lmstudio"):
                return profile.name
        return None

    def classify_error(self, provider: str, error: Exception) -> ClassifiedError:
        error_str = str(error).lower()
        if "401" in error_str or "403" in error_str or "unauthorized" in error_str:
            return ClassifiedError(FailoverReason.AUTH, should_rotate_credential=True, message=str(error))
        if "429" in error_str or "rate" in error_str:
            return ClassifiedError(FailoverReason.RATE_LIMIT, message=str(error))
        if "402" in error_str or "billing" in error_str or "quota" in error_str:
            return ClassifiedError(FailoverReason.BILLING, should_rotate_credential=True, message=str(error))
        if "timeout" in error_str or "timed out" in error_str:
            return ClassifiedError(FailoverReason.TIMEOUT, message=str(error))
        if "500" in error_str or "502" in error_str or "503" in error_str:
            return ClassifiedError(FailoverReason.SERVER_ERROR, message=str(error))
        if "context" in error_str and ("too long" in error_str or "overflow" in error_str):
            return ClassifiedError(FailoverReason.CONTEXT_OVERFLOW, should_compress=True, message=str(error))
        if "404" in error_str or "not found" in error_str:
            return ClassifiedError(FailoverReason.MODEL_NOT_FOUND, should_fallback=True, message=str(error))
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

    def stats(self) -> dict[str, Any]:
        return {
            "total_providers": len(self._profiles),
            "credentials": {p: len(c) for p, c in self._credentials.items()},
            "error_counts": dict(self._error_counts),
        }
