from __future__ import annotations
import os
import time
from typing import Any
from .types import (
    ProviderProfile,
    ProviderCredential,
    FailoverReason,
    ClassifiedError,
    ProviderType,
    CostTier,
)
from ..model_aliases import normalize_model_id


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
        from .profiles import register_all_profiles

        register_all_profiles(self)

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
