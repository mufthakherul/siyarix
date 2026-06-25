from __future__ import annotations

import time


from siyarix.providers.types import (
    ClassifiedError,
    CostTier,
    FailoverReason,
    ModelInfo,
    ProviderCredential,
    ProviderProfile,
    ProviderType,
)


class TestFailoverReason:
    def test_enum_values(self):
        assert FailoverReason.AUTH.value == "auth"
        assert FailoverReason.RATE_LIMIT.value == "rate_limit"
        assert FailoverReason.BILLING.value == "billing"
        assert FailoverReason.TIMEOUT.value == "timeout"
        assert FailoverReason.SERVER_ERROR.value == "server_error"
        assert FailoverReason.CONTEXT_OVERFLOW.value == "context_overflow"
        assert FailoverReason.MODEL_NOT_FOUND.value == "model_not_found"
        assert FailoverReason.UNKNOWN.value == "unknown"

    def test_enum_members(self):
        assert len(FailoverReason) == 8


class TestClassifiedError:
    def test_defaults(self):
        err = ClassifiedError(reason=FailoverReason.AUTH)
        assert err.reason == FailoverReason.AUTH
        assert err.retryable is True
        assert err.should_rotate_credential is False
        assert err.should_fallback is False
        assert err.should_compress is False
        assert err.message == ""

    def test_custom_values(self):
        err = ClassifiedError(
            reason=FailoverReason.RATE_LIMIT,
            retryable=False,
            should_rotate_credential=True,
            should_fallback=True,
            should_compress=True,
            message="custom error",
        )
        assert err.reason == FailoverReason.RATE_LIMIT
        assert err.retryable is False
        assert err.should_rotate_credential is True
        assert err.should_fallback is True
        assert err.should_compress is True
        assert err.message == "custom error"


class TestProviderCredential:
    def test_defaults(self):
        cred = ProviderCredential(provider="openai")
        assert cred.provider == "openai"
        assert cred.api_key == ""
        assert cred.base_url == ""
        assert cred.status == "active"
        assert cred.cooldown_until == 0.0
        assert cred.failure_count == 0
        assert cred.last_used == 0.0

    def test_is_available_dead_status(self):
        cred = ProviderCredential(provider="openai", api_key="sk-abc", status="dead")
        assert cred.is_available is False

    def test_is_available_cooldown(self):
        cred = ProviderCredential(
            provider="openai", api_key="sk-abc", cooldown_until=time.time() + 100
        )
        assert cred.is_available is False

    def test_is_available_no_key_no_url(self):
        cred = ProviderCredential(provider="openai")
        assert cred.is_available is False

    def test_is_available_with_key(self):
        cred = ProviderCredential(provider="openai", api_key="sk-abc")
        assert cred.is_available is True

    def test_is_available_with_base_url(self):
        cred = ProviderCredential(provider="local", base_url="http://localhost:8080")
        assert cred.is_available is True

    def test_is_available_expired_cooldown(self):
        cred = ProviderCredential(
            provider="openai", api_key="sk-abc", cooldown_until=time.time() - 1
        )
        assert cred.is_available is True


class TestCostTier:
    def test_enum_values(self):
        assert CostTier.FREE.value == "free"
        assert CostTier.LOW.value == "low"
        assert CostTier.MEDIUM.value == "medium"
        assert CostTier.HIGH.value == "high"

    def test_sort_key(self):
        assert CostTier.FREE.sort_key == 0
        assert CostTier.LOW.sort_key == 1
        assert CostTier.MEDIUM.sort_key == 2
        assert CostTier.HIGH.sort_key == 3

    def test_sort_key_unknown_fallback(self):
        tier = CostTier.FREE
        object.__setattr__(tier, "_value_", "unknown")
        assert tier.sort_key == 99


class TestProviderType:
    def test_enum_values(self):
        assert ProviderType.CLOUD.value == "cloud"
        assert ProviderType.LOCAL.value == "local"


class TestModelInfo:
    def test_defaults(self):
        m = ModelInfo(name="gpt-4")
        assert m.name == "gpt-4"
        assert m.supports_vision is False
        assert m.supports_tools is True
        assert m.supports_structured_output is False
        assert m.supports_function_calling is True
        assert m.context_window == 8192
        assert m.cost_tier == CostTier.MEDIUM

    def test_custom_values(self):
        m = ModelInfo(
            name="claude-3",
            supports_vision=True,
            supports_tools=False,
            supports_structured_output=True,
            supports_function_calling=False,
            context_window=200000,
            cost_tier=CostTier.HIGH,
        )
        assert m.supports_vision is True
        assert m.supports_tools is False
        assert m.supports_structured_output is True
        assert m.supports_function_calling is False
        assert m.context_window == 200000
        assert m.cost_tier == CostTier.HIGH


class TestProviderProfile:
    def test_minimal_profile(self):
        p = ProviderProfile(name="test_provider")
        assert p.name == "test_provider"
        assert p.display_name == "Test_Provider"
        assert p.default_model == ""
        assert p.models == []
        assert p.fallback_models == []

    def test_display_name_from_name(self):
        p = ProviderProfile(name="openai")
        assert p.display_name == "Openai"

    def test_explicit_display_name(self):
        p = ProviderProfile(name="openai", display_name="OpenAI")
        assert p.display_name == "OpenAI"

    def test_default_model_from_first_model(self):
        p = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5")],
        )
        assert p.default_model == "gpt-4"

    def test_explicit_default_model(self):
        p = ProviderProfile(
            name="test",
            default_model="gpt-3.5",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5")],
        )
        assert p.default_model == "gpt-3.5"

    def test_fallback_models_from_models(self):
        p = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5"), ModelInfo(name="gpt-3")],
        )
        assert p.fallback_models == ["gpt-3.5", "gpt-3"]

    def test_fallback_models_single_model(self):
        p = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4")],
        )
        assert p.fallback_models == []

    def test_explicit_fallback_models(self):
        p = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5")],
            fallback_models=["custom-fallback"],
        )
        assert p.fallback_models == ["custom-fallback"]

    def test_supports_from_models(self):
        p = ProviderProfile(
            name="test",
            models=[
                ModelInfo(
                    name="vision-model",
                    supports_vision=True,
                    supports_tools=False,
                    supports_structured_output=True,
                ),
                ModelInfo(
                    name="tool-model",
                    supports_vision=False,
                    supports_tools=True,
                    supports_structured_output=False,
                ),
            ],
        )
        assert p.supports_vision is True
        assert p.supports_tools is True
        assert p.supports_structured_output is True

    def test_supports_from_models_all_false(self):
        p = ProviderProfile(
            name="test",
            models=[
                ModelInfo(
                    name="m1",
                    supports_vision=False,
                    supports_tools=False,
                    supports_structured_output=False,
                ),
            ],
        )
        assert p.supports_vision is False
        assert p.supports_tools is False
        assert p.supports_structured_output is False

    def test_get_model_names(self):
        p = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5")],
        )
        assert p.get_model_names() == ["gpt-4", "gpt-3.5"]

    def test_get_model_names_empty(self):
        p = ProviderProfile(name="test")
        assert p.get_model_names() == []

    def test_default_fields(self):
        p = ProviderProfile(name="test")
        assert p.supports_streaming is True
        assert p.supports_tools is True
        assert p.supports_vision is False
        assert p.supports_structured_output is False
        assert p.sdk_dependency == ""
        assert p.max_tokens == 4096
        assert p.max_context_tokens == 128000
        assert p.priority == 0
        assert p.cost_tier == CostTier.MEDIUM
        assert p.provider_type == ProviderType.CLOUD
        assert p.docs_url == ""
        assert p.api_key_env == ""
        assert p.base_url == ""
