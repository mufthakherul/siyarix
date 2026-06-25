from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.providers.manager import (
    ProviderManager,
    get_provider_env_var,
    resolve_api_key,
)
from siyarix.providers.types import (
    CostTier,
    FailoverReason,
    ProviderCredential,
    ProviderProfile,
    ProviderType,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    ProviderManager._instance = None
    ProviderManager._instance_lock = None
    yield


@pytest.fixture
def mock_profiles():
    return [
        ProviderProfile(
            name="openai", base_url="", provider_type=ProviderType.CLOUD, priority=0, models=[]
        ),
        ProviderProfile(
            name="anthropic", base_url="", provider_type=ProviderType.CLOUD, priority=1, models=[]
        ),
        ProviderProfile(
            name="ollama",
            base_url="http://localhost:11434",
            provider_type=ProviderType.LOCAL,
            priority=2,
            models=[],
        ),
    ]


@pytest.fixture
def manager(mock_profiles):
    with patch.object(ProviderManager, "_init_default_profiles") as mock_init:
        pm = ProviderManager()
        for p in mock_profiles:
            pm.register(p)
        return pm


@pytest.fixture
def state_manager_mock():
    with patch("siyarix.providers.manager.ProviderStateManager") as m:
        yield m


# ---------------------------------------------------------------------------
# Singleton pattern
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_instance_creates(self):
        pm = ProviderManager.get_instance()
        assert isinstance(pm, ProviderManager)

    def test_get_instance_returns_same(self):
        pm1 = ProviderManager.get_instance()
        pm2 = ProviderManager.get_instance()
        assert pm1 is pm2

    def test_init_raises_if_instance_exists(self):
        ProviderManager.get_instance()
        with pytest.raises(RuntimeError, match="singleton"):
            ProviderManager()

    def test_get_instance_thread_safe(self, monkeypatch):
        ProviderManager._instance = None
        ProviderManager._instance_lock = None
        lock = MagicMock()
        with patch("threading.Lock", return_value=lock):
            pm = ProviderManager.get_instance()
            assert isinstance(pm, ProviderManager)

    def test_get_instance_when_lock_already_exists(self):
        import threading

        ProviderManager._instance = None
        ProviderManager._instance_lock = threading.Lock()
        pm = ProviderManager.get_instance()
        assert isinstance(pm, ProviderManager)

    def test_get_instance_double_check_in_lock(self):
        class SetInstanceLock:
            def __enter__(self2):
                ProviderManager._instance = ProviderManager.__new__(ProviderManager)
                ProviderManager._instance._profiles = {}
                ProviderManager._instance._credentials = {}
                ProviderManager._instance._error_counts = {}
                from unittest.mock import MagicMock

                ProviderManager._instance._state_manager = MagicMock()
                return self2

            def __exit__(self2, *args):
                pass

        ProviderManager._instance = None
        ProviderManager._instance_lock = SetInstanceLock()
        pm = ProviderManager.get_instance()
        assert isinstance(pm, ProviderManager)


# ---------------------------------------------------------------------------
# Registration and profile methods
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register(self, manager):
        profile = ProviderProfile(name="custom", models=[])
        manager.register(profile)
        assert manager.get_profile("custom") is profile

    def test_get_profile_nonexistent(self, manager):
        assert manager.get_profile("nonexistent") is None

    def test_list_providers(self, manager):
        names = manager.list_providers()
        assert names == ["anthropic", "ollama", "openai"]

    def test_list_profiles_sorted_by_settings_priority(self, manager):
        settings_mock = MagicMock()
        settings_mock.get.return_value = ["anthropic", "openai"]
        with patch("siyarix.providers.manager.SettingsStore", return_value=settings_mock):
            profiles = manager.list_profiles()
            assert [p.name for p in profiles] == ["anthropic", "openai", "ollama"]

    def test_list_profiles_priority_as_string(self, manager):
        settings_mock = MagicMock()
        settings_mock.get.return_value = "anthropic, openai"
        with patch("siyarix.providers.manager.SettingsStore", return_value=settings_mock):
            profiles = manager.list_profiles()
            assert [p.name for p in profiles] == ["anthropic", "openai", "ollama"]

    def test_list_profiles_fallback_to_priority_field(self, manager):
        settings_mock = MagicMock()
        settings_mock.get.return_value = []
        with patch("siyarix.providers.manager.SettingsStore", return_value=settings_mock):
            profiles = manager.list_profiles()
            names = [p.name for p in profiles]
            assert names == ["ollama", "anthropic", "openai"]

    def test_get_models_valid(self, manager):
        from siyarix.providers.types import ModelInfo

        profile = ProviderProfile(
            name="test",
            models=[ModelInfo(name="gpt-4"), ModelInfo(name="gpt-3.5")],
        )
        manager.register(profile)
        assert manager.get_models("test") == ["gpt-4", "gpt-3.5"]

    def test_get_models_invalid(self, manager):
        assert manager.get_models("nonexistent") == []


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


class TestCredentials:
    def test_add_credential(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123")
        manager.add_credential(cred)
        assert "openai" in manager._credentials
        assert cred in manager._credentials["openai"]

    def test_add_credential_multiple(self, manager):
        cred1 = ProviderCredential(provider="openai", api_key="sk-123")
        cred2 = ProviderCredential(provider="openai", api_key="sk-456")
        manager.add_credential(cred1)
        manager.add_credential(cred2)
        assert len(manager._credentials["openai"]) == 2

    def test_get_credential_returns_available_with_lowest_failure(self, manager):
        c1 = ProviderCredential(provider="openai", api_key="sk-123", failure_count=5)
        c2 = ProviderCredential(provider="openai", api_key="sk-456", failure_count=1)
        manager.add_credential(c1)
        manager.add_credential(c2)
        result = manager.get_credential("openai")
        assert result is c2

    def test_get_credential_filters_dead(self, manager):
        c1 = ProviderCredential(provider="openai", api_key="sk-123", status="dead")
        c2 = ProviderCredential(provider="openai", api_key="sk-456")
        manager.add_credential(c1)
        manager.add_credential(c2)
        result = manager.get_credential("openai")
        assert result is c2

    def test_get_credential_no_available(self, manager):
        c1 = ProviderCredential(provider="openai", status="dead")
        manager.add_credential(c1)
        result = manager.get_credential("openai")
        assert result is None

    def test_get_credential_no_credentials(self, manager):
        assert manager.get_credential("openai") is None

    def test_get_api_key_from_credential(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-cred")
        manager.add_credential(cred)
        with patch(
            "siyarix.providers.manager.resolve_api_key", return_value="sk-env"
        ) as mock_resolve:
            key = manager.get_api_key("openai")
            assert key == "sk-cred"
            mock_resolve.assert_not_called()

    def test_get_api_key_fallback_to_resolve(self, manager):
        cred = ProviderCredential(provider="openai", api_key="")
        manager.add_credential(cred)
        with patch("siyarix.providers.manager.resolve_api_key", return_value="sk-resolved"):
            key = manager.get_api_key("openai")
            assert key == "sk-resolved"

    def test_get_api_key_empty(self, manager):
        with patch("siyarix.providers.manager.resolve_api_key", return_value=None):
            key = manager.get_api_key("openai")
            assert key == ""

    def test_get_base_url_from_credential(self, manager):
        profile = ProviderProfile(name="test", base_url="http://profile.url", models=[])
        manager.register(profile)
        cred = ProviderCredential(provider="test", base_url="http://cred.url")
        manager.add_credential(cred)
        assert manager.get_base_url("test") == "http://cred.url"

    def test_get_base_url_from_profile(self, manager):
        profile = ProviderProfile(name="test", base_url="http://profile.url", models=[])
        manager.register(profile)
        cred = ProviderCredential(provider="test", base_url="")
        manager.add_credential(cred)
        assert manager.get_base_url("test") == "http://profile.url"

    def test_get_base_url_empty(self, manager):
        assert manager.get_base_url("nonexistent") == ""


# ---------------------------------------------------------------------------
# Auto-detect
# ---------------------------------------------------------------------------


class TestAutoDetect:
    def test_remote_with_api_key(self, manager):
        profile = ProviderProfile(name="test", provider_type=ProviderType.CLOUD, models=[])
        manager.register(profile)
        with patch.object(manager, "list_profiles", return_value=[profile]):
            with patch("siyarix.providers.manager.resolve_api_key", return_value="sk-key"):
                assert manager.auto_detect_provider() == "test"

    def test_local_with_base_url(self, manager):
        profile = ProviderProfile(
            name="local-llm",
            base_url="http://localhost:8080",
            provider_type=ProviderType.LOCAL,
            models=[],
        )
        manager.register(profile)
        with patch.object(manager, "list_profiles", return_value=[profile]):
            with patch("siyarix.providers.manager.resolve_api_key", return_value=None):
                assert manager.auto_detect_provider() == "local-llm"

    def test_no_match(self, manager):
        profile = ProviderProfile(name="test", provider_type=ProviderType.CLOUD, models=[])
        manager.register(profile)
        with patch.object(manager, "list_profiles", return_value=[profile]):
            with patch("siyarix.providers.manager.resolve_api_key", return_value=None):
                assert manager.auto_detect_provider() is None


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------


class TestClassifyByHttpStatus:
    def test_none(self):
        assert ProviderManager._classify_by_http_status(None) is None

    def test_402(self):
        assert ProviderManager._classify_by_http_status(402) == FailoverReason.BILLING

    def test_429(self):
        assert ProviderManager._classify_by_http_status(429) == FailoverReason.RATE_LIMIT

    def test_401(self):
        assert ProviderManager._classify_by_http_status(401) == FailoverReason.AUTH

    def test_403(self):
        assert ProviderManager._classify_by_http_status(403) == FailoverReason.AUTH

    def test_408(self):
        assert ProviderManager._classify_by_http_status(408) == FailoverReason.TIMEOUT

    def test_404(self):
        assert ProviderManager._classify_by_http_status(404) == FailoverReason.MODEL_NOT_FOUND

    def test_503(self):
        assert ProviderManager._classify_by_http_status(503) == FailoverReason.SERVER_ERROR

    def test_500(self):
        assert ProviderManager._classify_by_http_status(500) == FailoverReason.SERVER_ERROR

    def test_502(self):
        assert ProviderManager._classify_by_http_status(502) == FailoverReason.SERVER_ERROR

    def test_504(self):
        assert ProviderManager._classify_by_http_status(504) == FailoverReason.SERVER_ERROR

    def test_529(self):
        assert ProviderManager._classify_by_http_status(529) == FailoverReason.SERVER_ERROR

    def test_400(self):
        assert ProviderManager._classify_by_http_status(400) == FailoverReason.AUTH

    def test_422(self):
        assert ProviderManager._classify_by_http_status(422) == FailoverReason.AUTH

    def test_other(self):
        assert ProviderManager._classify_by_http_status(418) is None


class TestClassifyByMessage:
    def test_auth_401(self):
        reason, rotate = ProviderManager._classify_by_message("401 unauthorized")
        assert reason == FailoverReason.AUTH
        assert rotate is True

    def test_auth_403(self):
        reason, rotate = ProviderManager._classify_by_message("403 forbidden")
        assert reason == FailoverReason.AUTH
        assert rotate is True

    def test_auth_unauthorized(self):
        reason, rotate = ProviderManager._classify_by_message("Unauthorized access")
        assert reason == FailoverReason.AUTH
        assert rotate is True

    def test_auth_invalid_api_key(self):
        reason, rotate = ProviderManager._classify_by_message("Invalid API key")
        assert reason == FailoverReason.AUTH
        assert rotate is True

    def test_rate_limit_429(self):
        reason, rotate = ProviderManager._classify_by_message("429 too many requests")
        assert reason == FailoverReason.RATE_LIMIT
        assert rotate is False

    def test_rate_limit_text(self):
        reason, rotate = ProviderManager._classify_by_message("rate limit exceeded")
        assert reason == FailoverReason.RATE_LIMIT
        assert rotate is False

    def test_rate_limit_underscore(self):
        reason, rotate = ProviderManager._classify_by_message("rate_limit_exceeded")
        assert reason == FailoverReason.RATE_LIMIT
        assert rotate is False

    def test_billing_402(self):
        reason, rotate = ProviderManager._classify_by_message("402 payment required")
        assert reason == FailoverReason.BILLING
        assert rotate is True

    def test_billing_text(self):
        reason, rotate = ProviderManager._classify_by_message("billing issue")
        assert reason == FailoverReason.BILLING
        assert rotate is True

    def test_billing_quota(self):
        reason, rotate = ProviderManager._classify_by_message("quota exceeded")
        assert reason == FailoverReason.BILLING
        assert rotate is True

    def test_billing_insufficient(self):
        reason, rotate = ProviderManager._classify_by_message("insufficient funds")
        assert reason == FailoverReason.BILLING
        assert rotate is True

    def test_timeout_text(self):
        reason, rotate = ProviderManager._classify_by_message("request timeout")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_timeout_timed_out(self):
        reason, rotate = ProviderManager._classify_by_message("timed out")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_timeout_timedout(self):
        reason, rotate = ProviderManager._classify_by_message("timedout")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_connection_econnreset(self):
        reason, rotate = ProviderManager._classify_by_message("econnreset")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_connection_econnrefused(self):
        reason, rotate = ProviderManager._classify_by_message("econnrefused")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_connection_etimedout(self):
        reason, rotate = ProviderManager._classify_by_message("etimedout")
        assert reason == FailoverReason.TIMEOUT
        assert rotate is False

    def test_server_error_500(self):
        reason, rotate = ProviderManager._classify_by_message("500 internal server error")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_502(self):
        reason, rotate = ProviderManager._classify_by_message("502 bad gateway")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_503(self):
        reason, rotate = ProviderManager._classify_by_message("503 service unavailable")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_504(self):
        reason, rotate = ProviderManager._classify_by_message("504 gateway error")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_internal_server(self):
        reason, rotate = ProviderManager._classify_by_message("internal server error")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_overloaded(self):
        reason, rotate = ProviderManager._classify_by_message("overloaded")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_server_error_at_capacity(self):
        reason, rotate = ProviderManager._classify_by_message("at capacity")
        assert reason == FailoverReason.SERVER_ERROR
        assert rotate is False

    def test_context_overflow(self):
        reason, rotate = ProviderManager._classify_by_message("context too long")
        assert reason == FailoverReason.CONTEXT_OVERFLOW
        assert rotate is False

    def test_context_overflow_alternative(self):
        reason, rotate = ProviderManager._classify_by_message("context overflow")
        assert reason == FailoverReason.CONTEXT_OVERFLOW
        assert rotate is False

    def test_context_max_length(self):
        reason, rotate = ProviderManager._classify_by_message("context max length exceeded")
        assert reason == FailoverReason.CONTEXT_OVERFLOW
        assert rotate is False

    def test_context_overflow_with_all_keywords(self):
        reason, rotate = ProviderManager._classify_by_message(
            "context too long overflow max length"
        )
        assert reason == FailoverReason.CONTEXT_OVERFLOW
        assert rotate is False

    def test_context_without_too_long(self):
        reason, rotate = ProviderManager._classify_by_message("some context thing")
        assert reason is None
        assert rotate is False

    def test_model_not_found_404(self):
        reason, rotate = ProviderManager._classify_by_message("404 not found")
        assert reason == FailoverReason.MODEL_NOT_FOUND
        assert rotate is False

    def test_model_not_found_text(self):
        reason, rotate = ProviderManager._classify_by_message("model not found")
        assert reason == FailoverReason.MODEL_NOT_FOUND
        assert rotate is False

    def test_model_not_found_not_found(self):
        reason, rotate = ProviderManager._classify_by_message("not found")
        assert reason == FailoverReason.MODEL_NOT_FOUND
        assert rotate is False

    def test_unknown(self):
        reason, rotate = ProviderManager._classify_by_message("some random error")
        assert reason is None
        assert rotate is False


class TestClassifyError:
    def test_http_status_wins(self, manager):
        err = Exception("rate limit")
        result = manager.classify_error("openai", err, http_status=402)
        assert result.reason == FailoverReason.BILLING

    def test_message_fallback(self, manager):
        err = Exception("rate limit exceeded")
        result = manager.classify_error("openai", err, http_status=None)
        assert result.reason == FailoverReason.RATE_LIMIT

    def test_message_fallback_when_status_unknown(self, manager):
        err = Exception("rate limit exceeded")
        result = manager.classify_error("openai", err, http_status=418)
        assert result.reason == FailoverReason.RATE_LIMIT

    def test_auth_result(self, manager):
        err = Exception("unauthorized")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.AUTH
        assert result.should_rotate_credential is True

    def test_rate_limit_result(self, manager):
        err = Exception("rate limit")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.RATE_LIMIT
        assert result.should_rotate_credential is False

    def test_billing_result(self, manager):
        err = Exception("quota exceeded")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.BILLING
        assert result.should_rotate_credential is True

    def test_timeout_result(self, manager):
        err = Exception("timeout")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.TIMEOUT
        assert result.should_rotate_credential is False

    def test_server_error_result(self, manager):
        err = Exception("internal server error")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.SERVER_ERROR
        assert result.should_compress is False

    def test_context_overflow_result(self, manager):
        err = Exception("context too long")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.CONTEXT_OVERFLOW
        assert result.should_compress is True

    def test_model_not_found_result(self, manager):
        err = Exception("model not found")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.MODEL_NOT_FOUND
        assert result.should_fallback is True

    def test_unknown_result(self, manager):
        err = Exception("weird error")
        result = manager.classify_error("openai", err)
        assert result.reason == FailoverReason.UNKNOWN


# ---------------------------------------------------------------------------
# Failure and success recording
# ---------------------------------------------------------------------------


class TestRecordFailure:
    def test_increments_error_counts(self, manager):
        manager.record_failure("openai", FailoverReason.SERVER_ERROR)
        assert manager._error_counts["openai"] == 1

    def test_increments_existing_error_counts(self, manager):
        manager._error_counts["openai"] = 3
        manager.record_failure("openai", FailoverReason.SERVER_ERROR)
        assert manager._error_counts["openai"] == 4

    def test_sets_credential_dead_on_auth(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123")
        manager.add_credential(cred)
        manager.record_failure("openai", FailoverReason.AUTH)
        assert cred.status == "dead"

    def test_sets_credential_dead_on_billing(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123")
        manager.add_credential(cred)
        manager.record_failure("openai", FailoverReason.BILLING)
        assert cred.status == "dead"

    def test_rate_limit_backoff(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=0)
        manager.add_credential(cred)
        before = time.time()
        manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        expected_backoff = min(3600, 10 * (2**1))
        assert cred.cooldown_until >= before + expected_backoff - 1
        assert cred.failure_count == 1

    def test_timeout_backoff(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=0)
        manager.add_credential(cred)
        before = time.time()
        manager.record_failure("openai", FailoverReason.TIMEOUT)
        expected_backoff = min(300, 5 * (2**1))
        assert cred.cooldown_until >= before + expected_backoff - 1
        assert cred.failure_count == 1

    def test_server_error_backoff(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=0)
        manager.add_credential(cred)
        before = time.time()
        manager.record_failure("openai", FailoverReason.SERVER_ERROR)
        expected_backoff = min(300, 5 * (2**1))
        assert cred.cooldown_until >= before + expected_backoff - 1

    def test_rate_limit_backoff_capped(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=20)
        manager.add_credential(cred)
        before = time.time()
        manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        assert cred.cooldown_until >= before + 3600 - 1

    def test_timeout_backoff_capped(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=20)
        manager.add_credential(cred)
        before = time.time()
        manager.record_failure("openai", FailoverReason.TIMEOUT)
        assert cred.cooldown_until >= before + 300 - 1

    def test_only_updates_first_available_credential(self, manager):
        c1 = ProviderCredential(provider="openai", api_key="sk-123")
        c2 = ProviderCredential(provider="openai", api_key="sk-456")
        manager.add_credential(c1)
        manager.add_credential(c2)
        manager.record_failure("openai", FailoverReason.AUTH)
        assert c1.status == "dead"
        assert c2.status == "active"

    def test_skips_non_available_credentials(self, manager):
        c1 = ProviderCredential(provider="openai", api_key="sk-123", status="dead")
        c2 = ProviderCredential(provider="openai", api_key="sk-456")
        manager.add_credential(c1)
        manager.add_credential(c2)
        manager.record_failure("openai", FailoverReason.AUTH)
        assert c1.status == "dead"
        assert c2.status == "dead"

    def test_unknown_reason_no_backoff(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123")
        manager.add_credential(cred)
        manager.record_failure("openai", FailoverReason.CONTEXT_OVERFLOW)
        assert cred.failure_count == 1
        assert cred.status == "active"
        assert cred.cooldown_until == 0.0

    def test_calls_state_manager(self, manager):
        with patch.object(manager._state_manager, "record_failure") as mock_rec:
            manager.record_failure("openai", FailoverReason.TIMEOUT)
            mock_rec.assert_called_once_with("openai", FailoverReason.TIMEOUT)


class TestRecordSuccess:
    def test_resets_error_counts(self, manager):
        manager._error_counts["openai"] = 5
        manager.record_success("openai")
        assert manager._error_counts["openai"] == 0

    def test_resets_credential_failure_count(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123", failure_count=5)
        manager.add_credential(cred)
        manager.record_success("openai")
        assert cred.failure_count == 0

    def test_updates_last_used(self, manager):
        cred = ProviderCredential(provider="openai", api_key="sk-123")
        manager.add_credential(cred)
        before = time.time()
        manager.record_success("openai")
        assert cred.last_used >= before

    def test_only_updates_first_available(self, manager):
        c1 = ProviderCredential(provider="openai", api_key="sk-123", failure_count=3)
        c2 = ProviderCredential(provider="openai", api_key="sk-456", failure_count=2)
        manager.add_credential(c1)
        manager.add_credential(c2)
        manager.record_success("openai")
        assert c1.failure_count == 0
        assert c2.failure_count == 2

    def test_skips_dead_credential_in_success(self, manager):
        c1 = ProviderCredential(provider="openai", status="dead", failure_count=3)
        c2 = ProviderCredential(provider="openai", api_key="sk-456", failure_count=2)
        manager.add_credential(c1)
        manager.add_credential(c2)
        manager.record_success("openai")
        assert c1.failure_count == 3
        assert c2.failure_count == 0

    def test_calls_state_manager(self, manager):
        with patch.object(manager._state_manager, "record_success") as mock_rec:
            manager.record_success("openai")
            mock_rec.assert_called_once_with("openai")


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------


class TestSelectProvider:
    def test_preferred_available(self, manager, mock_profiles):
        with patch.object(manager, "get_api_key", return_value="sk-key"):
            provider, model = manager.select_provider(preferred="openai")
            assert provider == "openai"

    def test_preferred_not_in_profiles(self, manager):
        ollama = ProviderProfile(
            name="ollama",
            base_url="http://localhost:11434",
            provider_type=ProviderType.LOCAL,
            priority=2,
            models=[],
        )
        with patch.object(manager, "get_api_key", return_value=""):
            with patch.object(manager, "auto_detect_provider", return_value=None):
                with patch.object(manager, "list_profiles", return_value=[ollama]):
                    provider, model = manager.select_provider(preferred="nonexistent")
                    assert provider == "ollama"

    def test_preferred_without_key_but_has_base_url(self, manager):
        profile = ProviderProfile(name="ollama", base_url="http://localhost:11434", models=[])
        manager.register(profile)
        provider, model = manager.select_provider(preferred="ollama")
        assert provider == "ollama"

    def test_preferred_no_key_no_base_url_falls_through(self, manager):
        with patch.object(manager, "get_api_key", return_value=""):
            with patch.object(manager, "auto_detect_provider", return_value="anthropic"):
                provider, model = manager.select_provider(preferred="openai")
                assert provider == "anthropic"

    def test_auto_detect_success(self, manager):
        with patch.object(manager, "get_api_key", return_value=""):
            with patch.object(manager, "auto_detect_provider", return_value="anthropic"):
                provider, model = manager.select_provider()
                assert provider == "anthropic"

    def test_fallback_to_first_available(self, manager):
        with patch.object(
            manager, "get_api_key", side_effect=lambda p: "sk-key" if p == "openai" else ""
        ):
            with patch.object(manager, "auto_detect_provider", return_value=None):
                with patch.object(
                    manager, "list_profiles", return_value=manager._profiles.values()
                ):
                    provider, model = manager.select_provider()
                    assert provider == "openai"

    def test_for_loop_continues_when_no_key_or_base_url(self):
        with patch.object(ProviderManager, "_init_default_profiles"):
            mgr = ProviderManager()
        empty1 = ProviderProfile(name="empty1", base_url="", models=[])
        empty2 = ProviderProfile(name="empty2", base_url="", models=[])
        mgr.register(empty1)
        mgr.register(empty2)
        with patch.object(mgr, "get_api_key", return_value=""):
            with patch.object(mgr, "auto_detect_provider", return_value=None):
                provider, model = mgr.select_provider()
                assert provider == "ollama"
                assert model == "llama3.1"

    def test_ultimate_fallback_ollama(self, manager):
        with patch.object(manager, "get_api_key", return_value=""):
            with patch.object(manager, "auto_detect_provider", return_value=None):
                with patch.object(manager, "list_profiles", return_value=[]):
                    provider, model = manager.select_provider()
                    assert provider == "ollama"
                    assert model == "llama3.1"


# ---------------------------------------------------------------------------
# Capability filtering
# ---------------------------------------------------------------------------


class TestGetProvidersByCapability:
    @pytest.fixture
    def cap_manager(self):
        with patch.object(ProviderManager, "_init_default_profiles"):
            pm = ProviderManager()
            return pm

    def test_vision_filter(self, cap_manager):
        p1 = ProviderProfile(name="vision_provider", supports_vision=True, models=[])
        p2 = ProviderProfile(name="no_vision", supports_vision=False, models=[])
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability(vision=True)
        assert len(result) == 1
        assert result[0].name == "vision_provider"

    def test_free_filter(self, cap_manager):
        p1 = ProviderProfile(name="free_provider", cost_tier=CostTier.FREE, models=[])
        p2 = ProviderProfile(name="paid_provider", cost_tier=CostTier.HIGH, models=[])
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability(free=True)
        assert len(result) == 1
        assert result[0].name == "free_provider"

    def test_local_filter(self, cap_manager):
        p1 = ProviderProfile(name="local_provider", provider_type=ProviderType.LOCAL, models=[])
        p2 = ProviderProfile(name="cloud_provider", provider_type=ProviderType.CLOUD, models=[])
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability(local=True)
        assert len(result) == 1
        assert result[0].name == "local_provider"

    def test_non_local_filter(self, cap_manager):
        p1 = ProviderProfile(name="local_provider", provider_type=ProviderType.LOCAL, models=[])
        p2 = ProviderProfile(name="cloud_provider", provider_type=ProviderType.CLOUD, models=[])
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability()
        names = [p.name for p in result]
        assert "cloud_provider" in names
        assert "local_provider" not in names

    def test_function_calling_filter(self, cap_manager):
        p1 = ProviderProfile(name="tools_provider", supports_tools=True, models=[])
        p2 = ProviderProfile(name="no_tools", supports_tools=False, models=[])
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability(function_calling=True)
        assert len(result) == 1
        assert result[0].name == "tools_provider"

    def test_combined_filters(self, cap_manager):
        p1 = ProviderProfile(
            name="best",
            supports_vision=True,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.LOCAL,
            supports_tools=True,
            models=[],
        )
        p2 = ProviderProfile(
            name="partial",
            supports_vision=True,
            cost_tier=CostTier.FREE,
            provider_type=ProviderType.CLOUD,
            supports_tools=True,
            models=[],
        )
        cap_manager.register(p1)
        cap_manager.register(p2)
        result = cap_manager.get_providers_by_capability(
            vision=True, free=True, local=True, function_calling=True
        )
        assert len(result) == 1
        assert result[0].name == "best"


# ---------------------------------------------------------------------------
# Resolve model ID
# ---------------------------------------------------------------------------


class TestResolveModelId:
    def test_delegates_to_normalize_model_id(self, manager):
        with patch(
            "siyarix.providers.manager.normalize_model_id", return_value="gpt-4-turbo"
        ) as mock_norm:
            result = manager.resolve_model_id("openai", "gpt-4")
            assert result == "gpt-4-turbo"
            mock_norm.assert_called_once_with("openai", "gpt-4")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_returns_dict(self, manager):
        manager.add_credential(ProviderCredential(provider="openai", api_key="sk-123"))
        manager.add_credential(ProviderCredential(provider="openai", api_key="sk-456"))
        manager.add_credential(
            ProviderCredential(provider="ollama", base_url="http://localhost:11434")
        )
        manager._error_counts["openai"] = 2
        stats = manager.stats()
        assert stats["total_providers"] == 3
        assert stats["credentials"] == {"openai": 2, "ollama": 1}
        assert stats["error_counts"] == {"openai": 2}


# ---------------------------------------------------------------------------
# Complete (async)
# ---------------------------------------------------------------------------


class TestComplete:
    @pytest.mark.asyncio
    async def test_complete_calls_adapter(self, manager):
        mock_adapter = AsyncMock(return_value="response")
        with patch("siyarix.providers.manager.resolve_api_key", return_value="sk-key"):
            with patch("siyarix.chat.openai_compat.make_openai_adapter", return_value=mock_adapter):
                result = await manager.complete(
                    provider="openai",
                    model="gpt-4",
                    system_prompt="sys",
                    user_prompt="user",
                    history=[{"role": "user", "content": "hi"}],
                    stream=False,
                    extra_param="val",
                )
                assert result == "response"
                mock_adapter.assert_awaited_once_with(
                    "sys",
                    "user",
                    stream=False,
                    history=[{"role": "user", "content": "hi"}],
                    model="gpt-4",
                    extra_param="val",
                )

    @pytest.mark.asyncio
    async def test_complete_without_history(self, manager):
        mock_adapter = AsyncMock(return_value="response")
        with patch("siyarix.providers.manager.resolve_api_key", return_value="sk-key"):
            with patch("siyarix.chat.openai_compat.make_openai_adapter", return_value=mock_adapter):
                result = await manager.complete(
                    provider="openai",
                    model="gpt-4",
                    system_prompt="sys",
                    user_prompt="user",
                )
                assert result == "response"
                mock_adapter.assert_awaited_once_with(
                    "sys", "user", stream=False, history=None, model="gpt-4"
                )

    @pytest.mark.asyncio
    async def test_complete_no_api_key(self, manager):
        mock_adapter = AsyncMock(return_value="response")
        with patch("siyarix.providers.manager.resolve_api_key", return_value=""):
            with patch("siyarix.chat.openai_compat.make_openai_adapter", return_value=mock_adapter):
                result = await manager.complete(
                    provider="openai", model="gpt-4", system_prompt="sys", user_prompt="user"
                )
                assert result == "response"


# ---------------------------------------------------------------------------
# Ensemble decide
# ---------------------------------------------------------------------------


class TestEnsembleDecide:
    @pytest.mark.asyncio
    async def test_majority_vote_dict(self, manager):
        manager.complete = AsyncMock(
            side_effect=[
                {"content": "A"},
                {"content": "A"},
                {"content": "B"},
            ]
        )
        manager.select_provider = MagicMock(
            side_effect=[
                ("openai", "model1"),
                ("anthropic", "model2"),
                ("gemini", "model3"),
            ]
        )
        result = await manager.ensemble_decide("sys", "user", ["p1", "p2", "p3"])
        assert result == "A"

    @pytest.mark.asyncio
    async def test_majority_vote_object(self, manager):
        class Resp:
            content = "C"

        manager.complete = AsyncMock(
            side_effect=[
                Resp(),
                Resp(),
                {"content": "D"},
            ]
        )
        manager.select_provider = MagicMock(return_value=("p", "m"))
        result = await manager.ensemble_decide("sys", "user", ["p1", "p2", "p3"])
        assert result == "C"

    @pytest.mark.asyncio
    async def test_majority_vote_string(self, manager):
        manager.complete = AsyncMock(
            side_effect=[
                "E",
                "E",
                {"content": "F"},
            ]
        )
        manager.select_provider = MagicMock(return_value=("p", "m"))
        result = await manager.ensemble_decide("sys", "user", ["p1", "p2", "p3"])
        assert result == "E"

    @pytest.mark.asyncio
    async def test_all_fail_raises_error(self, manager):
        manager.complete = AsyncMock(side_effect=Exception("fail"))
        manager.select_provider = MagicMock(return_value=("p", "m"))
        with pytest.raises(RuntimeError, match="All ensemble providers failed"):
            await manager.ensemble_decide("sys", "user", ["p1", "p2"])

    @pytest.mark.asyncio
    async def test_handles_mixed_content_types(self, manager):
        class Resp:
            content = "X"

        manager.complete = AsyncMock(
            side_effect=[
                {"content": "X"},
                Resp(),
                "X",
            ]
        )
        manager.select_provider = MagicMock(return_value=("p", "m"))
        result = await manager.ensemble_decide("sys", "user", ["p1", "p2", "p3"])
        assert result == "X"

    @pytest.mark.asyncio
    async def test_select_provider_called_per_provider(self, manager):
        manager.complete = AsyncMock(side_effect=[{"content": "A"}, {"content": "B"}])
        manager.select_provider = MagicMock(side_effect=[("p1", "m1"), ("p2", "m2")])
        await manager.ensemble_decide("sys", "user", ["a", "b"])
        assert manager.select_provider.call_count == 2


# ---------------------------------------------------------------------------
# resolve_api_key (module-level function)
# ---------------------------------------------------------------------------


class TestResolveApiKey:
    def test_from_credential_store(self):
        mock_store = MagicMock()
        mock_store.retrieve.return_value = "sk-store"
        with patch("siyarix.credential_store.get_creds", return_value=mock_store):
            with patch(
                "siyarix.providers.manager.get_provider_env_var", return_value="OPENAI_API_KEY"
            ):
                result = resolve_api_key("openai")
                assert result == "sk-store"

    def test_from_env_var(self):
        mock_store = MagicMock()
        mock_store.retrieve.return_value = None
        with patch("siyarix.credential_store.get_creds", return_value=mock_store):
            with patch(
                "siyarix.providers.manager.get_provider_env_var", return_value="OPENAI_API_KEY"
            ):
                with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env"}, clear=True):
                    result = resolve_api_key("openai")
                    assert result == "sk-env"

    def test_from_env_var_explicit_name(self):
        mock_store = MagicMock()
        mock_store.retrieve.return_value = None
        with patch("siyarix.credential_store.get_creds", return_value=mock_store):
            with patch.dict(os.environ, {"CUSTOM_KEY": "sk-custom"}, clear=True):
                result = resolve_api_key("openai", env_var="CUSTOM_KEY")
                assert result == "sk-custom"

    def test_no_credential_no_env(self):
        mock_store = MagicMock()
        mock_store.retrieve.return_value = None
        with patch("siyarix.credential_store.get_creds", return_value=mock_store):
            with patch(
                "siyarix.providers.manager.get_provider_env_var", return_value="OPENAI_API_KEY"
            ):
                with patch.dict(os.environ, {}, clear=True):
                    result = resolve_api_key("openai")
                    assert result is None

    def test_credential_store_exception(self):
        with patch("siyarix.credential_store.CredentialStore", side_effect=Exception("fail")):
            with patch(
                "siyarix.providers.manager.get_provider_env_var", return_value="OPENAI_API_KEY"
            ):
                with patch.dict(os.environ, {}, clear=True):
                    result = resolve_api_key("openai")
                    assert result is None

    def test_credential_store_retrieve_exception(self):
        mock_store = MagicMock()
        mock_store.retrieve.side_effect = Exception("retrieve fail")
        with patch("siyarix.credential_store.CredentialStore", return_value=mock_store):
            with patch(
                "siyarix.providers.manager.get_provider_env_var", return_value="OPENAI_API_KEY"
            ):
                with patch.dict(os.environ, {}, clear=True):
                    result = resolve_api_key("openai")
                    assert result is None

    def test_no_env_var_uses_get_provider_env_var(self):
        mock_store = MagicMock()
        mock_store.retrieve.return_value = None
        with patch("siyarix.credential_store.CredentialStore", return_value=mock_store):
            with patch("siyarix.providers.manager.get_provider_env_var", return_value="CUSTOM_VAR"):
                with patch.dict(os.environ, {"CUSTOM_VAR": "sk-resolved"}, clear=True):
                    result = resolve_api_key("openai", env_var=None)
                    assert result == "sk-resolved"


# ---------------------------------------------------------------------------
# get_provider_env_var (module-level function)
# ---------------------------------------------------------------------------


class TestGetProviderEnvVar:
    def test_from_profile(self):
        profile = ProviderProfile(name="openai", api_key_env="OPENAI_CUSTOM_KEY", models=[])
        pm = ProviderManager.get_instance()
        pm.register(profile)
        env_var = get_provider_env_var("openai")
        assert env_var == "OPENAI_CUSTOM_KEY"

    def test_fallback(self):
        pm = ProviderManager.get_instance()
        env_var = get_provider_env_var("custom_provider")
        assert env_var == "CUSTOM_PROVIDER_API_KEY"


# ---------------------------------------------------------------------------
# Init default profiles
# ---------------------------------------------------------------------------


class TestInitDefaultProfiles:
    def test_init_default_profiles_called(self):
        ProviderManager._instance = None
        ProviderManager._instance_lock = None
        with patch("siyarix.providers.profiles.register_all_profiles") as mock_register:
            pm = ProviderManager()
            mock_register.assert_called_once_with(pm)
