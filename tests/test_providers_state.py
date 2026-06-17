from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest

from siyarix.providers.state import ProviderStateManager
from siyarix.providers.types import FailoverReason


@pytest.fixture
def state_manager():
    return ProviderStateManager(path=None)


@pytest.fixture
def state_manager_with_path(tmp_path):
    path = str(tmp_path / "provider_state.json")
    return ProviderStateManager(path=path)


class TestInit:
    def test_defaults(self, state_manager):
        assert state_manager.path is None
        assert state_manager._disabled == {}
        assert state_manager._failure_counts == {}
        assert state_manager._last_fail_time == {}
        assert state_manager._cooldown_secs == 30.0
        assert state_manager._skip_cache == {}

    def test_with_path_loads(self, tmp_path):
        data = {"disabled": {"openai": 0.0}, "failure_counts": {"openai": 2}, "last_fail_time": {"openai": 100.0}}
        path = str(tmp_path / "state.json")
        Path(path).write_text(json.dumps(data), encoding="utf-8")
        mgr = ProviderStateManager(path=path)
        assert mgr.path == path
        assert mgr._disabled == {"openai": 0.0}
        assert mgr._failure_counts == {"openai": 2}
        assert mgr._last_fail_time == {"openai": 100.0}

    def test_with_path_loads_list_disabled_format(self, tmp_path):
        data = {"disabled": ["openai", "anthropic"]}
        path = str(tmp_path / "state.json")
        Path(path).write_text(json.dumps(data), encoding="utf-8")
        mgr = ProviderStateManager(path=path)
        assert mgr._disabled == {"openai": 0.0, "anthropic": 0.0}

    def test_with_path_file_not_found(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        mgr = ProviderStateManager(path=path)
        assert mgr._disabled == {}

    def test_with_path_json_decode_error(self, tmp_path):
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("{invalid", encoding="utf-8")
        mgr = ProviderStateManager(path=path)
        assert mgr._disabled == {}

    def test_with_path_non_dict_disabled_raw(self, tmp_path):
        data = {"disabled": "string_value"}
        path = str(tmp_path / "state.json")
        Path(path).write_text(json.dumps(data), encoding="utf-8")
        mgr = ProviderStateManager(path=path)
        assert mgr._disabled == {}

    def test_load_early_return_when_path_not_set(self, state_manager):
        state_manager.path = None
        state_manager._load()


class TestSave:
    def test_no_path(self, state_manager):
        state_manager.save()

    def test_with_path(self, tmp_path):
        path = str(tmp_path / "state.json")
        mgr = ProviderStateManager(path=path)
        mgr._disabled = {"openai": 100.0}
        mgr._failure_counts = {"openai": 3}
        mgr._last_fail_time = {"openai": 50.0}
        mgr.save()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert data["disabled"] == {"openai": 100.0}
        assert data["failure_counts"] == {"openai": 3}
        assert data["last_fail_time"] == {"openai": 50.0}

    def test_creates_parent_dir(self, tmp_path):
        path = str(tmp_path / "sub" / "state.json")
        mgr = ProviderStateManager(path=path)
        mgr.save()
        assert Path(path).parent.exists()

    def test_exception_logged(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        path = str(tmp_path / "state.json")
        mgr = ProviderStateManager(path=path)
        with patch("pathlib.Path.mkdir", side_effect=OSError("denied")):
            mgr.save()
            assert "Failed to save provider state" in caplog.text


class TestComputeCooldown:
    def test_zero_failures(self, state_manager):
        cooldown = state_manager._compute_cooldown("openai")
        assert cooldown == 30.0

    def test_one_failure(self, state_manager):
        state_manager._failure_counts["openai"] = 1
        cooldown = state_manager._compute_cooldown("openai")
        assert cooldown == 30.0

    def test_two_failures(self, state_manager):
        state_manager._failure_counts["openai"] = 2
        cooldown = state_manager._compute_cooldown("openai")
        assert cooldown == 60.0

    def test_three_failures(self, state_manager):
        state_manager._failure_counts["openai"] = 3
        cooldown = state_manager._compute_cooldown("openai")
        assert cooldown == 300.0

    def test_four_or_more_failures(self, state_manager):
        state_manager._failure_counts["openai"] = 10
        cooldown = state_manager._compute_cooldown("openai")
        assert cooldown == 300.0


class TestIsDisabled:
    def test_not_in_disabled(self, state_manager):
        assert state_manager.is_disabled("openai") is False

    def test_cooldown_expired(self, state_manager):
        state_manager._disabled["openai"] = time.time() - 10
        state_manager._failure_counts["openai"] = 3
        result = state_manager.is_disabled("openai")
        assert result is False
        assert "openai" not in state_manager._disabled
        assert state_manager._failure_counts["openai"] == 0

    def test_still_in_cooldown(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 100
        result = state_manager.is_disabled("openai")
        assert result is True

    def test_expired_calls_save(self, state_manager):
        state_manager._disabled["openai"] = time.time() - 10
        with patch.object(state_manager, "save") as mock_save:
            state_manager.is_disabled("openai")
            mock_save.assert_called_once()


class TestCooldownRemaining:
    def test_not_disabled(self, state_manager):
        assert state_manager.cooldown_remaining("openai") == 0.0

    def test_still_in_cooldown(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 50
        remaining = state_manager.cooldown_remaining("openai")
        assert 49.0 < remaining <= 50.0

    def test_expired_returns_zero(self, state_manager):
        state_manager._disabled["openai"] = time.time() - 10
        remaining = state_manager.cooldown_remaining("openai")
        assert remaining == 0.0


class TestRecordFailure:
    def test_increments_failure_count(self, state_manager):
        state_manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        assert state_manager._failure_counts["openai"] == 1

    def test_increments_existing_failure_count(self, state_manager):
        state_manager._failure_counts["openai"] = 2
        state_manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        assert state_manager._failure_counts["openai"] == 3

    def test_sets_disabled_with_cooldown(self, state_manager):
        state_manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        assert "openai" in state_manager._disabled
        assert state_manager._disabled["openai"] > time.time()

    def test_sets_last_fail_time(self, state_manager):
        before = time.time()
        state_manager.record_failure("openai", FailoverReason.RATE_LIMIT)
        assert state_manager._last_fail_time["openai"] >= before

    def test_calls_save(self, state_manager):
        with patch.object(state_manager, "save") as mock_save:
            state_manager.record_failure("openai", FailoverReason.RATE_LIMIT)
            mock_save.assert_called_once()

    def test_emits_event(self, state_manager):
        with patch("siyarix.providers.state.emit_sync") as mock_emit:
            state_manager.record_failure("openai", FailoverReason.AUTH)
            mock_emit.assert_called_once()
            event = mock_emit.call_args[0][0]
            assert event.type.value == "provider.error"
            assert event.source == "providers"
            assert event.data["provider"] == "openai"
            assert event.data["failure_count"] == 1
            assert event.data["reason"] == "auth"

    def test_reason_none(self, state_manager):
        with patch("siyarix.providers.state.emit_sync") as mock_emit:
            state_manager.record_failure("openai", None)
            event = mock_emit.call_args[0][0]
            assert event.data["reason"] == "unknown"


class TestRecordSuccess:
    def test_removes_from_disabled(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 100
        state_manager.record_success("openai")
        assert "openai" not in state_manager._disabled

    def test_resets_failure_count(self, state_manager):
        state_manager._failure_counts["openai"] = 5
        state_manager.record_success("openai")
        assert state_manager._failure_counts["openai"] == 0

    def test_calls_save(self, state_manager):
        with patch.object(state_manager, "save") as mock_save:
            state_manager.record_success("openai")
            mock_save.assert_called_once()

    def test_emits_event(self, state_manager):
        with patch("siyarix.providers.state.emit_sync") as mock_emit:
            state_manager.record_success("openai")
            mock_emit.assert_called_once()
            event = mock_emit.call_args[0][0]
            assert event.type.value == "provider.selected"
            assert event.source == "providers"
            assert event.data == {"provider": "openai", "status": "recovered"}

    def test_noop_if_not_disabled(self, state_manager):
        state_manager.record_success("openai")
        assert "openai" not in state_manager._disabled
        assert state_manager._failure_counts["openai"] == 0


class TestMarkSkipCandidate:
    def test_new_session(self, state_manager):
        state_manager.mark_skip_candidate("session_1", "openai", "gpt-4")
        assert "session_1" in state_manager._skip_cache
        assert "openai/gpt-4" in state_manager._skip_cache["session_1"]
        assert state_manager._skip_cache["session_1"]["openai/gpt-4"] > time.time()

    def test_existing_session(self, state_manager):
        state_manager._skip_cache["session_1"] = {}
        state_manager.mark_skip_candidate("session_1", "openai", "gpt-4")
        assert "openai/gpt-4" in state_manager._skip_cache["session_1"]

    def test_multiple_models(self, state_manager):
        state_manager.mark_skip_candidate("session_1", "openai", "gpt-4")
        state_manager.mark_skip_candidate("session_1", "openai", "gpt-3.5")
        assert len(state_manager._skip_cache["session_1"]) == 2


class TestIsCandidateSkipped:
    def test_not_in_cache(self, state_manager):
        assert state_manager.is_candidate_skipped("session_1", "openai", "gpt-4") is False

    def test_in_cache_not_expired(self, state_manager):
        far_future = time.time() + 10000
        state_manager._skip_cache["session_1"] = {"openai/gpt-4": far_future}
        assert state_manager.is_candidate_skipped("session_1", "openai", "gpt-4") is True

    def test_expired(self, state_manager):
        state_manager._skip_cache["session_1"] = {"openai/gpt-4": time.time() - 10}
        assert state_manager.is_candidate_skipped("session_1", "openai", "gpt-4") is False
        assert "openai/gpt-4" not in state_manager._skip_cache["session_1"]

    def test_session_not_in_cache(self, state_manager):
        assert state_manager.is_candidate_skipped("unknown_session", "openai", "gpt-4") is False


class TestGetAvailableProviders:
    def test_no_preferred(self, state_manager):
        assert state_manager.get_available_providers() == []

    def test_all_disabled(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 100
        state_manager._disabled["anthropic"] = time.time() + 100
        result = state_manager.get_available_providers(preferred=["openai", "anthropic"])
        assert result == []

    def test_some_available(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 100
        result = state_manager.get_available_providers(preferred=["openai", "anthropic"])
        assert result == ["anthropic"]

    def test_all_available(self, state_manager):
        result = state_manager.get_available_providers(preferred=["openai", "anthropic"])
        assert result == ["openai", "anthropic"]

    def test_expired_disabled_counts_as_available(self, state_manager):
        state_manager._disabled["openai"] = time.time() - 10
        result = state_manager.get_available_providers(preferred=["openai"])
        assert result == ["openai"]

    def test_preferred_is_none(self, state_manager):
        state_manager._disabled["openai"] = time.time() + 100
        result = state_manager.get_available_providers(preferred=None)
        assert result == []

    def test_preferred_is_empty(self, state_manager):
        result = state_manager.get_available_providers(preferred=[])
        assert result == []

    def test_preserves_preferred_order(self, state_manager):
        result = state_manager.get_available_providers(preferred=["anthropic", "openai"])
        assert result == ["anthropic", "openai"]
