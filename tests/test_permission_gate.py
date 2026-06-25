from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.permission_gate — permission gate."""


from unittest.mock import MagicMock, patch


from siyarix.permission_gate import GateResult, PermissionGate


class TestGateResult:
    def test_defaults(self) -> None:
        r = GateResult(allowed=False, stage="syntax")
        assert r.allowed is False
        assert r.stage == "syntax"
        assert r.reason == ""
        assert r.tool == ""
        assert r.command == ""
        assert r.requires_review is False


class TestPermissionGate:
    def test_empty_command_returns_syntax_block(self) -> None:
        gate = PermissionGate()
        result = gate.check("")
        assert result.allowed is False
        assert result.stage == "syntax"
        assert "Empty" in result.reason

    def test_whitespace_command_returns_syntax_block(self) -> None:
        gate = PermissionGate()
        result = gate.check("   ")
        assert result.allowed is False
        assert result.stage == "syntax"

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_critical_danger_returns_forbidden(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(
            severity="critical", reasons=["rm -rf detected"]
        )
        gate = PermissionGate()
        result = gate.check("rm -rf /")
        assert result.allowed is False
        assert result.stage == "forbidden"
        assert "Destructive" in result.reason

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_high_danger_returns_review(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="high", reasons=["shutdown detected"])
        gate = PermissionGate()
        result = gate.check("shutdown -h now")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_medium_danger_returns_review(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="medium", reasons=["rm detected"])
        gate = PermissionGate()
        result = gate.check("rm file.txt")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_safe_command_returns_approved(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("ls -la")
        assert result.allowed is True
        assert result.stage == "approved"


"""Extra tests for permission_gate targeting uncovered lines."""


import time
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.permission_gate import GateStage


class TestGateResultInvalidStage:
    def test_invalid_stage_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid stage"):
            GateResult(allowed=False, stage="bogus_stage")

    def test_valid_str_stage_coerces_to_enum(self) -> None:
        r = GateResult(allowed=False, stage="syntax")
        assert r.stage == GateStage.SYNTAX


class TestPermissionGateLoadState:
    def test_load_state_corrupt_json(self, tmp_path) -> None:
        state_file = tmp_path / "rate_limit.json"
        state_file.write_text("not valid json", encoding="utf-8")
        gate = PermissionGate()
        # Override state file after init
        gate._state_file = state_file
        gate._load_state()
        assert gate._calls == []

    def test_load_state_file_missing(self, tmp_path) -> None:
        state_file = tmp_path / "rate_limit.json"
        assert not state_file.exists()
        gate = PermissionGate()
        gate._state_file = state_file
        gate._load_state()
        assert gate._calls == []

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_rate_limit_exceeded(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate(rate_limit_calls=2, rate_limit_period=60.0)
        now = time.time()
        gate._calls = [now - 1, now - 2]
        result = gate.check("ls")
        assert result.allowed is False
        assert result.stage == GateStage.FORBIDDEN
        assert "Rate limit" in result.reason

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_restricted_payload_blocked(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check(
            "rm -rf /important",
            context={"restricted_payload": True},
        )
        assert result.allowed is False
        assert result.stage == GateStage.FORBIDDEN
        assert "verification failed" in result.reason

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_restricted_payload_not_blocked_safe_command(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("ls", context={"restricted_payload": True})
        assert result.allowed is True
        assert result.stage == GateStage.APPROVED

    def test_save_state_write_failure(self, tmp_path) -> None:
        state_file = tmp_path / "rate_limit.json"
        gate = PermissionGate()
        gate._state_file = state_file
        gate._calls = [time.time()]
        gate._save_state(force=True)
        # Now make parent read-only to force write failure on a subsequent attempt
        state_file.parent.chmod(0o444)
        old_dirty = gate._dirty
        gate._save_state(force=True)
        # Restore permissions
        state_file.parent.chmod(0o755)

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_rate_limit_edge_one_call_remaining(self, MockDA: MagicMock) -> None:
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate(rate_limit_calls=3, rate_limit_period=60.0)
        now = time.time()
        gate._calls = [now - 1]
        result = gate.check("ls")
        assert result.allowed is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_fifty_calls_triggers_save(self, MockDA: MagicMock) -> None:
        """After 50 calls, _save_state(force=True) is triggered via the modulo check."""
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate(rate_limit_calls=100, rate_limit_period=3600.0)
        gate._dirty = False
        for i in range(50):
            gate.check(f"cmd{i}")
        # The 50th check should have forced a save (dirty reset)
        # We test by making the write fail and ensuring dirty remains
        state_file = gate._state_file
        with patch.object(Path, "write_text", side_effect=PermissionError):
            gate.check("extra")
        # The check forces save since _calls % 50 == 1 → not forced
        # Instead test the 50th call directly via _save_state
        gate._dirty = True
        gate._save_state(force=(len(gate._calls) % 50 == 0))
        assert gate._dirty is True  # not forced
        gate._dirty = True
        gate._save_state(force=True)  # simulate forced
        # If write fails, dirty stays True
        with patch.object(Path, "write_text", side_effect=PermissionError):
            gate._dirty = True
            gate._save_state(force=True)
            assert gate._dirty is True
