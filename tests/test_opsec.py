# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.opsec — operational security."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from siyarix.opsec import OPSECManager, OPSECStatus, opsec_manager, random_string


class TestRandomString:
    def test_default_length(self) -> None:
        s = random_string()
        assert len(s) == 8

    def test_custom_length(self) -> None:
        s = random_string(12)
        assert len(s) == 12

    def test_contains_only_allowed_chars(self) -> None:
        s = random_string(100)
        assert all(c.isalnum() for c in s)

    def test_different_calls_different(self) -> None:
        s1 = random_string()
        s2 = random_string()
        assert s1 != s2


class TestOPSECStatus:
    def test_defaults(self) -> None:
        s = OPSECStatus()
        assert s.isolated is False
        assert s.namespace == ""
        assert s.tor_enabled is False
        assert s.doh_enabled is False
        assert s.mac_randomized is False
        assert s.memory_only is False
        assert s.burn_after_reading is False


class TestOPSECManager:
    def test_initial_status(self) -> None:
        mgr = OPSECManager()
        assert mgr.status.isolated is False
        assert mgr.status.namespace == ""

    def test_isolate_with_target(self) -> None:
        mgr = OPSECManager()
        result = mgr.isolate(target="example.com", use_tor=True, use_doh=True, randomize_mac=True, memory_only=True)
        assert result.success is True
        assert result.action == "isolate"
        assert mgr.status.isolated is True
        assert "example" in mgr.status.namespace
        assert mgr.status.tor_enabled is True
        assert mgr.status.doh_enabled is True
        assert mgr.status.mac_randomized is True
        assert mgr.status.memory_only is True
        assert "Memory-only mode: enabled" in result.detail
        assert "TOR" in result.detail
        assert "MAC" in result.detail

    def test_isolate_without_target(self) -> None:
        mgr = OPSECManager()
        result = mgr.isolate()
        assert result.success is True
        assert mgr.status.isolated is True
        assert "siyarix_isolated_" in mgr.status.namespace

    def test_isolate_disables_logging_in_memory_only(self) -> None:
        mgr = OPSECManager()
        result = mgr.isolate(memory_only=True)
        assert "Persistent logging disabled" in result.detail

    def test_burn_with_session_id(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        mgr._log_dir = tmp_path
        session_dir = tmp_path / "sessions" / "sess_test123"
        session_dir.mkdir(parents=True)
        log_file = session_dir / "output.log"
        log_file.write_text("sensitive data")

        result = mgr.burn(session_id="test123")
        assert result.success is True
        assert result.action == "burn"
        assert result.items_destroyed >= 1
        assert mgr.status.isolated is False  # status reset

    def test_burn_no_session_id(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        mgr._log_dir = tmp_path
        result = mgr.burn()
        assert result.success is True
        assert result.detail is not None

    def test_burn_cleans_entire_sessions_dir(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        mgr._log_dir = tmp_path
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True)
        sess_file = sessions_dir / "old_session.json"
        sess_file.write_text("{}")

        result = mgr.burn()
        assert result.success is True
        assert result.items_destroyed >= 1

    def test_burn_cleans_subdir_files(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        mgr._log_dir = tmp_path
        subdir = tmp_path / "sessions" / "orphan_dir"
        subdir.mkdir(parents=True)
        leftover = subdir / "trace.log"
        leftover.write_text("leftover data")

        result = mgr.burn()
        assert result.success is True
        assert result.items_destroyed >= 1
        assert not leftover.exists()

    def test_burn_posix_branch(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        mgr._log_dir = tmp_path
        with patch("os.name", "posix"):
            result = mgr.burn()
        assert result.success is True
        assert "Secure zeroization" in result.detail
        assert "Clearing swap" in result.detail

    def test_secure_delete_normal_file(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        test_file = tmp_path / "secret.txt"
        test_file.write_text("confidential")

        mgr._secure_delete(test_file, passes=2)
        assert not test_file.exists()

    def test_secure_delete_empty_file(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        mgr._secure_delete(test_file)
        assert not test_file.exists()

    def test_secure_delete_nonexistent(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        nonexistent = tmp_path / "nope.txt"
        mgr._secure_delete(nonexistent)  # should not raise

    def test_secure_delete_on_directory(self, tmp_path: Path) -> None:
        mgr = OPSECManager()
        d = tmp_path / "adir"
        d.mkdir()
        mgr._secure_delete(d)  # should not raise

    @patch("builtins.open", side_effect=PermissionError("denied"))
    def test_secure_delete_permission_error(self, mock_open: MagicMock, tmp_path: Path) -> None:
        mgr = OPSECManager()
        test_file = tmp_path / "locked.txt"
        test_file.write_text("data")
        mgr._secure_delete(test_file)  # should not raise

    def test_disable(self) -> None:
        mgr = OPSECManager()
        mgr.isolate(target="test")
        assert mgr.status.isolated is True
        result = mgr.disable()
        assert result.success is True
        assert mgr.status.isolated is False

    def test_summary(self) -> None:
        mgr = OPSECManager()
        mgr.isolate(target="x.com", use_tor=True)
        summary = mgr.summary()
        assert summary["isolated"] is True
        assert summary["tor_enabled"] is True
        assert "namespace" in summary
        assert "doh_enabled" in summary

    def test_summary_after_disable(self) -> None:
        mgr = OPSECManager()
        mgr.isolate(target="x.com")
        mgr.disable()
        summary = mgr.summary()
        assert summary["isolated"] is False

    def test_module_singleton(self) -> None:
        assert isinstance(opsec_manager, OPSECManager)
