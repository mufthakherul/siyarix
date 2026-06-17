# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for config.py - SettingsStore."""

from __future__ import annotations

import builtins
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.config import (
    DEFAULTS,
    SettingsStore,
    _try_load_toml,
    _write_toml,
    get_config_dir,
)



# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    cfg = tmp_path / "settings.toml"
    return SettingsStore(path=cfg)


# ---------------------------------------------------------------------------
# _try_load_toml
# ---------------------------------------------------------------------------

class TestTryLoadToml:
    def test_file_not_found(self, tmp_path):
        assert _try_load_toml(tmp_path / "nope.toml") == {}

    def test_tomllib_python311(self, tmp_path):
        fp = tmp_path / "test.toml"
        fp.write_text('key = "value"\nnum = 42\nflag = true\n')
        data = _try_load_toml(fp)
        assert data.get("key") == "value"

    def test_tomli_fallback(self, tmp_path):
        import builtins

        orig_import = builtins.__import__
        fp = tmp_path / "test.toml"
        fp.write_text('greeting = "hello"\n')

        def mock_import(name, *args, **kwargs):
            if name == "tomllib":
                raise ImportError("no tomllib")
            return orig_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            data = _try_load_toml(fp)
            assert data.get("greeting") == "hello"

    def test_fallback_parser(self, tmp_path):
        import builtins

        orig_import = builtins.__import__
        fp = tmp_path / "test.toml"
        fp.write_text('# comment\nkey = "value"\ncount = 42\nflag = true\nrate = 3.14\n')

        def mock_import(name, *args, **kwargs):
            if name in ("tomllib", "tomli"):
                raise ImportError(f"no {name}")
            return orig_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            data = _try_load_toml(fp)
            assert data.get("key") == "value"
            assert data.get("count") == 42
            assert data.get("flag") is True
            assert data.get("rate") == 3.14

    def test_fallback_parser_float(self, tmp_path):
        import builtins

        orig_import = builtins.__import__
        fp = tmp_path / "test.toml"
        fp.write_text("pi = 3.14\n")

        def mock_import(name, *args, **kwargs):
            if name in ("tomllib", "tomli"):
                raise ImportError(f"no {name}")
            return orig_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            data = _try_load_toml(fp)
            assert data.get("pi") == 3.14

    def test_exception_returns_empty(self, tmp_path):
        fp = tmp_path / "bad.toml"
        fp.write_text("not valid toml stuff {{{")
        data = _try_load_toml(fp)
        assert data == {}


# ---------------------------------------------------------------------------
# _write_toml
# ---------------------------------------------------------------------------


class TestWriteToml:
    def test_writes_file(self, tmp_path):
        fp = tmp_path / "out.toml"
        _write_toml(fp, {"key": "value", "num": 42, "flag": True})
        content = fp.read_text()
        assert 'key = "value"' in content
        assert "num = 42" in content
        assert "flag = true" in content

    def test_writes_with_description(self, tmp_path):
        fp = tmp_path / "out.toml"
        _write_toml(fp, {"scan_timeout": 300})
        content = fp.read_text()
        assert "scan_timeout" in content
        assert "Seconds" in content  # from DESCRIPTIONS


# ---------------------------------------------------------------------------
# SettingsStore
# ---------------------------------------------------------------------------


class TestSettingsStore:
    def test_init_applies_defaults(self, store):
        assert store.get("default_output_format") == "table"
        assert store.get("scan_timeout") == 300

    def test_get_unknown_key_raises(self, store):
        with pytest.raises(KeyError, match="Unknown setting"):
            store.get("nonexistent_key")

    def test_get_custom_value(self, store):
        store._data["scan_timeout"] = 600
        assert store.get("scan_timeout") == 600

    def test_set_bool(self, store):
        result = store.set("tls_verify", "false")
        assert result is False
        assert store.get("tls_verify") is False

    def test_set_int(self, store):
        result = store.set("scan_timeout", "99")
        assert result == 99
        assert store.get("scan_timeout") == 99

    def test_set_float(self, store):
        result = store.set("default_parallel", "5")
        assert result == 5

    def test_set_int_invalid(self, store):
        with pytest.raises(ValueError, match="expects an integer"):
            store.set("scan_timeout", "not_a_number")

    def test_set_unknown_key_raises(self, store):
        with pytest.raises(KeyError, match="Unknown setting"):
            store.set("bad_key", "value")

    def test_reset_single_key(self, store):
        store.set("scan_timeout", "999")
        store.reset("scan_timeout")
        assert store.get("scan_timeout") == DEFAULTS["scan_timeout"]

    def test_reset_all(self, store):
        store.set("scan_timeout", "999")
        store.set("default_parallel", "10")
        store.reset()
        assert store.get("scan_timeout") == DEFAULTS["scan_timeout"]
        assert store.get("default_parallel") == DEFAULTS["default_parallel"]

    def test_reset_unknown_key_raises(self, store):
        with pytest.raises(KeyError, match="Unknown setting"):
            store.reset("bad_key")

    def test_list_all(self, store):
        rows = store.list_all()
        assert len(rows) == len(DEFAULTS)
        for row in rows:
            assert "key" in row
            assert "value" in row
            assert "default" in row
            assert "description" in row

    def test_list_all_modified(self, store):
        store.set("scan_timeout", "999")
        rows = store.list_all()
        timeout = next(r for r in rows if r["key"] == "scan_timeout")
        assert timeout["modified"] is True

    def test_edit(self, store):
        store._path.write_text('key = "value"\n')
        with (
            patch("siyarix.config.safe_run_sync") as mock_safe,
            patch("siyarix.config.os.getenv", return_value="editor"),
        ):
            store.edit()
            assert mock_safe.called

    def test_edit_safe_run_fails(self, store):
        store._path.write_text('key = "value"\n')
        with (
            patch("siyarix.config.safe_run_sync", side_effect=Exception("fail")),
            patch("siyarix.config.os.getenv", return_value="editor"),
        ):
            # edit() catches the exception and logs it, no longer falls back to subprocess.run
            store.edit()
            # If it didn't crash, the test passes


    def test_edit_both_fail(self, store):
        store._path.write_text('key = "value"\n')
        with (
            patch("siyarix.config.safe_run_sync", side_effect=Exception("fail1")),
            patch("subprocess.run", side_effect=Exception("fail2")),
            patch("siyarix.config.os.getenv", return_value="editor"),
        ):
            store.edit()
            # Should not raise — catches all exceptions

    def test_env_override_log_level(self, tmp_path):
        with patch.dict(os.environ, {"SIYARIX_LOG_LEVEL": "debug"}, clear=True):
            cfg = tmp_path / "settings.toml"
            store = SettingsStore(path=cfg)
            assert store.get("log_level") == "debug"

    def test_env_override_scan_timeout(self, tmp_path):
        with patch.dict(os.environ, {"SIYARIX_TIMEOUT": "500"}, clear=True):
            cfg = tmp_path / "settings.toml"
            store = SettingsStore(path=cfg)
            assert store.get("scan_timeout") == 500

    def test_env_override_bad_timeout(self, tmp_path):
        with patch.dict(os.environ, {"SIYARIX_TIMEOUT": "not_a_number"}, clear=True):
            cfg = tmp_path / "settings.toml"
            store = SettingsStore(path=cfg)
            assert store.get("scan_timeout") == DEFAULTS["scan_timeout"]

    def test_env_override_stealth(self, tmp_path):
        with patch.dict(os.environ, {"SIYARIX_SAFE_MODE": "true"}, clear=True):
            cfg = tmp_path / "settings.toml"
            store = SettingsStore(path=cfg)
            assert store._data["_safe_mode"] is True

    def test_env_override_config_path(self, tmp_path):
        with patch.dict(os.environ, {"SIYARIX_CONFIG": str(tmp_path / "custom")}, clear=True):
            cfg = tmp_path / "settings.toml"
            store = SettingsStore(path=cfg)
            assert store._data["_config_path"] is not None


# ---------------------------------------------------------------------------
# _coerce
# ---------------------------------------------------------------------------


class TestCoerce:
    def test_coerce_bool_true(self, store):
        assert store._coerce("tls_verify", "true") is True
        assert store._coerce("tls_verify", "1") is True
        assert store._coerce("tls_verify", "yes") is True

    def test_coerce_bool_false(self, store):
        assert store._coerce("tls_verify", "false") is False

    def test_coerce_int(self, store):
        assert store._coerce("scan_timeout", "42") == 42

    def test_coerce_int_error(self, store):
        with pytest.raises(ValueError, match="expects an integer"):
            store._coerce("scan_timeout", "abc")

    def test_coerce_float(self, store):
        assert store._coerce("default_parallel", "3") == 3

    def test_coerce_string(self, store):
        assert store._coerce("persona", "bug_hunter") == "bug_hunter"


# ---------------------------------------------------------------------------
# SettingsStore persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_load_roundtrip(self, tmp_path):
        cfg = tmp_path / "settings.toml"
        store = SettingsStore(path=cfg)
        store.set("scan_timeout", "120")
        store.set("persona", "offensive")

        store2 = SettingsStore(path=cfg)
        assert store2.get("scan_timeout") == 120
        assert store2.get("persona") == "offensive"

    def test_save_creates_file(self, tmp_path):
        cfg = tmp_path / "settings.toml"
        store = SettingsStore(path=cfg)
        store.set("scan_timeout", "60")
        assert cfg.exists()

    def test_set_calls_save(self, store):
        with patch.object(store, "_save") as mock_save:
            store.set("scan_timeout", "1")
            mock_save.assert_called_once()

class TestConfigCore:
    """Cover missing config.py lines: fallback TOML parser, backup, restore etc."""

    def _disable_tomllib(self):
        """Patch sys.modules to make tomllib and tomli unavailable."""
        return patch.dict("sys.modules", {"tomllib": None, "tomli": None})

    def test_try_load_toml_fallback_parser_true(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("key = true")
        with self._disable_tomllib():
            data = _try_load_toml(f)
        assert data.get("key") is True

    def test_try_load_toml_fallback_int(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("count = 42")
        with self._disable_tomllib():
            data = _try_load_toml(f)
        assert data.get("count") == 42

    def test_try_load_toml_fallback_float(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("rate = 3.14")
        with self._disable_tomllib():
            data = _try_load_toml(f)
        assert data.get("rate") == 3.14

    def test_try_load_toml_fallback_bad_value_becomes_string(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("key = something")
        with self._disable_tomllib():
            data = _try_load_toml(f)
        assert data.get("key") == "something"

    def test_try_load_toml_fallback_false(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("key = false")
        with self._disable_tomllib():
            data = _try_load_toml(f)
        assert data.get("key") is False

    def test_try_load_toml_fallback_exception_returns_empty(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("key = val")
        with self._disable_tomllib():
            with patch.object(Path, "read_text", side_effect=Exception("bad")):
                with patch("siyarix.config.logger") as mock_log:
                    data = _try_load_toml(f)
        assert data == {}
        mock_log.exception.assert_called_once()

    def test_try_load_toml_raises_exception_returns_empty(self, tmp_path):
        from siyarix.config import _try_load_toml
        f = tmp_path / "settings.toml"
        f.write_text("key = val")
        with patch("tomllib.load", side_effect=Exception("parse error")):
            with patch("siyarix.config.logger") as mock_log:
                data = _try_load_toml(f)
        assert data == {}
        mock_log.exception.assert_called_once()

    def test_backup_returns_none_when_no_path(self):
        from siyarix.config import SettingsStore
        store = SettingsStore()
        store._path = Path("/nonexistent/settings.toml")
        result = store.backup()
        assert result is None

    def test_backup_oserror_returns_none(self, tmp_path):
        from siyarix.config import SettingsStore
        store = SettingsStore()
        store._path = tmp_path / "settings.toml"
        store._path.write_text("key = true")
        with patch("shutil.copy2", side_effect=OSError("fail")):
            with patch("siyarix.config.logger") as mock_log:
                result = store.backup()
        assert result is None
        mock_log.warning.assert_called_once()

    def test_save_backup_called_when_data_differs(self, tmp_path):
        from siyarix.config import SettingsStore
        p = tmp_path / "settings.toml"
        p.write_text("key = true")
        store = SettingsStore(path=p)
        store._data["key"] = "changed"
        with patch.object(store, "backup") as mock_backup:
            store._save()
            mock_backup.assert_called_once()

    def test_cleanup_old_backups_ignores_oserror(self, tmp_path):
        from siyarix.config import SettingsStore
        store = SettingsStore(path=tmp_path / "settings.toml")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        for i in range(10):
            (backup_dir / f"settings_20250101_{i:02d}0000.toml").write_text("")
        with patch.object(Path, "unlink", side_effect=OSError("fail")):
            store._cleanup_old_backups(keep=5)

    def test_restore_latest_no_backup_dir(self):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_config_dir", return_value=Path("/nonexistent")):
            result = SettingsStore.restore_latest()
        assert result is None

    def test_restore_latest_no_backups(self, tmp_path):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_config_dir", return_value=tmp_path):
            result = SettingsStore.restore_latest()
        assert result is None

    def test_restore_latest_oserror(self, tmp_path):
        from siyarix.config import SettingsStore, get_config_dir
        backup_dir = get_config_dir() / "backups"
        backup_dir.mkdir(parents=True)
        (backup_dir / "settings_20250101_120000.toml").write_text("k=v")
        with patch("shutil.copy2", side_effect=OSError("fail")):
            with patch("siyarix.config.logger") as mock_log:
                result = SettingsStore.restore_latest()
        assert result is None
        mock_log.warning.assert_called_once()

    def test_edit_reloads_data(self, tmp_path):
        from siyarix.config import SettingsStore
        p = tmp_path / "settings.toml"
        p.write_text("key = true")
        store = SettingsStore(path=p)
        with patch("siyarix.config.safe_run_sync"):
            with patch("os.getenv", return_value="notepad.exe"):
                store.edit()
        assert store._data["key"] is True

    def test_coerce_float(self):
        from siyarix.config import SettingsStore, DEFAULTS
        store = SettingsStore()
        orig = DEFAULTS.get("scan_timeout")
        DEFAULTS["scan_timeout"] = 3.0
        try:
            result = store._coerce("scan_timeout", 3.5)
            assert isinstance(result, float)
        finally:
            if orig is not None:
                DEFAULTS["scan_timeout"] = orig
            else:
                del DEFAULTS["scan_timeout"]

    def test_coerce_float_value_error(self):
        from siyarix.config import SettingsStore, DEFAULTS
        store = SettingsStore()
        orig = DEFAULTS.get("scan_timeout")
        DEFAULTS["scan_timeout"] = 3.0
        try:
            with pytest.raises(ValueError, match="expects a number"):
                store._coerce("scan_timeout", "not_a_number")
        finally:
            if orig is not None:
                DEFAULTS["scan_timeout"] = orig
            else:
                del DEFAULTS["scan_timeout"]

    def test_env_override_home_dir(self):
        from siyarix.config import SettingsStore
        with patch.dict(os.environ, {"SIYARIX_HOME": "/tmp/siyarix_home"}, clear=True):
            with patch("siyarix.config.get_settings_file") as mock_get:
                p = MagicMock(spec=Path)
                p.exists.return_value = False
                mock_get.return_value = p
                store = SettingsStore()
                assert "_home_dir" in store._data


# ═══════════════════════════════════════════════════════════════════
# context.py (55% - missing many lines)
# ═══════════════════════════════════════════════════════════════════
class TestConfigEdgeCases:
    """Cover remaining config.py uncovered lines."""

    @patch.dict(os.environ, {"SIYARIX_PERSONA": "bug_hunter"}, clear=True)
    def test_env_override_persona(self):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_settings_file") as mock_get:
            p = MagicMock(spec=Path)
            p.exists.return_value = False
            mock_get.return_value = p
            store = SettingsStore()
            assert store._data.get("persona") == "bug_hunter"

    @patch.dict(os.environ, {"SIYARIX_SAFE_MODE": "1"}, clear=True)
    def test_env_override_bool_safe_mode(self):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_settings_file") as mock_get:
            p = MagicMock(spec=Path)
            p.exists.return_value = False
            mock_get.return_value = p
            store = SettingsStore()
            assert store._data.get("_safe_mode") is True

    @patch.dict(os.environ, {"SIYARIX_TIMEOUT": "invalid"}, clear=True)
    def test_env_override_timeout_invalid_ignored(self):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_settings_file") as mock_get:
            p = MagicMock(spec=Path)
            p.exists.return_value = False
            mock_get.return_value = p
            store = SettingsStore()
            # Should keep default since ValueError is caught
            assert store._data.get("scan_timeout") == DEFAULTS["scan_timeout"]

    @patch.dict(os.environ, {"SIYARIX_CONFIG": "/tmp/custom"}, clear=True)
    def test_env_override_config_path(self):
        from siyarix.config import SettingsStore
        with patch("siyarix.config.get_settings_file") as mock_get:
            p = MagicMock(spec=Path)
            p.exists.return_value = False
            mock_get.return_value = p
            store = SettingsStore()
            assert "_config_path" in store._data

    def test_write_toml_bool_and_float(self, tmp_path):
        p = tmp_path / "out.toml"
        _write_toml(p, {"flag": True, "rate": 3.5, "name": "test"})
        assert p.exists()
        content = p.read_text()
        assert "true" in content
        assert "test" in content
        assert "3.5" in content

    def test_save_backup_exception_still_saves(self, tmp_path):
        store = SettingsStore(path=tmp_path / "settings.toml")
        store._data["key"] = "value"
        with patch.object(store, "backup", side_effect=Exception("backup fail")):
            store._save()
            assert (tmp_path / "settings.toml").exists()

    def test_restore_latest_success(self, tmp_path):
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(parents=True)
        bk = backup_dir / "settings_20250101_120000.toml"
        bk.write_text("key = true")
        with patch("siyarix.config.get_config_dir", return_value=tmp_path):
            with patch("siyarix.config.get_settings_file", return_value=tmp_path / "settings.toml"):
                result = SettingsStore.restore_latest()
                assert result is not None

    def test_reset_single_key(self):
        store = SettingsStore()
        store._data["scan_timeout"] = 999
        store.reset("scan_timeout")
        assert store._data["scan_timeout"] == DEFAULTS["scan_timeout"]

    def test_reset_unknown_key_raises(self):
        store = SettingsStore()
        with pytest.raises(KeyError, match="Unknown setting"):
            store.reset("nonexistent_key")

    def test_coerce_bool_value_from_bool(self):
        store = SettingsStore()
        result = store._coerce("auto_sync", True)
        assert result is True

    def test_coerce_int_value_from_int(self):
        store = SettingsStore()
        result = store._coerce("scan_timeout", 42)
        assert result == 42

    def test_coerce_float_value_from_float(self):
        store = SettingsStore()
        orig = DEFAULTS.get("scan_timeout")
        DEFAULTS["scan_timeout"] = 3.0
        try:
            result = store._coerce("scan_timeout", 2.5)
            assert isinstance(result, float)
        finally:
            if orig is not None:
                DEFAULTS["scan_timeout"] = orig
            else:
                del DEFAULTS["scan_timeout"]


# ═══════════════════════════════════════════════════════════════════
# 14. context.py (96% - missing post_init, window, compress, relevant)
# ═══════════════════════════════════════════════════════════════════
