# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for config.py — SettingsStore (140 stmts, ~56% covered)."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from siyarix.config import (
    DEFAULTS,
    SettingsStore,
    _try_load_toml,
    _write_toml,
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
