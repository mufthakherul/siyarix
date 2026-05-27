"""Tests for siyarix.environment — env file helpers."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch


from siyarix.environment import (
    _quote,
    _strip_quotes,
    ensure_env_file,
    key_value_or_default,
    load_env_file,
    provider_env_var,
    upsert_env_vars,
)


class TestStripQuotes:
    def test_no_quotes(self) -> None:
        assert _strip_quotes("hello") == "hello"

    def test_double_quotes(self) -> None:
        assert _strip_quotes('"hello"') == "hello"

    def test_single_quotes(self) -> None:
        assert _strip_quotes("'hello'") == "hello"

    def test_mismatched_quotes(self) -> None:
        assert _strip_quotes('"hello') == '"hello'

    def test_strip_whitespace(self) -> None:
        assert _strip_quotes('  "hello"  ') == "hello"

    def test_single_char(self) -> None:
        assert _strip_quotes('"a"') == "a"


class TestQuote:
    def test_basic(self) -> None:
        assert _quote("hello") == '"hello"'

    def test_with_backslash(self) -> None:
        assert _quote('path\\to') == '"path\\\\to"'

    def test_with_double_quote(self) -> None:
        assert _quote('say "hi"') == '"say \\"hi\\""'

    def test_empty(self) -> None:
        assert _quote("") == '""'


class TestEnsureEnvFile:
    def test_exists_returns_path(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING=1")
        result = ensure_env_file(env_file)
        assert result == env_file
        assert env_file.read_text() == "EXISTING=1"

    def test_creates_from_example(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        example = tmp_path / ".env.example"
        example.write_text("# Example\nKEY=VALUE\n")
        with patch("siyarix.environment.ENV_EXAMPLE_FILE", example):
            result = ensure_env_file(env_file)
        assert result == env_file
        assert env_file.read_text() == "# Example\nKEY=VALUE\n"

    def test_creates_default(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        nonexistent = tmp_path / "nonexistent_example.env"
        with patch("siyarix.environment.ENV_EXAMPLE_FILE", nonexistent):
            result = ensure_env_file(env_file)
        assert result == env_file
        content = env_file.read_text()
        assert "# Siyarix environment file" in content
        assert "OPENAI_API_KEY=REPLACE_ME" in content
        assert "SIYARIX_API_KEY=" in content


class TestLoadEnvFile:
    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_env_file(tmp_path / "nonexistent.env")
        assert result == {}

    def test_loads_key_values(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        env_file = tmp_path / ".env"
        env_file.write_text('KEY=value\nNUM=42\nQUOTED="hello world"\n')
        try:
            result = load_env_file(env_file, override=True)
            assert result == {"KEY": "value", "NUM": "42", "QUOTED": "hello world"}
            assert os.environ.get("KEY") == "value"
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_skips_placeholders(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=REPLACE_ME\nACTUAL=real\n")
        try:
            result = load_env_file(env_file, override=True)
            assert "KEY" in result
            assert os.environ.get("KEY") is None
            assert os.environ.get("ACTUAL") == "real"
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\nKEY=val\n")
        try:
            result = load_env_file(env_file, override=True)
            assert result == {"KEY": "val"}
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_skips_lines_without_equals(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=val\nNOT_A_KV_LINE\nOTHER=thing\n")
        try:
            result = load_env_file(env_file, override=True)
            assert result == {"KEY": "val", "OTHER": "thing"}
            assert "NOT_A_KV_LINE" not in result
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_no_override_existing(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        os.environ["EXISTING"] = "oldval"
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING=newval\n")
        try:
            result = load_env_file(env_file, override=False)
            assert result == {"EXISTING": "newval"}
            assert os.environ["EXISTING"] == "oldval"
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_override_existing(self, tmp_path: Path) -> None:
        backup = os.environ.copy()
        os.environ["EXISTING"] = "oldval"
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING=newval\n")
        try:
            result = load_env_file(env_file, override=True)
            assert result == {"EXISTING": "newval"}
            assert os.environ["EXISTING"] == "newval"
        finally:
            os.environ.clear()
            os.environ.update(backup)


class TestUpsertEnvVars:
    def test_upsert_existing_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\nKEY=old\nOTHER=keep\n")
        upsert_env_vars({"KEY": "new"}, env_file)
        content = env_file.read_text()
        assert "KEY=\"new\"" in content
        assert "OTHER=keep" in content

    def test_upsert_new_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING=val\n")
        upsert_env_vars({"NEW_KEY": "new_val"}, env_file)
        content = env_file.read_text()
        assert "NEW_KEY=\"new_val\"" in content

    def test_upsert_remove_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value\n")
        upsert_env_vars({"KEY": None}, env_file)
        content = env_file.read_text()
        assert "KEY=" in content

    def test_preserves_comments(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("# top comment\nKEY=old\n# bottom\n")
        upsert_env_vars({"KEY": "new"}, env_file)
        content = env_file.read_text()
        assert "# top comment" in content
        assert "# bottom" in content

    def test_empty_file_adds_all(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("")
        upsert_env_vars({"A": "1", "B": "2"}, env_file)
        content = env_file.read_text()
        assert 'A="1"' in content
        assert 'B="2"' in content

    def test_ensures_file_exists(self, tmp_path: Path) -> None:
        env_file = tmp_path / "new.env"
        result = upsert_env_vars({"K": "v"}, env_file)
        assert result.exists()
        assert 'K="v"' in result.read_text()


class TestKeyValueOrDefault:
    def test_key_exists(self) -> None:
        assert key_value_or_default({"a": "hello"}, "a") == "hello"

    def test_key_missing_returns_default(self) -> None:
        assert key_value_or_default({}, "missing", "fallback") == "fallback"

    def test_non_string_value(self) -> None:
        assert key_value_or_default({"num": 42}, "num") == "42"


class TestProviderEnvVar:
    def test_known_providers(self) -> None:
        assert provider_env_var("openai") == "OPENAI_API_KEY"
        assert provider_env_var("gemini") == "GEMINI_API_KEY"
        assert provider_env_var("anthropic") == "ANTHROPIC_API_KEY"
        assert provider_env_var("siyarix") == "SIYARIX_API_KEY"

    def test_normalizes_input(self) -> None:
        assert provider_env_var("  OpenAI  ") == "OPENAI_API_KEY"
        assert provider_env_var("GEMINI") == "GEMINI_API_KEY"

    def test_custom_provider(self) -> None:
        assert provider_env_var("custom_provider") == "CUSTOM_PROVIDER_API_KEY"
