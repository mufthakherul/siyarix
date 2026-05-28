# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.command_profiles — command profile management."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.command_profiles import CommandProfile, CommandProfileStore, JINJA_AVAILABLE


class TestCommandProfile:
    def test_attributes(self) -> None:
        p = CommandProfile(name="test", command="nmap -sV {{target}}", description="Scan", created_at="2024-01-01")
        assert p.name == "test"
        assert p.command == "nmap -sV {{target}}"
        assert p.description == "Scan"
        assert p.created_at == "2024-01-01"

    def test_defaults(self) -> None:
        p = CommandProfile(name="default", command="ls")
        assert p.description is None
        assert p.created_at is None


class TestCommandProfileStore:
    def test_list_profiles_empty(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        assert store.list_profiles() == []

    def test_list_credentials_alias(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        assert store.list_credentials() == []

    def test_save_and_list(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"

        profile = CommandProfile(name="nmap_scan", command="nmap -sV {{target}}")
        store.save(profile)

        profiles = store.list_profiles()
        assert len(profiles) == 1
        assert profiles[0].name == "nmap_scan"
        assert profiles[0].command == "nmap -sV {{target}}"

    def test_save_assigns_created_at(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"

        profile = CommandProfile(name="test", command="echo hello")
        saved = store.save(profile)
        assert saved.created_at is not None

    def test_get_existing(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        store.save(CommandProfile(name="test", command="ls"))

        result = store.get("test")
        assert result is not None
        assert result.name == "test"
        assert result.command == "ls"

    def test_get_missing(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        assert store.get("nonexistent") is None

    def test_delete_existing(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        store.save(CommandProfile(name="todelete", command="rm"))
        assert store.delete("todelete") is True
        assert store.get("todelete") is None

    def test_delete_missing(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        assert store.delete("nonexistent") is False

    def test_load_corrupted_file_returns_empty(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        store._file.write_text("not valid json{")
        assert store.list_profiles() == []

    def test_extract_placeholders_jinja(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        placeholders = store.extract_placeholders("nmap -p {{port}} {{target}}")
        assert sorted(placeholders) == ["port", "target"]

    def test_extract_placeholders_format(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        placeholders = store.extract_placeholders("nmap -p {port} {target}")
        assert sorted(placeholders) == ["port", "target"]

    def test_extract_placeholders_mixed(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        placeholders = store.extract_placeholders("nmap {{target}} -p {port}")
        assert sorted(placeholders) == ["port", "target"]

    def test_extract_placeholders_no_matches(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        assert store.extract_placeholders("ls -la") == []

    def test_render_without_jinja(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        with patch("siyarix.command_profiles.JINJA_AVAILABLE", False):
            result = store.render("nmap -p {port}", {"port": "9090"})
        assert result == "nmap -p 9090"

    def test_render_jinja_failure_falls_back_to_format(self, tmp_path: Path) -> None:
        if not JINJA_AVAILABLE:
            pytest.skip("Jinja2 not available")
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        with patch("siyarix.command_profiles.Template", side_effect=RuntimeError("jinja broke")):
            result = store.render("nmap -p {port}", {"port": "8080"})
        assert result == "nmap -p 8080"

    def test_extract_placeholders_deduplicates(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        placeholders = store.extract_placeholders("{{x}} {{x}} {x}")
        assert placeholders == ["x"]

    def test_render_with_jinja(self, tmp_path: Path) -> None:
        if not JINJA_AVAILABLE:
            pytest.skip("Jinja2 not available")
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        result = store.render("nmap -p {{port}} {{target}}", {"port": "80", "target": "example.com"})
        assert result == "nmap -p 80 example.com"

    def test_render_with_format_fallback(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        with patch("siyarix.command_profiles.JINJA_AVAILABLE", False):
            result = store.render("nmap -p {port} {target}", {"port": "443", "target": "test.com"})
        assert result == "nmap -p 443 test.com"

    def test_render_no_params(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        result = store.render("ls -la")
        assert result == "ls -la"

    def test_render_missing_param_returns_original(self, tmp_path: Path) -> None:
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        with patch("siyarix.command_profiles.JINJA_AVAILABLE", False):
            result = store.render("nmap {port}", {"target": "x"})
        assert result == "nmap {port}"

    def test_render_jinja_failure_falls_back(self, tmp_path: Path) -> None:
        if not JINJA_AVAILABLE:
            pytest.skip("Jinja2 not available")
        store = CommandProfileStore()
        store._dir = tmp_path
        store._file = tmp_path / "command_profiles.json"
        result = store.render("nmap {{port}}", {"port": "80"})
        assert result == "nmap 80"
