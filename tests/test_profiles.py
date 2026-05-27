"""Tests for siyarix.profiles — profile and workspace configuration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siyarix.profiles import ProfileStore, _config_dir


def test_config_dir_default() -> None:
    result = _config_dir()
    assert result == Path.home() / ".siyarix"


def test_config_dir_with_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", "/tmp/custom_config")
    result = _config_dir()
    assert result == Path("/tmp/custom_config")


class TestProfileStore:
    def test_init_creates_directory(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path / "new_dir"
        store._profiles_file = store._dir / "profiles.json"
        store._dir.mkdir(parents=True, exist_ok=True)
        assert store._dir.exists()

    def test_load_empty_returns_defaults(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        data = store.load()
        assert data == {"active_profile": "default", "profiles": {}}

    def test_load_missing_profiles_key(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text(json.dumps({"active_profile": "custom"}))
        data = store.load()
        assert data["profiles"] == {}
        assert data["active_profile"] == "custom"

    def test_load_missing_active_profile_key(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text(json.dumps({"profiles": {}}))
        data = store.load()
        assert data["active_profile"] == "default"

    def test_load_corrupted_file_returns_defaults(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text("not valid json")
        data = store.load()
        assert data == {"active_profile": "default", "profiles": {}}

    def test_save(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        data = json.loads(store._profiles_file.read_text())
        assert data["active_profile"] == "default"

    def test_get_active_profile_with_profiles(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text(
            json.dumps(
                {
                    "active_profile": "default",
                    "profiles": {
                        "default": {"last_used_at": "2024-01-01"},
                        "work": {"last_used_at": "2024-02-01"},
                    },
                }
            )
        )
        result = store.get_active_profile()
        assert result == "default"

    def test_get_active_profile_fallback_to_most_recent(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text(
            json.dumps(
                {
                    "active_profile": "nonexistent",
                    "profiles": {
                        "old": {"last_used_at": "2024-01-01"},
                        "new": {"last_used_at": "2024-02-01"},
                    },
                }
            )
        )
        result = store.get_active_profile()
        assert result == "new"

    def test_get_active_profile_no_profiles(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store._profiles_file.write_text(
            json.dumps({"active_profile": "default", "profiles": {}})
        )
        result = store.get_active_profile()
        assert result == "default"

    def test_set_active_profile(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "default",
                "profiles": {
                    "myprofile": {"last_used_at": "2024-01-01", "server_url": "https://x.com"}
                },
            }
        )
        store.set_active_profile("myprofile")
        data = json.loads(store._profiles_file.read_text())
        assert data["active_profile"] == "myprofile"
        assert "last_used_at" in data["profiles"]["myprofile"]

    def test_set_active_profile_not_found(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        with pytest.raises(ValueError, match="not found"):
            store.set_active_profile("nonexistent")

    def test_list_profiles(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "main",
                "profiles": {
                    "main": {"server_url": "https://a.com", "last_used_at": "2024-01-01"},
                    "dev": {"server_url": "https://b.com", "last_used_at": "2024-02-01"},
                },
            }
        )
        profiles = store.list_profiles()
        assert len(profiles) == 2
        main_profile = [p for p in profiles if p["name"] == "main"][0]
        assert main_profile["active"] is True
        dev_profile = [p for p in profiles if p["name"] == "dev"][0]
        assert dev_profile["active"] is False

    def test_get_profile_by_name(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "default",
                "profiles": {
                    "test": {
                        "server_url": "https://test.com",
                        "org_id": "org123",
                        "auth_method": "oauth",
                    }
                },
            }
        )
        profile = store.get_profile("test")
        assert profile is not None
        assert profile["name"] == "test"
        assert profile["server_url"] == "https://test.com"
        assert profile["org_id"] == "org123"
        assert profile["auth_method"] == "oauth"

    def test_get_profile_default(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "default",
                "profiles": {
                    "default": {"server_url": "https://default.com"}
                },
            }
        )
        profile = store.get_profile()
        assert profile is not None
        assert profile["name"] == "default"

    def test_get_profile_nonexistent(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        assert store.get_profile("nonexistent") is None

    def test_upsert_profile_creates_new(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        result = store.upsert_profile(
            "newprofile",
            server_url="https://siyarix.cloud",
            org_id="org_1",
            auth_method="api_key",
            default_target="example.com",
            default_output_format="json",
        )
        assert result["name"] == "newprofile"
        assert result["server_url"] == "https://siyarix.cloud"
        assert result["default_output_format"] == "json"

    def test_upsert_profile_updates_existing(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "existing",
                "profiles": {
                    "existing": {
                        "server_url": "https://old.com",
                        "auth_method": "api_key",
                        "default_output_format": "table",
                        "created_at": "2024-01-01",
                        "last_used_at": "2024-01-01",
                    }
                },
            }
        )
        result = store.upsert_profile(
            "existing",
            server_url="https://new.com",
            auth_method="oauth",
        )
        assert result["server_url"] == "https://new.com"
        assert result["auth_method"] == "oauth"
        assert result["created_at"] == "2024-01-01"  # preserved

    def test_upsert_profile_sets_active_when_unset(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        store.upsert_profile("first", server_url="https://x.com")
        data = json.loads(store._profiles_file.read_text())
        assert data["active_profile"] == "first"

    def test_delete_profile(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "default",
                "profiles": {
                    "default": {"server_url": "https://a.com", "last_used_at": "2024-01-01"},
                    "extra": {"server_url": "https://b.com", "last_used_at": "2024-02-01"},
                },
            }
        )
        assert store.delete_profile("extra") is True
        data = json.loads(store._profiles_file.read_text())
        assert "extra" not in data["profiles"]

    def test_delete_profile_nonexistent(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save({"active_profile": "default", "profiles": {}})
        assert store.delete_profile("nonexistent") is False

    def test_delete_active_profile_falls_back(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "main",
                "profiles": {
                    "main": {"server_url": "https://main.com", "last_used_at": "2024-01-01"},
                    "backup": {"server_url": "https://backup.com", "last_used_at": "2024-02-01"},
                },
            }
        )
        store.delete_profile("main")
        data = json.loads(store._profiles_file.read_text())
        assert data["active_profile"] == "backup"

    def test_delete_last_profile_resets_to_default(self, tmp_path: Path) -> None:
        store = ProfileStore()
        store._dir = tmp_path
        store._profiles_file = tmp_path / "profiles.json"
        store.save(
            {
                "active_profile": "onlyone",
                "profiles": {
                    "onlyone": {"server_url": "https://x.com", "last_used_at": "2024-01-01"}
                },
            }
        )
        store.delete_profile("onlyone")
        data = json.loads(store._profiles_file.read_text())
        assert data["active_profile"] == "default"
