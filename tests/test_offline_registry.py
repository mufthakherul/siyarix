# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.offline_registry — Offline Response Registry."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

pass  # offline_registry removed OfflineResponder
pass  # removed best_match, match_entry
pass  # removed ResponseEntry, ResponseRegistry
pass  # removed known_variables, resolve


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_pack() -> dict:
    return {
        "version": "1.0",
        "locale": "en",
        "responses": [
            {
                "id": "greeting",
                "priority": 100,
                "triggers": ["hello", "hi", "hey"],
                "patterns": [],
                "template": "Hello {username}. Good {time_of_day}.",
                "match_threshold": 0.7,
            },
            {
                "id": "goodbye",
                "priority": 60,
                "triggers": ["bye", "goodbye"],
                "patterns": [],
                "template": "Goodbye {username}.",
                "match_threshold": 0.7,
            },
            {
                "id": "regex_test",
                "priority": 50,
                "triggers": [],
                "patterns": ["\\b(great|awesome)\\b.*\\b(job|work)\\b"],
                "template": "Regex matched!",
                "match_threshold": 0.7,
            },
        ],
    }


@pytest.fixture
def pack_dir(sample_pack: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "responses.json").write_text(json.dumps(sample_pack), encoding="utf-8")
    return d


# ---------------------------------------------------------------------------
# VariableResolver
# ---------------------------------------------------------------------------


class TestVariableResolver:
    def test_resolves_username(self) -> None:
        result = resolve("Hello {username}")
        assert "{username}" not in result
        assert len(result) > 6

    def test_resolves_hostname(self) -> None:
        result = resolve("Host: {hostname}")
        assert "{hostname}" not in result
        assert result.startswith("Host: ")

    def test_resolves_platform(self) -> None:
        result = resolve("Platform: {platform}")
        assert "{platform}" not in result
        assert result.startswith("Platform: ")

    def test_resolves_time_of_day(self) -> None:
        result = resolve("Good {time_of_day}")
        assert result in (
            "Good morning",
            "Good noon",
            "Good afternoon",
            "Good evening",
            "Good night",
        )

    def test_resolves_version(self) -> None:
        result = resolve("v{version}")
        assert "{version}" not in result
        assert "." in result

    def test_resolves_repo_url(self) -> None:
        result = resolve("{repo_url}")
        assert result.startswith("http")

    def test_unknown_variable_left_as_is(self) -> None:
        result = resolve("Hello {unknown_var}")
        assert "{unknown_var}" in result

    def test_multiple_variables(self) -> None:
        result = resolve("{username}@{hostname}")
        assert "@" in result
        assert "{username}" not in result
        assert "{hostname}" not in result

    def test_known_variables(self) -> None:
        varset = known_variables()
        assert "username" in varset
        assert "hostname" in varset
        assert "platform" in varset
        assert "time_of_day" in varset
        assert "version" in varset
        assert "repo_url" in varset


# ---------------------------------------------------------------------------
# TriggerMatcher
# ---------------------------------------------------------------------------


class TestTriggerMatcher:
    def test_exact_match_returns_1(self) -> None:
        entry = ResponseEntry(id="t", priority=50, triggers=["hello", "hi"])
        score = match_entry("hello", entry)
        assert score == 1.0

    def test_exact_match_case_insensitive(self) -> None:
        entry = ResponseEntry(id="t", priority=50, triggers=["Hello"])
        score = match_entry("hello", entry)
        assert score == 1.0

    def test_regex_pattern_matches(self) -> None:
        entry = ResponseEntry(id="t", priority=50, patterns=["\\bgreat\\b"])
        score = match_entry("great job", entry)
        assert score == 1.0

    def test_fuzzy_match_above_threshold(self) -> None:
        entry = ResponseEntry(id="t", priority=50, triggers=["hello"])
        score = match_entry("helo", entry, threshold=0.7)
        assert score >= 0.7

    def test_fuzzy_below_threshold_returns_0(self) -> None:
        entry = ResponseEntry(id="t", priority=50, triggers=["hello"])
        score = match_entry("xyzzy", entry, threshold=0.7)
        assert score == 0.0

    def test_no_match_returns_0(self) -> None:
        entry = ResponseEntry(id="t", priority=50, triggers=["hello"])
        score = match_entry("nmap scan", entry)
        assert score == 0.0


class TestBestMatch:
    def test_returns_highest_score_entry(self) -> None:
        entries = [
            ResponseEntry(id="a", priority=10, triggers=["hello"]),
            ResponseEntry(id="b", priority=50, triggers=["hi"]),
        ]
        result = best_match("hi", entries)
        assert result is not None
        assert result.id == "b"

    def test_priority_tiebreak(self) -> None:
        entries = [
            ResponseEntry(id="low", priority=10, triggers=["test"]),
            ResponseEntry(id="high", priority=100, triggers=["test"]),
        ]
        result = best_match("test", entries)
        assert result is not None
        assert result.id == "high"

    def test_none_when_no_match(self) -> None:
        entries = [
            ResponseEntry(id="a", priority=10, triggers=["hello"]),
        ]
        result = best_match("xyzzy", entries)
        assert result is None


# ---------------------------------------------------------------------------
# ResponseRegistry
# ---------------------------------------------------------------------------


class TestResponseRegistry:
    def test_loads_from_pack_dir(self, pack_dir: Path) -> None:
        reg = ResponseRegistry(pack_dir=str(pack_dir))
        reg.load()
        assert reg.entry_count() == 3
        assert reg.pack_count() == 1

    def test_entries_sorted_by_priority_descending(self, pack_dir: Path) -> None:
        reg = ResponseRegistry(pack_dir=str(pack_dir))
        reg.load()
        priorities = [e.priority for e in reg.entries]
        assert priorities == sorted(priorities, reverse=True)

    def test_hot_reload_detects_change(self, pack_dir: Path) -> None:
        reg = ResponseRegistry(pack_dir=str(pack_dir))
        reg.load()
        assert reg.entry_count() == 3

        pack_file = pack_dir / "responses.json"
        data = json.loads(pack_file.read_text(encoding="utf-8"))
        data["responses"].append({
            "id": "new_one",
            "priority": 1,
            "triggers": ["new"],
            "template": "New response",
        })
        pack_file.write_text(json.dumps(data), encoding="utf-8")

        assert reg.reload_if_changed() is True
        assert reg.entry_count() == 4

    def test_no_reload_when_unchanged(self, pack_dir: Path) -> None:
        reg = ResponseRegistry(pack_dir=str(pack_dir))
        reg.load()
        assert reg.reload_if_changed() is False

    def test_entries_property_auto_loads(self, pack_dir: Path) -> None:
        reg = ResponseRegistry(pack_dir=str(pack_dir))
        assert not reg._loaded
        assert reg.entry_count() == 3
        assert reg._loaded


# ---------------------------------------------------------------------------
# OfflineResponder (end-to-end)
# ---------------------------------------------------------------------------


class TestOfflineResponder:
    def test_respond_greeting_exact(self, pack_dir: Path) -> None:
        r = OfflineResponder(pack_dir=str(pack_dir))
        reply = r.respond("hello")
        assert reply is not None
        assert reply.startswith("Hello ")
        assert "Good " in reply

    def test_respond_fuzzy_match(self, pack_dir: Path) -> None:
        r = OfflineResponder(pack_dir=str(pack_dir))
        reply = r.respond("helo")
        assert reply is not None
        assert reply.startswith("Hello ")

    def test_respond_regex_match(self, pack_dir: Path) -> None:
        r = OfflineResponder(pack_dir=str(pack_dir))
        reply = r.respond("great job")
        assert reply is not None
        assert reply == "Regex matched!"

    def test_respond_none_on_no_match(self, pack_dir: Path) -> None:
        r = OfflineResponder(pack_dir=str(pack_dir))
        reply = r.respond("some random unheard-of query")
        assert reply is None

    def test_reload_if_changed(self, pack_dir: Path) -> None:
        r = OfflineResponder(pack_dir=str(pack_dir))
        assert r.reload_if_changed() is False

        pack_file = pack_dir / "responses.json"
        data = json.loads(pack_file.read_text(encoding="utf-8"))
        data["responses"][0]["triggers"].append("howdy")
        pack_file.write_text(json.dumps(data), encoding="utf-8")

        assert r.reload_if_changed() is True
        reply = r.respond("howdy")
        assert reply is not None
        assert reply.startswith("Hello ")

    def test_default_pack_loaded(self) -> None:
        r = OfflineResponder()
        reply = r.respond("hello")
        assert reply is not None
        assert "Siyarix" in reply

    def test_identity_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("who are you")
        assert reply is not None
        assert "Siyarix" in reply

    def test_creator_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("who created you")
        assert reply is not None
        assert "MUFTHAKHERUL" in reply

    def test_thanks_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("thanks")
        assert reply is not None
        assert "welcome" in reply.lower()

    def test_goodbye_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("bye")
        assert reply is not None
        assert "Goodbye" in reply

    def test_version_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("version")
        assert reply is not None
        assert "Version" in reply or "Registry Mode" in reply

    def test_status_response(self) -> None:
        r = OfflineResponder()
        reply = r.respond("status")
        assert reply is not None
        assert "Registry Mode" in reply or "Status Report" in reply


# ---------------------------------------------------------------------------
# Community pack loading
# ---------------------------------------------------------------------------


class TestCommunityPack:
    def test_loads_community_pack(self) -> None:
        r = OfflineResponder()
        reply = r.respond("community")
        assert reply is not None
        assert "community" in reply.lower() or "contributors" in reply.lower()
