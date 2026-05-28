# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.achievement — achievement & gamification system."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.achievement import (
    BUILTIN_ACHIEVEMENTS,
    Achievement,
    AchievementSystem,
    achievement_system,
)

TEST_ACHIEVEMENTS_DATA = {
    "first_scan": {"name": "Custom", "description": "Custom desc", "icon": "🎯", "category": "scanning", "tier": "gold", "unlocked_at": "2024-01-01", "progress": 1, "target": 1}
}


class TestAchievement:
    def test_defaults(self) -> None:
        a = Achievement(id="test", name="Test", description="Test badge")
        assert a.icon == "🏆"
        assert a.category == "general"
        assert a.tier == "bronze"
        assert a.unlocked_at == ""
        assert a.progress == 0
        assert a.target == 1

    def test_unlocked_property_true(self) -> None:
        a = Achievement(id="test", name="Test", description="Test", unlocked_at="2024-01-01", progress=1, target=1)
        assert a.unlocked is True

    def test_unlocked_property_false_empty_at(self) -> None:
        a = Achievement(id="test", name="Test", description="Test", progress=1, target=1)
        assert a.unlocked is False

    def test_unlocked_property_false_insufficient_progress(self) -> None:
        a = Achievement(id="test", name="Test", description="Test", unlocked_at="2024-01-01", progress=0, target=1)
        assert a.unlocked is False


class TestAchievementSystem:
    @pytest.fixture
    def system(self, tmp_path: Path) -> AchievementSystem:
        test_dir = tmp_path / "achievements"
        test_dir.mkdir(parents=True, exist_ok=True)
        with patch("siyarix.achievement.ACHIEVEMENTS_DIR", test_dir):
            sys = AchievementSystem.__new__(AchievementSystem)
            sys._file = test_dir / "achievements.json"
            sys._achievements = {}
            sys._load()
            return sys

    def test_init_creates_dir(self, tmp_path: Path) -> None:
        test_dir = tmp_path / "achievements_init"
        with patch("siyarix.achievement.ACHIEVEMENTS_DIR", test_dir):
            sys = AchievementSystem()
            assert sys._file.parent.exists()

    def test_init_loads_builtin_when_no_file(self, system: AchievementSystem) -> None:
        assert len(system._achievements) == len(BUILTIN_ACHIEVEMENTS)

    def test_init_loads_from_file(self, tmp_path: Path) -> None:
        test_dir = tmp_path / "achievements_load"
        test_dir.mkdir(parents=True, exist_ok=True)
        f = test_dir / "achievements.json"
        f.write_text(json.dumps(TEST_ACHIEVEMENTS_DATA), encoding="utf-8")
        with patch("siyarix.achievement.ACHIEVEMENTS_DIR", test_dir):
            sys = AchievementSystem()
        assert sys._achievements["first_scan"].name == "Custom"
        assert sys._achievements["first_scan"].unlocked is True

    def test_init_loads_on_corrupt_file(self, tmp_path: Path) -> None:
        test_dir = tmp_path / "achievements_corrupt"
        test_dir.mkdir(parents=True, exist_ok=True)
        f = test_dir / "achievements.json"
        f.write_text("not json", encoding="utf-8")
        with patch("siyarix.achievement.ACHIEVEMENTS_DIR", test_dir):
            sys = AchievementSystem()
        assert len(sys._achievements) == len(BUILTIN_ACHIEVEMENTS)

    def test_save_and_load_roundtrip(self, system: AchievementSystem) -> None:
        system.progress("first_scan")
        sys2 = AchievementSystem.__new__(AchievementSystem)
        sys2._file = system._file
        sys2._achievements = {}
        sys2._load()
        assert sys2._achievements["first_scan"].progress == 1

    def test_list_all(self, system: AchievementSystem) -> None:
        all_ach = system.list_all()
        assert len(all_ach) == len(BUILTIN_ACHIEVEMENTS)

    def test_list_unlocked_empty(self, system: AchievementSystem) -> None:
        assert system.list_unlocked() == []

    def test_list_unlocked_after_progress(self, system: AchievementSystem) -> None:
        system.progress("first_scan")
        unlocked = system.list_unlocked()
        assert len(unlocked) == 1
        assert unlocked[0].id == "first_scan"

    def test_list_locked(self, system: AchievementSystem) -> None:
        locked = system.list_locked()
        assert len(locked) == len(BUILTIN_ACHIEVEMENTS)

    def test_get_by_category(self, system: AchievementSystem) -> None:
        scans = system.get_by_category("scanning")
        assert all(a.category == "scanning" for a in scans)
        assert len(scans) > 0

    def test_get_by_category_empty(self, system: AchievementSystem) -> None:
        assert system.get_by_category("nonexistent") == []

    def test_progress_normal(self, system: AchievementSystem) -> None:
        ach = system.progress("first_scan")
        assert ach is not None
        assert ach.progress == 1
        assert ach.unlocked is True

    def test_progress_already_unlocked(self, system: AchievementSystem) -> None:
        system.progress("first_scan")
        ach2 = system.progress("first_scan")
        assert ach2 is not None
        assert ach2.progress == 1

    def test_progress_nonexistent(self, system: AchievementSystem) -> None:
        assert system.progress("nonexistent") is None

    def test_progress_multi_step(self, system: AchievementSystem) -> None:
        for _ in range(3):
            system.progress("ten_scans")
        assert system._achievements["ten_scans"].progress == 3

    def test_check_and_award_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("scan")
        assert system._achievements["first_scan"].unlocked is True

    def test_check_and_award_scan_perfect(self, system: AchievementSystem) -> None:
        system.check_and_award("scan", metadata={"all_success": True})
        assert system._achievements["perfect_scan"].unlocked is True

    def test_check_and_award_finding(self, system: AchievementSystem) -> None:
        system.check_and_award("finding")
        assert system._achievements["first_vuln"].unlocked is True

    def test_check_and_award_finding_critical(self, system: AchievementSystem) -> None:
        system.check_and_award("finding", metadata={"severity": "critical"})
        assert system._achievements["first_critical"].unlocked is True

    def test_check_and_award_tool_used(self, system: AchievementSystem) -> None:
        system.check_and_award("tool_used")
        assert system._achievements["first_tool"].unlocked is True

    def test_check_and_award_stealth_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("stealth_scan")
        assert system._achievements["stealth_ten"].progress == 1

    def test_check_and_award_learning_module(self, system: AchievementSystem) -> None:
        system.check_and_award("learning_module")
        assert system._achievements["first_learning"].unlocked is True

    def test_check_and_award_report_generated(self, system: AchievementSystem) -> None:
        system.check_and_award("report_generated")
        assert system._achievements["first_report"].unlocked is True

    def test_check_and_award_playbook_created(self, system: AchievementSystem) -> None:
        system.check_and_award("playbook_created")
        assert system._achievements["first_playbook"].unlocked is True

    def test_check_and_award_ctf_joined(self, system: AchievementSystem) -> None:
        system.check_and_award("ctf_joined")

    def test_check_and_award_agent_spawned(self, system: AchievementSystem) -> None:
        system.check_and_award("agent_spawned")
        assert system._achievements["first_agent"].unlocked is True

    def test_check_and_award_mobile_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("mobile_scan")
        assert system._achievements["first_mobile"].unlocked is True

    def test_check_and_award_iot_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("iot_scan")
        assert system._achievements["first_iot"].unlocked is True

    def test_check_and_award_iac_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("iac_scan")
        assert system._achievements["first_iac"].unlocked is True

    def test_check_and_award_cloud_scan(self, system: AchievementSystem) -> None:
        system.check_and_award("cloud_scan")
        assert system._achievements["first_cloud"].unlocked is True

    def test_check_and_award_compliance_run(self, system: AchievementSystem) -> None:
        system.check_and_award("compliance_run")
        assert system._achievements["compliance_first"].unlocked is True

    def test_check_and_award_opsec_activated(self, system: AchievementSystem) -> None:
        system.check_and_award("opsec_activated")
        assert system._achievements["first_opsec"].unlocked is True

    def test_check_and_award_unknown_event(self, system: AchievementSystem) -> None:
        system.check_and_award("unknown_event")

    def test_summary_all_locked(self, system: AchievementSystem) -> None:
        s = system.summary()
        assert s["total"] == len(BUILTIN_ACHIEVEMENTS)
        assert s["unlocked"] == 0
        assert s["locked"] == len(BUILTIN_ACHIEVEMENTS)

    def test_summary_some_unlocked(self, system: AchievementSystem) -> None:
        system.progress("first_scan")
        system.progress("first_vuln")
        s = system.summary()
        assert s["unlocked"] == 2

    def test_save_error_handled(self, system: AchievementSystem) -> None:
        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            system._save()

    def test_singleton_exists(self) -> None:
        assert achievement_system is not None
