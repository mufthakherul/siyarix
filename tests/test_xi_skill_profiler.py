# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the XI SkillProfiler module."""

from __future__ import annotations

from siyarix.xi.skill_profiler import SkillLevel, SkillProfile, SkillProfiler


class TestSkillProfiler:
    """Test suite for the Skill Profiler."""

    def test_initial_profile(self):
        sp = SkillProfiler()
        profile = sp.profile
        assert profile.level == SkillLevel.INTERMEDIATE
        assert profile.score == 50.0
        assert profile.total_commands == 0

    def test_record_command_basic(self):
        sp = SkillProfiler()
        sp.record_command("nmap -sV target", tool="nmap", success=True)
        assert sp.profile.total_commands == 1
        assert sp.profile.unique_tools == 1

    def test_record_command_failure(self):
        sp = SkillProfiler()
        sp.record_command("nmap -sV target", tool="nmap", success=False)
        assert sp.profile.error_rate > 0

    def test_advanced_feature_detection(self):
        sp = SkillProfiler()
        sp.record_command("nmap --parallel target", tool="nmap", success=True)
        sp.record_command("sqlmap -u target", tool="sqlmap", success=True)
        sp.record_command("msfconsole -q", tool="msfconsole", success=True)
        # Need 5 commands to trigger reassessment
        sp.record_command("nmap target", tool="nmap", success=True)
        sp.record_command("nuclei -u target", tool="nuclei", success=True)
        assert sp.profile.advanced_features_used >= 2

    def test_beginner_profile(self):
        sp = SkillProfiler()
        for _ in range(5):
            sp.record_command("nmap target", tool="nmap", success=False)  # all fail
        assert sp.profile.score < 50

    def test_expert_profile(self):
        sp = SkillProfiler()
        for i in range(60):
            tool = [
                "nmap",
                "nuclei",
                "sqlmap",
                "hydra",
                "gobuster",
                "ffuf",
                "wpscan",
                "nikto",
            ][i % 8]
            command = f"{tool} --parallel --persist target"
            sp.record_command(command, tool=tool, success=True)
        # Trigger final assessment
        profile = sp.profile
        assert profile.score >= 50

    def test_verbosity_mapping(self):
        assert SkillProfile(level=SkillLevel.BEGINNER).verbosity == "verbose"
        assert SkillProfile(level=SkillLevel.INTERMEDIATE).verbosity == "normal"
        assert SkillProfile(level=SkillLevel.ADVANCED).verbosity == "compact"
        assert SkillProfile(level=SkillLevel.EXPERT).verbosity == "minimal"

    def test_show_hints(self):
        assert SkillProfile(level=SkillLevel.BEGINNER).show_hints is True
        assert SkillProfile(level=SkillLevel.INTERMEDIATE).show_hints is True
        assert SkillProfile(level=SkillLevel.ADVANCED).show_hints is False
        assert SkillProfile(level=SkillLevel.EXPERT).show_hints is False

    def test_auto_confirm_safe(self):
        assert SkillProfile(level=SkillLevel.EXPERT).auto_confirm_safe is True
        assert SkillProfile(level=SkillLevel.BEGINNER).auto_confirm_safe is False

    def test_to_dict(self):
        profile = SkillProfile(level=SkillLevel.ADVANCED, score=72.5, total_commands=30)
        d = profile.to_dict()
        assert d["level"] == SkillLevel.ADVANCED
        assert d["score"] == 72.5
        assert d["verbosity"] == "compact"

    def test_reset(self):
        sp = SkillProfiler()
        sp.record_command("nmap target", tool="nmap", success=True)
        sp.reset()
        assert sp.profile.total_commands == 0
        assert sp.profile.score == 50.0

    def test_skill_level_all(self):
        levels = SkillLevel.all()
        assert len(levels) == 4
        assert SkillLevel.BEGINNER in levels
        assert SkillLevel.EXPERT in levels

    def test_assessment_trigger_on_multiple_of_5(self):
        sp = SkillProfiler()
        # Record exactly 4 commands — no assessment yet
        for i in range(4):
            sp.record_command(f"nmap target{i}", tool="nmap", success=True)
        assert sp.profile.total_commands == 4
        # 5th command triggers assessment
        sp.record_command("nuclei target", tool="nuclei", success=True)
        assert sp.profile.unique_tools == 2
