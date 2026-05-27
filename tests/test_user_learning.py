"""Tests for siyarix.user_learning — user profile learning & adaptation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.user_learning import (
    _CVE_KNOWLEDGE,
    _MILESTONES,
    _TOOL_CATEGORIES,
    _TOOL_EXPLAINERS,
    ExperienceLevel,
    PedagogicalEngine,
    PedagogicalStep,
    SessionRecord,
    UserLearning,
    UserProfile,
)


# ── ExperienceLevel ────────────────────────────────────────────────────

class TestExperienceLevel:
    def test_all(self) -> None:
        assert ExperienceLevel.all() == ["novice", "intermediate", "advanced", "expert"]

    def test_auto_detect_novice(self) -> None:
        p = UserProfile(total_commands=1, unique_tools=1)
        assert ExperienceLevel.auto_detect(p) == "novice"

    def test_auto_detect_intermediate(self) -> None:
        p = UserProfile(total_commands=10, unique_tools=5, category_count=2, advanced_command_count=1)
        assert ExperienceLevel.auto_detect(p) == "intermediate"

    def test_auto_detect_advanced(self) -> None:
        p = UserProfile(total_commands=40, unique_tools=9, category_count=4, advanced_command_count=4)
        assert ExperienceLevel.auto_detect(p) == "advanced"

    def test_auto_detect_expert(self) -> None:
        p = UserProfile(total_commands=200, unique_tools=15, category_count=5, advanced_command_count=8)
        assert ExperienceLevel.auto_detect(p) == "expert"

    def test_auto_detect_high_error_rate(self) -> None:
        p = UserProfile(total_commands=20, unique_tools=5, category_count=2, advanced_command_count=1, error_rate=0.5)
        assert ExperienceLevel.auto_detect(p) == "novice"  # heavily penalized

    def test_auto_detect_medium_error_rate(self) -> None:
        p = UserProfile(total_commands=100, unique_tools=10, category_count=4, advanced_command_count=5, total_errors=30)
        p.error_rate = 0.3
        result = ExperienceLevel.auto_detect(p)
        assert isinstance(result, str)

    def test_auto_detect_zero_commands(self) -> None:
        p = UserProfile()
        assert ExperienceLevel.auto_detect(p) == "novice"


# ── SessionRecord ──────────────────────────────────────────────────────

class TestSessionRecord:
    def test_defaults(self) -> None:
        s = SessionRecord()
        assert s.session_id == ""
        assert s.command_count == 0
        assert s.tools_used == []
        assert s.pedagogical_steps == 0

    def test_to_dict(self) -> None:
        s = SessionRecord(session_id="s1", command_count=5, tools_used=["nmap"], duration_seconds=100.0)
        d = s.to_dict()
        assert d["session_id"] == "s1"
        assert d["command_count"] == 5
        assert d["duration_seconds"] == 100.0

    def test_from_dict(self) -> None:
        data = {"session_id": "s1", "command_count": 3, "tools_used": ["nmap"]}
        s = SessionRecord.from_dict(data)
        assert s.session_id == "s1"
        assert s.command_count == 3

    def test_from_dict_ignores_extra_keys(self) -> None:
        data = {"session_id": "s1", "command_count": 3, "extra_field": "ignored"}
        s = SessionRecord.from_dict(data)
        assert not hasattr(s, "extra_field")


# ── UserProfile ────────────────────────────────────────────────────────

class TestUserProfile:
    def test_defaults(self) -> None:
        p = UserProfile()
        assert p.experience == ExperienceLevel.INTERMEDIATE
        assert p.auto_detect is True
        assert p.total_commands == 0
        assert p.preferences["verbosity"] == "adaptive"

    def test_to_dict(self) -> None:
        p = UserProfile(username="test_user", total_commands=10, session_count=1)
        d = p.to_dict()
        assert d["username"] == "test_user"
        assert d["total_commands"] == 10
        assert isinstance(d["error_rate"], float)

    def test_to_dict_truncates_recent_tools(self) -> None:
        p = UserProfile(recent_tools=[f"t{i}" for i in range(60)])
        d = p.to_dict()
        assert len(d["recent_tools"]) == 50

    def test_from_dict(self) -> None:
        data = {"username": "test", "total_commands": 5, "experience": "expert", "sessions": [{"session_id": "s1", "command_count": 2}]}
        p = UserProfile.from_dict(data)
        assert p.username == "test"
        assert p.total_commands == 5
        assert p.experience == "expert"
        assert len(p.sessions) == 1

    def test_from_dict_empty(self) -> None:
        p = UserProfile.from_dict({})
        assert p.username == ""
        assert p.experience == "intermediate"

    def test_error_rate_calculation(self) -> None:
        p = UserProfile(total_errors=3, total_commands=10)
        p.error_rate = 0.3
        assert p.error_rate == 0.3

    def test_category_counts(self) -> None:
        p = UserProfile(category_counts={"recon": 5, "web": 3}, category_count=2)
        assert p.category_count == 2
        assert p.category_counts["recon"] == 5


# ── PedagogicalEngine ──────────────────────────────────────────────────

class TestPedagogicalEngine:
    @pytest.fixture
    def engine(self) -> PedagogicalEngine:
        return PedagogicalEngine()

    def test_generate_step_title_with_category(self, engine: PedagogicalEngine) -> None:
        title = engine._generate_step_title("nmap", "nmap -sV target", "tool_run")
        assert "Reconnaissance" in title
        assert "nmap" in title

    def test_generate_step_title_exploit(self, engine: PedagogicalEngine) -> None:
        title = engine._generate_step_title("hydra", "hydra -l admin ...", "tool_run")
        assert "Exploitation" in title

    def test_generate_step_title_unknown_tool(self, engine: PedagogicalEngine) -> None:
        title = engine._generate_step_title("custom_tool", "", "")
        assert title == "Custom_Tool Scan"

    def test_generate_step_title_from_step_type(self, engine: PedagogicalEngine) -> None:
        title = engine._generate_step_title("", "", "analysis_step")
        assert title == "Analysis Step"

    def test_generate_step_title_fallback(self, engine: PedagogicalEngine) -> None:
        title = engine._generate_step_title("", "", "")
        assert title == "Analysis Step"

    def test_explain_what_happened_known_tool(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_happened("nmap", "nmap target", "output")
        assert text == _TOOL_EXPLAINERS["nmap"]["what_happened"]

    def test_explain_what_happened_operation_match(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_happened("", "port_scan target", "")
        assert "thousands of ports" in text

    def test_explain_what_happened_fallback(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_happened("", "", "")
        assert "executed the" in text

    def test_explain_what_happened_with_command(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_happened("", "some_command --flag", "output_data")
        assert "some_command" in text

    def test_explain_what_it_means_known_tool(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_it_means("nmap", "nmap target", "")
        assert _TOOL_EXPLAINERS["nmap"]["what_it_means"] in text

    def test_explain_what_it_means_operation_match(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_it_means("", "exploit --target", "")
        assert "Successful exploitation" in text

    def test_explain_what_it_means_fallback(self, engine: PedagogicalEngine) -> None:
        text = engine._explain_what_it_means("", "", "")
        assert "potential security issue" in text

    def test_generate_breakdown_basic(self, engine: PedagogicalEngine) -> None:
        steps = [{"tool": "nmap", "command": "nmap -sV target", "output": "Open ports: 22, 80"}]
        result = engine.generate_breakdown(steps)
        assert len(result) == 1
        assert result[0].title == "Reconnaissance (nmap)"
        assert result[0].command == "nmap -sV target"
        assert "specially crafted packets" in result[0].what_happened

    def test_generate_breakdown_with_cves(self, engine: PedagogicalEngine) -> None:
        steps = [{"tool": "nuclei", "command": "nuclei -u target", "output": "Found CVE-2021-41773 Apache path traversal"}]
        result = engine.generate_breakdown(steps)
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-41773"
        assert any("Apache" in d for d in result[0].details)

    def test_generate_breakdown_with_findings(self, engine: PedagogicalEngine) -> None:
        steps = [{"tool": "nmap", "command": "nmap target", "output": ""}]
        findings = [{"tool": "nmap", "severity": "critical", "description": "Open SSH port"}]
        result = engine.generate_breakdown(steps, findings)
        assert result[0].severity == "critical"

    def test_generate_breakdown_severity_high(self, engine: PedagogicalEngine) -> None:
        steps = [{"tool": "nmap", "command": "nmap target", "output": ""}]
        findings = [{"tool": "nmap", "severity": "high", "description": "Issue"}]
        result = engine.generate_breakdown(steps, findings)
        assert result[0].severity == "high"

    def test_generate_breakdown_severity_medium(self, engine: PedagogicalEngine) -> None:
        steps = [{"tool": "nmap", "command": "nmap target", "output": ""}]
        findings = [{"tool": "nmap", "severity": "medium", "description": "Medium issue"}]
        result = engine.generate_breakdown(steps, findings)
        assert result[0].severity == "medium"

    def test_generate_breakdown_empty(self, engine: PedagogicalEngine) -> None:
        assert engine.generate_breakdown([]) == []

    def test_display_breakdown_empty(self, engine: PedagogicalEngine) -> None:
        engine.display_breakdown([])

    def test_display_breakdown_steps(self, engine: PedagogicalEngine) -> None:
        mock_console = MagicMock()
        engine._console = mock_console
        steps = [PedagogicalStep(title="Step 1", command="nmap target", what_happened="Scan", what_it_means="Open ports")]
        engine.display_breakdown(steps)
        mock_console.print.assert_called()

    def test_display_detailed_step(self, engine: PedagogicalEngine) -> None:
        mock_console = MagicMock()
        engine._console = mock_console
        step = PedagogicalStep(title="Test", command="nmap target", what_happened="Scan", what_it_means="Open", cve_id="CVE-2021-41773")
        engine._display_detailed_step(step)
        mock_console.print.assert_called()


# ── UserLearning ───────────────────────────────────────────────────────

@pytest.fixture
def ul(tmp_path: Path) -> UserLearning:
    with patch("siyarix.user_learning._LEARNING_DIR", tmp_path / "learning"), \
         patch("siyarix.user_learning._MEMORY_DIR", tmp_path / "memory"):
        u = UserLearning()
        u._profile_path = tmp_path / "learning" / "user_profile.json"
        u._profile_path.parent.mkdir(parents=True, exist_ok=True)
        return u


class TestUserLearningInit:
    def test_init_creates_dirs(self, ul: UserLearning) -> None:
        assert ul._profile_path.parent.exists()

    def test_init_defaults(self, ul: UserLearning) -> None:
        assert ul._profile.username == ""
        assert ul._profile.experience == "intermediate"
        assert ul._current_session is None

    def test_init_with_skill_profiler(self) -> None:
        sp = MagicMock()
        with patch("siyarix.user_learning._LEARNING_DIR", Path("/tmp/test_learning")), \
             patch("siyarix.user_learning._MEMORY_DIR", Path("/tmp/test_memory")):
            u = UserLearning(xi_skill_profiler=sp)
            assert u._skill_profiler is sp

    def test_load_no_file(self, ul: UserLearning) -> None:
        ul._load()
        assert ul._profile.created_at != ""

    def test_load_from_file(self, ul: UserLearning) -> None:
        data = {"username": "test", "total_commands": 10}
        ul._profile_path.write_text(json.dumps(data), encoding="utf-8")
        ul._load()
        assert ul._profile.username == "test"
        assert ul._profile.total_commands == 10

    def test_load_corrupt_file(self, ul: UserLearning) -> None:
        ul._profile_path.write_text("not json", encoding="utf-8")
        ul._load()
        assert ul._profile.username == ""

    def test_save_and_reload(self, ul: UserLearning) -> None:
        ul._profile.username = "saved_user"
        ul._save()
        ul._profile = UserProfile()
        ul._load()
        assert ul._profile.username == "saved_user"

    def test_save_error(self, ul: UserLearning) -> None:
        with patch("builtins.open", side_effect=OSError("disk full")):
            ul._save()


class TestUserLearningProperties:
    def test_profile_property(self, ul: UserLearning) -> None:
        assert ul.profile is ul._profile

    def test_experience_getter(self, ul: UserLearning) -> None:
        assert ul.experience == "intermediate"

    def test_experience_setter_valid(self, ul: UserLearning) -> None:
        ul.experience = "expert"
        assert ul._profile.experience == "expert"
        assert ul._profile.auto_detect is False

    def test_experience_setter_invalid(self, ul: UserLearning) -> None:
        ul.experience = "invalid"
        assert ul._profile.experience == "intermediate"

    def test_pedagogical_enabled_default(self, ul: UserLearning) -> None:
        assert ul.pedagogical_enabled is False

    def test_set_pedagogical(self, ul: UserLearning) -> None:
        ul.set_pedagogical(True)
        assert ul._profile.pedagogical_enabled is True

    def test_auto_detect_enabled_default(self, ul: UserLearning) -> None:
        assert ul.auto_detect_enabled is True

    def test_enable_auto_detect(self, ul: UserLearning) -> None:
        ul._profile.auto_detect = False
        ul.enable_auto_detect()
        assert ul._profile.auto_detect is True

    def test_disable_auto_detect(self, ul: UserLearning) -> None:
        ul.disable_auto_detect()
        assert ul._profile.auto_detect is False


class TestUserLearningPreferences:
    def test_set_preference_valid(self, ul: UserLearning) -> None:
        ul.set_preference("verbosity", "verbose")
        assert ul._profile.preferences["verbosity"] == "verbose"

    def test_set_preference_invalid(self, ul: UserLearning) -> None:
        ul.set_preference("invalid_key", "value")
        assert "invalid_key" not in ul._profile.preferences

    def test_get_preference(self, ul: UserLearning) -> None:
        assert ul.get_preference("verbosity") == "adaptive"

    def test_get_preference_default(self, ul: UserLearning) -> None:
        assert ul.get_preference("nonexistent", "fallback") == "fallback"

    def test_preferences_property(self, ul: UserLearning) -> None:
        prefs = ul.preferences
        assert isinstance(prefs, dict)
        assert prefs["verbosity"] == "adaptive"


class TestUserLearningSession:
    def test_start_session(self, ul: UserLearning) -> None:
        ul.start_session("test-session")
        assert ul._current_session is not None
        assert ul._current_session.session_id == "test-session"
        assert ul._profile.session_count == 1

    def test_start_session_auto_id(self, ul: UserLearning) -> None:
        ul.start_session()
        assert ul._current_session is not None
        assert ul._current_session.session_id != ""

    def test_end_session_no_session(self, ul: UserLearning) -> None:
        result = ul.end_session()
        assert result is None

    def test_end_session_with_session(self, ul: UserLearning) -> None:
        ul.start_session("s1")
        ul._current_session.command_count = 5
        result = ul.end_session()
        assert result is not None
        assert result.session_id == "s1"
        assert result.command_count == 5
        assert ul._current_session is None
        assert len(ul._profile.sessions) == 1


class TestUserLearningRecordCommand:
    def test_record_command_basic(self, ul: UserLearning) -> None:
        ul.record_command("nmap -sV target", tool="nmap", success=True)
        assert ul._profile.total_commands == 1
        assert ul._profile.category_counts.get("recon", 0) == 1

    def test_record_command_failure(self, ul: UserLearning) -> None:
        ul.record_command("nmap target", tool="nmap", success=False)
        assert ul._profile.total_errors == 1
        assert ul._profile.total_commands == 1

    def test_record_command_with_findings(self, ul: UserLearning) -> None:
        ul.record_command("nuclei -u target", tool="nuclei", findings_count=5)
        assert ul._profile.total_findings == 5

    def test_record_command_unknown_category(self, ul: UserLearning) -> None:
        ul.record_command("custom_tool", tool="custom_tool")
        assert ul._profile.category_counts.get("other", 0) == 1

    def test_record_command_advanced(self, ul: UserLearning) -> None:
        ul.record_command("nmap -sV -sC -O --script=http-title target", tool="nmap")
        assert ul._profile.advanced_command_count == 1

    def test_record_command_updates_session(self, ul: UserLearning) -> None:
        ul.start_session("s1")
        ul.record_command("nmap target", tool="nmap")
        assert ul._current_session is not None
        assert ul._current_session.command_count == 1
        assert "nmap" in ul._current_session.tools_used

    def test_record_command_triggers_reassessment(self, ul: UserLearning) -> None:
        for i in range(5):
            ul.record_command(f"nmap target {i}", tool="nmap")
        assert ul._profile.total_commands == 5


class TestUserLearningAnalyzeComplexity:
    def test_simple_command(self) -> None:
        assert UserLearning._analyze_complexity("ls") == 0

    def test_with_flags(self) -> None:
        assert UserLearning._analyze_complexity("nmap -sV -sC -O target") >= 3

    def test_with_operators(self) -> None:
        assert UserLearning._analyze_complexity("nmap target && nuclei target") >= 2

    def test_with_many_parts(self) -> None:
        cmd = " ".join(["word"] * 15)
        result = UserLearning._analyze_complexity(cmd)
        assert result >= 1

    def test_with_special_flags(self) -> None:
        assert UserLearning._analyze_complexity("nmap --dry-run target") >= 1

    def test_empty_command(self) -> None:
        assert UserLearning._analyze_complexity("") == 0


class TestUserLearningExperience:
    def test_reassess_auto_detects(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 200
        ul._profile.unique_tools = 15
        ul._profile.category_count = 5
        ul._profile.advanced_command_count = 8
        ul._reassess()
        assert ul._profile.experience == "expert"

    def test_reassess_skipped_when_manual(self, ul: UserLearning) -> None:
        ul._profile.auto_detect = False
        ul._profile.experience = "novice"
        ul._profile.total_commands = 200
        ul._reassess()
        assert ul._profile.experience == "novice"


class TestUserLearningMilestones:
    def test_check_milestones_first_command(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 1
        newly = ul._check_milestones()
        ids = [m["id"] for m in newly]
        assert "first_command" in ids

    def test_check_milestones_only_once(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 1
        ul._check_milestones()
        newly = ul._check_milestones()
        assert "first_command" not in [m["id"] for m in newly]

    def test_check_milestones_ten_commands(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 10
        newly = ul._check_milestones()
        ids = [m["id"] for m in newly]
        assert "ten_commands" in ids

    def test_get_milestones(self, ul: UserLearning) -> None:
        ms = ul.get_milestones()
        assert len(ms) == len(_MILESTONES)
        assert ms[0]["achieved"] is False
        assert "id" in ms[0]

    def test_get_milestones_with_achievement(self, ul: UserLearning) -> None:
        ul._profile.milestones.append("first_command")
        ms = ul.get_milestones()
        assert ms[0]["achieved"] is True


class TestUserLearningPedagogical:
    def test_generate_pedagogical_output_disabled(self, ul: UserLearning) -> None:
        result = ul.generate_pedagogical_output([{"tool": "nmap"}])
        assert result is None

    def test_generate_pedagogical_output_enabled(self, ul: UserLearning) -> None:
        ul._profile.pedagogical_enabled = True
        steps = [{"tool": "nmap", "command": "nmap target", "output": ""}]
        result = ul.generate_pedagogical_output(steps)
        assert result is not None
        assert len(result) == 1

    def test_generate_pedagogical_output_tracks_session(self, ul: UserLearning) -> None:
        ul._profile.pedagogical_enabled = True
        ul.start_session("test")
        steps = [{"tool": "nmap", "command": "nmap target", "output": ""}, {"tool": "nuclei", "command": "nuclei target", "output": ""}]
        with patch("sys.stdin.readline", return_value="n"):
            ul.generate_pedagogical_output(steps)
        assert ul._current_session is not None
        assert ul._current_session.pedagogical_steps == 2

    def test_should_show_explanation_auto_novice(self, ul: UserLearning) -> None:
        ul._profile.experience = "novice"
        assert ul.should_show_explanation() is True

    def test_should_show_explanation_auto_expert(self, ul: UserLearning) -> None:
        ul._profile.experience = "expert"
        assert ul.should_show_explanation() is False

    def test_should_show_explanation_manual(self, ul: UserLearning) -> None:
        ul._profile.auto_detect = False
        ul._profile.preferences["show_hints"] = False
        assert ul.should_show_explanation() is False

    def test_verbosity_level_auto_novice(self, ul: UserLearning) -> None:
        ul._profile.experience = "novice"
        assert ul.verbosity_level() == 2

    def test_verbosity_level_auto_expert(self, ul: UserLearning) -> None:
        ul._profile.experience = "expert"
        assert ul.verbosity_level() == 0

    def test_verbosity_level_manual(self, ul: UserLearning) -> None:
        ul._profile.auto_detect = False
        ul._profile.preferences["verbosity"] = "minimal"
        assert ul.verbosity_level() == 0

    def test_verbosity_level_manual_verbose(self, ul: UserLearning) -> None:
        ul._profile.auto_detect = False
        ul._profile.preferences["verbosity"] = "verbose"
        assert ul.verbosity_level() == 2

    def test_auto_confirm_safe_expert(self, ul: UserLearning) -> None:
        ul._profile.experience = "expert"
        assert ul.auto_confirm_safe() is True

    def test_auto_confirm_safe_not_expert(self, ul: UserLearning) -> None:
        ul._profile.experience = "novice"
        assert ul.auto_confirm_safe() is False


class TestUserLearningXI:
    def test_sync_skill_profiler_with_profiler(self, ul: UserLearning) -> None:
        sp = MagicMock()
        ul._skill_profiler = sp
        ul._sync_skill_profiler("nmap target", "nmap", True)
        sp.record_command.assert_called_once_with("nmap target", tool="nmap", success=True)

    def test_sync_skill_profiler_no_profiler(self, ul: UserLearning) -> None:
        ul._sync_skill_profiler("nmap target", "nmap", True)

    def test_sync_skill_profiler_error(self, ul: UserLearning) -> None:
        sp = MagicMock()
        sp.record_command.side_effect = Exception("error")
        ul._skill_profiler = sp
        ul._sync_skill_profiler("nmap target", "nmap", True)

    def test_sync_from_skill_profiler_no_profiler(self, ul: UserLearning) -> None:
        ul.sync_from_skill_profiler()

    def test_sync_from_skill_profiler_with_level(self, ul: UserLearning) -> None:
        sp = MagicMock()
        sp.profile = MagicMock()
        sp.profile.level = "expert"
        ul._skill_profiler = sp
        ul.sync_from_skill_profiler()
        assert ul._profile.experience == "expert"

    def test_sync_from_skill_profiler_error(self, ul: UserLearning) -> None:
        sp = MagicMock()
        sp.profile.side_effect = AttributeError("no profile")
        ul._skill_profiler = sp
        ul.sync_from_skill_profiler()


class TestUserLearningDisplay:
    def test_get_profile_panel(self, ul: UserLearning) -> None:
        panel = ul.get_profile_panel()
        assert panel is not None

    def test_get_profile_panel_with_milestones(self, ul: UserLearning) -> None:
        ul._profile.milestones.append("first_command")
        panel = ul.get_profile_panel()
        assert panel is not None

    def test_get_milestones_panel(self, ul: UserLearning) -> None:
        panel = ul.get_milestones_panel()
        assert panel is not None

    def test_get_sessions_panel_empty(self, ul: UserLearning) -> None:
        panel = ul.get_sessions_panel()
        assert panel is not None

    def test_get_sessions_panel_with_data(self, ul: UserLearning) -> None:
        s = SessionRecord(session_id="s1", command_count=5, tools_used=["nmap", "nuclei", "gobuster", "hydra"])
        ul._profile.sessions.append(s)
        panel = ul.get_sessions_panel()
        assert panel is not None

    def test_get_sessions_panel_limit(self, ul: UserLearning) -> None:
        for i in range(15):
            ul._profile.sessions.append(SessionRecord(session_id=f"s{i}", command_count=1))
        panel = ul.get_sessions_panel(limit=5)
        assert panel is not None


class TestUserLearningImprovements:
    def test_get_improvement_suggestions_few_tools(self, ul: UserLearning) -> None:
        ul._profile.unique_tools = 2
        suggestions = ul.get_improvement_suggestions()
        assert any("Try more tools" in s for s in suggestions)

    def test_get_improvement_suggestions_missing_categories(self, ul: UserLearning) -> None:
        ul._profile.unique_tools = 10
        ul._profile.category_counts = {"recon": 5}
        suggestions = ul.get_improvement_suggestions()
        assert any("Explore" in s for s in suggestions)

    def test_get_improvement_suggestions_high_error_rate(self, ul: UserLearning) -> None:
        ul._profile.error_rate = 0.3
        ul._profile.total_commands = 20
        suggestions = ul.get_improvement_suggestions()
        assert any("Error rate" in s for s in suggestions)

    def test_get_improvement_suggestions_advanced_commands(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 15
        ul._profile.advanced_command_count = 1
        suggestions = ul.get_improvement_suggestions()
        assert any("--dry-run" in s for s in suggestions)

    def test_get_improvement_suggestions_medium_diversity(self, ul: UserLearning) -> None:
        ul._profile.unique_tools = 10
        ul._profile.category_counts = {"recon": 5, "web": 3, "exploit": 2}
        suggestions = ul.get_improvement_suggestions()
        assert any("bloodhound" in s for s in suggestions)


class TestUserLearningClear:
    def test_clear_history(self, ul: UserLearning) -> None:
        ul._profile.total_commands = 100
        ul._profile.username = "test"
        ul.clear_history()
        assert ul._profile.total_commands == 0
        assert ul._profile.username == ""


# ── _TOOL_CATEGORIES ──────────────────────────────────────────────────

def test_tool_categories_definitions() -> None:
    assert _TOOL_CATEGORIES["nmap"] == "recon"
    assert _TOOL_CATEGORIES["gobuster"] == "web"
    assert _TOOL_CATEGORIES["hydra"] == "exploit"
    assert _TOOL_CATEGORIES["docker"] == "infra"


# ── _CVE_KNOWLEDGE ────────────────────────────────────────────────────

def test_cve_knowledge_definitions() -> None:
    assert "CVE-2021-41773" in _CVE_KNOWLEDGE
    assert _CVE_KNOWLEDGE["MS17-010"]["description"] == "EternalBlue SMB vulnerability"


# ── record_command category_counts rounding (edge test) ───────────────

def test_record_command_error_rate_update(ul: UserLearning) -> None:
    ul.record_command("cmd1", tool="nmap", success=False)
    ul.record_command("cmd2", tool="nmap", success=False)
    ul.record_command("cmd3", tool="nmap", success=True)
    assert ul._profile.total_errors == 2
    assert ul._profile.total_commands == 3


def test_get_sessions_panel_zero_duration(ul: UserLearning) -> None:
    s = SessionRecord(session_id="test", command_count=1, duration_seconds=0)
    ul._profile.sessions.append(s)
    panel = ul.get_sessions_panel()
    assert panel is not None
