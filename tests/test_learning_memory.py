"""Tests for siyarix.learning_memory — tool learning system."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.learning_memory import (
    _FAST_THRESHOLD,
    _MIN_CONFIDENCE_SAMPLES,
    _THOROUGH_THRESHOLD,
    LearningEvent,
    LearningMemory,
    ToolPattern,
)


# ── ToolPattern ────────────────────────────────────────────────────────

class TestToolPattern:
    def test_defaults(self) -> None:
        p = ToolPattern(ngram=["nmap"])
        assert p.count == 1
        assert p.success_count == 1
        assert p.is_anti_pattern is False
        assert p.context_tags == []
        assert p.effective_flags == []
        assert p.ineffective_flags == []

    def test_confidence_below_min_samples(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=2, success_count=2)
        expected = 1.0 * (2 / _MIN_CONFIDENCE_SAMPLES)
        assert p.confidence == pytest.approx(expected)

    def test_confidence_above_min_samples(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=10, success_count=8, decay_score=0.9)
        assert p.confidence == pytest.approx(0.8 * 0.9)

    def test_confidence_with_decay(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=10, success_count=10, decay_score=0.5)
        assert p.confidence == pytest.approx(0.5)

    def test_success_rate(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=10, success_count=7)
        assert p.success_rate == 0.7

    def test_success_rate_zero_divide(self) -> None:
        p = ToolPattern(ngram=[], count=0, success_count=0)
        assert p.success_rate == 0

    def test_avg_duration_ms(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=2, total_duration_ms=1000)
        assert p.avg_duration_ms == 500.0

    def test_avg_duration_zero(self) -> None:
        p = ToolPattern(ngram=[], count=0)
        assert p.avg_duration_ms == 0.0

    def test_avg_findings(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=4, total_findings=10)
        assert p.avg_findings == 2.5

    def test_timing_category_fast(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=1, total_duration_ms=_FAST_THRESHOLD * 1000 - 1)
        assert p.timing_category == "fast"

    def test_timing_category_thorough(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=1, total_duration_ms=_THOROUGH_THRESHOLD * 1000)
        assert p.timing_category == "thorough"

    def test_timing_category_balanced(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=1, total_duration_ms=60000)
        assert p.timing_category == "balanced"

    def test_timing_category_unknown(self) -> None:
        p = ToolPattern(ngram=["nmap"], count=1, total_duration_ms=0)
        assert p.timing_category == "unknown"

    def test_has_correction_true(self) -> None:
        p = ToolPattern(ngram=["nmap"], original_command="nmap target", user_correction="nmap -sV target")
        assert p.has_correction is True

    def test_has_correction_false_same(self) -> None:
        p = ToolPattern(ngram=["nmap"], original_command="nmap target", user_correction="nmap target")
        assert p.has_correction is False

    def test_has_correction_false_empty(self) -> None:
        p = ToolPattern(ngram=["nmap"])
        assert p.has_correction is False

    def test_flag_effectiveness_score_zero(self) -> None:
        p = ToolPattern(ngram=["nmap"])
        assert p.flag_effectiveness_score == 0.0

    def test_flag_effectiveness_score_half(self) -> None:
        p = ToolPattern(ngram=["nmap"], effective_flags=["-sV"], ineffective_flags=["-O"])
        assert p.flag_effectiveness_score == 0.5

    def test_flag_effectiveness_score_full(self) -> None:
        p = ToolPattern(ngram=["nmap"], effective_flags=["-sV", "-sC"])
        assert p.flag_effectiveness_score == 1.0

    def test_apply_decay_no_last_used(self) -> None:
        p = ToolPattern(ngram=["nmap"])
        p.apply_decay()
        assert p.decay_score == 1.0

    def test_apply_decay_invalid_date(self) -> None:
        p = ToolPattern(ngram=["nmap"], last_used="not-a-date")
        p.apply_decay()
        assert p.decay_score == 1.0

    def test_apply_decay_recent(self) -> None:
        p = ToolPattern(ngram=["nmap"], last_used=datetime.now(timezone.utc).isoformat())
        p.apply_decay()
        assert p.decay_score == pytest.approx(1.0, abs=0.01)

    def test_apply_decay_old(self) -> None:
        p = ToolPattern(ngram=["nmap"], last_used="2020-01-01T00:00:00+00:00")
        p.apply_decay(time.time())
        assert p.decay_score < 0.5

    def test_to_dict(self) -> None:
        p = ToolPattern(ngram=["nmap"], task_type="port_scan", count=5)
        d = p.to_dict()
        assert d["ngram"] == ["nmap"]
        assert d["task_type"] == "port_scan"
        assert d["confidence"] == pytest.approx(p.confidence, abs=0.0001)
        assert d["timing_category"] == "unknown"

    def test_from_dict(self) -> None:
        data = {"ngram": ["nmap"], "task_type": "port_scan", "count": 10, "success_count": 9, "effective_flags": ["-sV"]}
        p = ToolPattern.from_dict(data)
        assert p.ngram == ["nmap"]
        assert p.task_type == "port_scan"
        assert p.count == 10
        assert p.effective_flags == ["-sV"]

    def test_from_dict_empty(self) -> None:
        p = ToolPattern.from_dict({})
        assert p.ngram == []
        assert p.count == 1


# ── LearningEvent ──────────────────────────────────────────────────────

class TestLearningEvent:
    def test_format_message_no_modification(self) -> None:
        e = LearningEvent(task="nmap scan", generated="nmap -sV target", user_modified="nmap -sV target", result="5 findings", insight="Good flags", delta_findings=0)
        msg = e.format_message("Test")
        assert "Test" in msg
        assert "Task:" in msg
        assert "User modified:" not in msg

    def test_format_message_with_modification(self) -> None:
        e = LearningEvent(task="nmap scan", generated="nmap target", user_modified="nmap -sV target", result="More findings", insight="Added flags help")
        msg = e.format_message("Test")
        assert "User modified:" in msg


# ── LearningMemory ─────────────────────────────────────────────────────

@pytest.fixture
def lm(tmp_path: Path) -> LearningMemory:
    with patch("siyarix.learning_memory._LEARNING_DIR", tmp_path / "learning"), \
         patch("siyarix.learning_memory._MEMORY_DIR", tmp_path / "memory"):
        mem = LearningMemory()
        mem._patterns.clear()
        mem._anti_patterns.clear()
        mem._ngram_index.clear()
        mem._patterns_path = tmp_path / "learning" / "tool_patterns.json"
        mem._patterns_path.parent.mkdir(parents=True, exist_ok=True)
        return mem


class TestLearningMemoryInit:
    def test_init_creates_dirs(self, lm: LearningMemory) -> None:
        assert lm._patterns_path.parent.exists()

    def test_init_defaults(self) -> None:
        with patch("siyarix.learning_memory._LEARNING_DIR", Path("/tmp/siyarix_test/learning")), \
             patch("siyarix.learning_memory._MEMORY_DIR", Path("/tmp/siyarix_test/memory")):
            mem = LearningMemory()
            assert mem._tool_learning_enabled is True
            assert mem._patterns == []
            assert mem._anti_patterns == []

    def test_init_with_predictor(self) -> None:
        predictor = MagicMock()
        with patch("siyarix.learning_memory._LEARNING_DIR", Path("/tmp/siyarix_test/learning")):
            mem = LearningMemory(xi_predictor=predictor)
            assert mem._predictor is predictor

    def test_tool_learning_enabled(self, lm: LearningMemory) -> None:
        assert lm.tool_learning_enabled is True

    def test_set_tool_learning(self, lm: LearningMemory) -> None:
        lm.set_tool_learning(False)
        assert lm.tool_learning_enabled is False
        lm.set_tool_learning(True)
        assert lm.tool_learning_enabled is True


class TestLearningMemoryPersistence:
    def test_load_no_file(self, lm: LearningMemory) -> None:
        lm._load()
        assert lm._patterns == []

    def test_save_and_load(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], count=3, task_type="port_scan")
        lm._patterns.append(p)
        lm._save()
        lm._patterns.clear()
        lm._load()
        assert len(lm._patterns) == 1
        assert lm._patterns[0].ngram == ["nmap"]

    def test_save_and_load_anti_patterns(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], count=2, is_anti_pattern=True)
        lm._anti_patterns.append(p)
        lm._save()
        lm._patterns.clear()
        lm._anti_patterns.clear()
        lm._load()
        assert len(lm._anti_patterns) == 1

    def test_load_corrupt_file(self, lm: LearningMemory) -> None:
        lm._patterns_path.write_text("not json", encoding="utf-8")
        lm._load()
        assert lm._patterns == []

    def test_save_error(self, lm: LearningMemory) -> None:
        with patch("builtins.open", side_effect=OSError("write error")):
            lm._save()

    def test_rebuild_index(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"])
        lm._patterns.append(p)
        lm._rebuild_index()
        assert "nmap" in lm._ngram_index
        assert "nuclei" in lm._ngram_index


class TestLearningMemoryClassification:
    def test_classify_task_port_scan(self) -> None:
        assert LearningMemory.classify_task(["nmap"]) == "port_scan"

    def test_classify_task_web_scan(self) -> None:
        assert LearningMemory.classify_task(["nuclei"]) == "web_scan"

    def test_classify_task_subdomain_enum(self) -> None:
        assert LearningMemory.classify_task(["subfinder"]) == "subdomain_enum"

    def test_classify_task_general(self) -> None:
        assert LearningMemory.classify_task(["unknown_tool"]) == "general"

    def test_classify_task_with_command(self) -> None:
        assert LearningMemory.classify_task(["custom"], "nmap -sV") == "port_scan"

    def test_extract_flags(self) -> None:
        flags = LearningMemory.extract_flags("nmap -sV -sC -O target")
        assert "-sV" in flags
        assert "-sC" in flags
        assert "-O" in flags

    def test_extract_flags_empty(self) -> None:
        assert LearningMemory.extract_flags("nmap target") == []

    def test_extract_platform(self) -> None:
        plat = LearningMemory.extract_platform()
        assert plat in ("linux", "windows", "darwin", "java")

    def test_categorize_timing_fast(self) -> None:
        assert LearningMemory.categorize_timing(_FAST_THRESHOLD * 1000 - 1) == "fast"

    def test_categorize_timing_thorough(self) -> None:
        assert LearningMemory.categorize_timing(_THOROUGH_THRESHOLD * 1000) == "thorough"

    def test_categorize_timing_balanced(self) -> None:
        assert LearningMemory.categorize_timing(60000) == "balanced"

    def test_categorize_timing_unknown(self) -> None:
        assert LearningMemory.categorize_timing(0) == "unknown"


class TestLearningMemoryRecord:
    def test_record_disabled(self, lm: LearningMemory) -> None:
        lm._tool_learning_enabled = False
        lm.record(tools=["nmap"], duration_ms=100, success=True)
        assert lm._patterns == []

    def test_record_empty_tools(self, lm: LearningMemory) -> None:
        lm.record(tools=[], duration_ms=100, success=True)
        assert lm._patterns == []

    def test_record_single_tool_success(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap"], duration_ms=100, success=True, command="nmap -sV target")
        assert len(lm._patterns) == 1
        assert lm._patterns[0].ngram == ["nmap"]

    def test_record_single_tool_failure(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap"], duration_ms=100, success=False, command="nmap target")
        assert len(lm._anti_patterns) == 1

    def test_record_multiple_tools(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap", "nuclei"], duration_ms=200, success=True)
        # ngram patterns: [nmap], [nuclei], [nmap, nuclei]
        assert len(lm._patterns) == 3

    def test_record_updates_existing(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap"], duration_ms=100, command="nmap target")
        lm.record(tools=["nmap"], duration_ms=200, command="nmap target")
        assert len(lm._patterns) == 1
        assert lm._patterns[0].count == 2
        assert lm._patterns[0].total_duration_ms == 300

    def test_record_with_phase_and_target(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap"], phase="recon", target="10.0.0.1", session_id="sess-1")
        assert len(lm._patterns) == 1
        tags = lm._patterns[0].context_tags
        assert "phase:recon" in tags
        assert "target:10.0.0.1" in tags
        assert "session:sess-1" in tags

    def test_record_with_predictor(self, lm: LearningMemory) -> None:
        predictor = MagicMock()
        lm._predictor = predictor
        lm.record(tools=["nmap"], command="nmap target")
        predictor.learn.assert_called_once_with("nmap")

    def test_record_with_persona(self, lm: LearningMemory) -> None:
        lm.record(tools=["nmap"], persona="bug_hunter", command="nmap target")
        assert lm._patterns[0].persona == "bug_hunter"

    def test_record_truncates_recent_tools(self, lm: LearningMemory) -> None:
        tools = [f"tool_{i}" for i in range(60)]
        lm.record(tools=tools, command="test")
        assert len(lm._recent_tools) == 50


class TestLearningMemoryRecordWithCorrection:
    def test_correction_disabled(self, lm: LearningMemory) -> None:
        lm._tool_learning_enabled = False
        event = lm.record_with_correction(tools=["nmap"], original="nmap target", corrected="nmap -sV target")
        assert event is None

    def test_correction_empty_tools(self, lm: LearningMemory) -> None:
        event = lm.record_with_correction(tools=[], original="", corrected="")
        assert event is None

    def test_correction_basic(self, lm: LearningMemory) -> None:
        event = lm.record_with_correction(
            tools=["nmap"],
            original="nmap target",
            corrected="nmap -sV target",
            task="Scan",
            findings_before=2,
            findings_after=5,
        )
        assert event is not None
        assert event.delta_findings == 3
        assert "significantly improve" in event.insight

    def test_correction_negative_delta(self, lm: LearningMemory) -> None:
        event = lm.record_with_correction(
            tools=["nmap"],
            original="nmap -sV -sC -O target",
            corrected="nmap target",
            findings_before=5,
            findings_after=2,
        )
        assert event is not None
        assert "added noise" in event.insight

    def test_correction_zero_delta(self, lm: LearningMemory) -> None:
        event = lm.record_with_correction(
            tools=["nmap"],
            original="nmap target",
            corrected="nmap -v target",
            findings_before=3,
            findings_after=3,
        )
        assert event is not None
        assert "equivalent results" in event.insight

    def test_correction_small_delta(self, lm: LearningMemory) -> None:
        event = lm.record_with_correction(
            tools=["nmap"],
            original="nmap target",
            corrected="nmap -sV target",
            findings_before=0,
            findings_after=1,
        )
        assert event is not None
        assert "1 more finding" in event.result

    def test_correction_tracks_flags(self, lm: LearningMemory) -> None:
        lm.record_with_correction(
            tools=["nmap"],
            original="nmap target",
            corrected="nmap -sV -sC target",
            findings_before=0,
            findings_after=5,
        )
        assert lm._patterns[0].effective_flags != []

    def test_correction_adds_ineffective_flags(self, lm: LearningMemory) -> None:
        lm.record_with_correction(
            tools=["nmap"],
            original="nmap target",
            corrected="nmap -O target",
            findings_before=5,
            findings_after=1,
        )
        assert lm._patterns[0].ineffective_flags != []


class TestLearningMemorySuggestions:
    def test_suggest_no_patterns(self, lm: LearningMemory) -> None:
        result = lm.suggest("nmap")
        assert result == []

    def test_suggest_with_transition(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=10, success_count=9, last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        lm._rebuild_index()
        result = lm.suggest("nmap")
        assert len(result) >= 1
        assert result[0]["tool"] == "nuclei"
        assert result[0]["confidence"] > 0

    def test_suggest_with_anti_pattern_warning(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=2, success_count=2, last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        lm._rebuild_index()
        ap = ToolPattern(ngram=["nmap", "nuclei"], count=3, success_count=0, is_anti_pattern=True)
        lm._anti_patterns.append(ap)
        result = lm.suggest("nmap")
        warnings = [r for r in result if r.get("warning")]
        assert len(warnings) >= 1

    def test_suggest_context_boost_phase(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=5, success_count=5, context_tags=["phase:recon"], last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        lm._rebuild_index()
        result = lm.suggest("nmap", phase="recon")
        assert len(result) >= 1

    def test_suggest_context_boost_target(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=5, success_count=5, context_tags=["target:10.0.0.1"], last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        lm._rebuild_index()
        result = lm.suggest("nmap", target="10.0.0.1")
        assert len(result) >= 1

    def test_suggest_session_boost(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=5, success_count=5, last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        lm._rebuild_index()
        lm._recent_tools = ["nmap", "nuclei"]
        result = lm.suggest("nmap")
        assert len(result) >= 1

    def test_suggest_min_confidence_filter(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=1, success_count=1, last_used="2020-01-01T00:00:00+00:00")
        lm._patterns.append(p)
        lm._rebuild_index()
        result = lm.suggest("nmap", min_confidence=0.99)
        assert result == []

    def test_suggest_max_suggestions(self, lm: LearningMemory) -> None:
        for tool in ["a", "b", "c", "d", "e", "f"]:
            p = ToolPattern(ngram=["nmap", tool], count=10, success_count=10, last_used=datetime.now(timezone.utc).isoformat())
            lm._patterns.append(p)
        lm._rebuild_index()
        result = lm.suggest("nmap", max_suggestions=3)
        assert len(result) == 3

    def test_suggest_for_task_type(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nuclei"], count=5, task_type="web_scan", last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        result = lm.suggest_for_task_type("web_scan")
        assert len(result) >= 1
        assert result[0]["task_type"] == "web_scan"

    def test_suggest_for_task_type_no_match(self, lm: LearningMemory) -> None:
        result = lm.suggest_for_task_type("nonexistent")
        assert result == []

    def test_suggest_platform_optimizations(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], platform="linux", original_command="nmap target", user_correction="nmap -sV target", correction_findings_delta=3, effective_flags=["-sV"])
        lm._patterns.append(p)
        result = lm.suggest_platform_optimizations("linux")
        assert len(result) >= 1

    def test_suggest_platform_optimizations_no_match(self, lm: LearningMemory) -> None:
        result = lm.suggest_platform_optimizations("nonexistent")
        assert result == []


class TestLearningMemoryAnalytics:
    def test_top_patterns(self, lm: LearningMemory) -> None:
        p1 = ToolPattern(ngram=["nmap"], count=100, success_count=95, last_used=datetime.now(timezone.utc).isoformat())
        p2 = ToolPattern(ngram=["nuclei"], count=1, success_count=1, last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.extend([p1, p2])
        top = lm.top_patterns(n=1)
        assert len(top) == 1
        assert top[0].ngram == ["nmap"]

    def test_top_patterns_min_count(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], count=1, last_used=datetime.now(timezone.utc).isoformat())
        lm._patterns.append(p)
        top = lm.top_patterns(n=10, min_count=5)
        assert top == []

    def test_top_anti_patterns(self, lm: LearningMemory) -> None:
        ap = ToolPattern(ngram=["hydra"], count=5, is_anti_pattern=True)
        lm._anti_patterns.append(ap)
        top = lm.top_anti_patterns()
        assert len(top) >= 1

    def test_corrections_empty(self, lm: LearningMemory) -> None:
        assert lm.corrections() == []

    def test_corrections_with_data(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], original_command="nmap target", user_correction="nmap -sV target", correction_count=3)
        lm._patterns.append(p)
        results = lm.corrections()
        assert len(results) == 1
        assert results[0].correction_count == 3

    def test_platform_insights(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], platform="linux", total_findings=10, correction_count=1)
        lm._patterns.append(p)
        insights = lm.platform_insights()
        assert len(insights) >= 1
        assert insights[0]["platform"] == "linux"

    def test_flag_effectiveness_report(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], effective_flags=["-sV"], ineffective_flags=["-O"])
        lm._patterns.append(p)
        report = lm.flag_effectiveness_report()
        assert len(report) >= 1

    def test_flag_effectiveness_report_empty(self) -> None:
        lm = LearningMemory.__new__(LearningMemory)
        lm._patterns = []
        report = lm.flag_effectiveness_report()
        assert report == []

    def test_timing_distribution(self, lm: LearningMemory) -> None:
        lm._patterns.append(ToolPattern(ngram=["nmap"], count=1, total_duration_ms=5000))
        dist = lm.timing_distribution()
        assert "fast" in dist

    def test_task_type_summary(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], task_type="port_scan", total_findings=10, correction_count=2)
        lm._patterns.append(p)
        summary = lm.task_type_summary()
        assert "port_scan" in summary
        assert summary["port_scan"]["total_findings"] == 10

    def test_most_learned_tools(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=5)
        lm._patterns.append(p)
        tools = lm.most_learned_tools()
        assert len(tools) >= 2

    def test_phase_distribution(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], phase="recon")
        lm._patterns.append(p)
        dist = lm.phase_distribution()
        assert "recon" in dist

    def test_pattern_network(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei"], count=5, success_count=5)
        lm._patterns.append(p)
        graph = lm.pattern_network()
        assert "nmap" in graph
        assert graph["nmap"][0][0] == "nuclei"

    def test_summary_property(self, lm: LearningMemory) -> None:
        s = lm.summary
        assert s["total_patterns"] == 0
        assert s["total_anti_patterns"] == 0

    def test_total_records(self, lm: LearningMemory) -> None:
        assert lm.total_records == 0
        lm._patterns.append(ToolPattern(ngram=["nmap"]))
        assert lm.total_records == 1


class TestLearningMemorySession:
    def test_start_session(self, lm: LearningMemory) -> None:
        lm.start_session()
        assert lm._recent_tools == []

    def test_end_session(self, lm: LearningMemory) -> None:
        lm._patterns.append(ToolPattern(ngram=["nmap"]))
        result = lm.end_session()
        assert len(result) == 1


class TestLearningMemoryExportImport:
    def test_export_patterns(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"], count=3)
        lm._patterns.append(p)
        data = lm.export_patterns()
        assert data["version"] == 3
        assert data["pattern_count"] == 1
        assert len(data["patterns"]) == 1

    def test_export_to_file(self, lm: LearningMemory, tmp_path: Path) -> None:
        p = ToolPattern(ngram=["nmap"])
        lm._patterns.append(p)
        out = tmp_path / "export.json"
        lm.export_patterns(out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["pattern_count"] == 1

    def test_import_patterns_from_dict(self, lm: LearningMemory) -> None:
        data = {"patterns": [{"ngram": ["nuclei"], "count": 5}]}
        count = lm.import_patterns(data, merge=False)
        assert count == 1
        assert len(lm._patterns) == 1

    def test_import_patterns_merge(self, lm: LearningMemory) -> None:
        # Pre-seed with a pattern, then merge imports
        lm._upsert_pattern(["nmap"], 100, 5, [], "recon", "port_scan", "linux", ["-sV"], "bug_hunter", "nmap target", "", 0, False)
        before_count = lm._patterns[0].count
        data = {"patterns": [{"ngram": ["nmap"], "count": 5}]}
        count = lm.import_patterns(data, merge=True)
        assert count == 1
        assert lm._patterns[0].count == before_count + 1

    def test_import_patterns_from_file(self, lm: LearningMemory, tmp_path: Path) -> None:
        f = tmp_path / "import.json"
        f.write_text(json.dumps({"patterns": [{"ngram": ["nikto"], "count": 2}]}), encoding="utf-8")
        count = lm.import_patterns(f)
        assert count == 1

    def test_import_patterns_file_not_found(self, lm: LearningMemory) -> None:
        count = lm.import_patterns("/nonexistent/file.json")
        assert count == 0

    def test_import_patterns_skips_empty_ngram(self, lm: LearningMemory) -> None:
        data = {"patterns": [{"ngram": [], "count": 5}]}
        count = lm.import_patterns(data)
        assert count == 0

    def test_suggest_chain(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap", "nuclei", "gobuster"])
        lm._patterns.append(p)
        completions = lm.suggest_chain(["nmap"])
        assert len(completions) >= 1
        assert completions[0] == ["nmap", "nuclei", "gobuster"]

    def test_suggest_chain_no_match(self, lm: LearningMemory) -> None:
        completions = lm.suggest_chain(["nonexistent"])
        assert completions == []


class TestLearningMemoryClearReset:
    def test_clear(self, lm: LearningMemory) -> None:
        p = ToolPattern(ngram=["nmap"])
        lm._patterns.append(p)
        lm.clear()
        assert lm._patterns == []
        assert lm._anti_patterns == []
        assert lm._ngram_index == {}
        assert lm._recent_tools == []
        assert lm._correction_events == []

    def test_reset(self, lm: LearningMemory) -> None:
        lm._patterns.append(ToolPattern(ngram=["nmap"]))
        lm.reset()
        assert lm._patterns == []

    def test_recent_correction_events(self, lm: LearningMemory) -> None:
        assert lm.recent_correction_events == []
        e = LearningEvent(task="t", generated="a", user_modified="b", result="r", insight="i")
        lm._correction_events.append(e)
        assert len(lm.recent_correction_events) == 1

    def test_upsert_pattern_prune(self, lm: LearningMemory) -> None:
        for i in range(501):
            lm._upsert_pattern([f"tool_{i}"], 0, 0, [], "", "", "linux", [], "", "", "", 0, False)
        assert len(lm._patterns) <= 500
