from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.providers.types import CostTier
from siyarix.providers.usage import UsageRecord, UsageTotals, UsageTracker


class TestUsageRecord:
    def test_defaults(self):
        r = UsageRecord()
        assert r.provider == ""
        assert r.model == ""
        assert r.input_tokens == 0
        assert r.output_tokens == 0
        assert r.call_count == 0
        assert r.total_cost_estimated == 0.0

    def test_record_with_free_tier(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(input_tokens=100, output_tokens=50, cost_tier=CostTier.FREE)
        assert r.input_tokens == 100
        assert r.output_tokens == 50
        assert r.call_count == 1
        assert r.total_cost_estimated == 0.0

    def test_record_with_low_tier(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(input_tokens=1000, output_tokens=500, cost_tier=CostTier.LOW)
        rate = 0.15e-6
        expected = (1000 + 500 * 4) * rate
        assert abs(r.total_cost_estimated - expected) < 1e-12

    def test_record_with_medium_tier(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(input_tokens=1000, output_tokens=500, cost_tier=CostTier.MEDIUM)
        rate = 2.0e-6
        expected = (1000 + 500 * 4) * rate
        assert abs(r.total_cost_estimated - expected) < 1e-12

    def test_record_with_high_tier(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(input_tokens=1000, output_tokens=500, cost_tier=CostTier.HIGH)
        rate = 10.0e-6
        expected = (1000 + 500 * 4) * rate
        assert abs(r.total_cost_estimated - expected) < 1e-12

    def test_record_default_tier(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(input_tokens=100, output_tokens=50)
        rate = 2.0e-6
        expected = (100 + 50 * 4) * rate
        assert abs(r.total_cost_estimated - expected) < 1e-12

    def test_record_multiple_calls(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(100, 50, CostTier.MEDIUM)
        r.record(200, 100, CostTier.MEDIUM)
        assert r.input_tokens == 300
        assert r.output_tokens == 150
        assert r.call_count == 2

    def test_to_dict(self):
        r = UsageRecord(provider="test", model="m1")
        r.record(100, 50, CostTier.MEDIUM)
        d = r.to_dict()
        assert d["provider"] == "test"
        assert d["model"] == "m1"
        assert d["input_tokens"] == 100
        assert d["output_tokens"] == 50
        assert d["call_count"] == 1
        assert isinstance(d["total_cost_estimated"], float)

    def test_from_dict(self):
        r = UsageRecord.from_dict(
            {
                "provider": "test",
                "model": "m1",
                "input_tokens": 100,
                "output_tokens": 50,
                "call_count": 1,
                "total_cost_estimated": 0.001,
            }
        )
        assert r.provider == "test"
        assert r.model == "m1"
        assert r.input_tokens == 100
        assert r.output_tokens == 50
        assert r.call_count == 1
        assert r.total_cost_estimated == 0.001

    def test_from_dict_ignores_extra_keys(self):
        r = UsageRecord.from_dict(
            {
                "provider": "test",
                "model": "m1",
                "input_tokens": 100,
                "output_tokens": 50,
                "call_count": 1,
                "total_cost_estimated": 0.001,
                "extra": "ignored",
            }
        )
        assert not hasattr(r, "extra")


class TestUsageTotals:
    def test_defaults(self):
        t = UsageTotals()
        assert t.total_tokens == 0
        assert t.estimated_cost_usd == 0.0

    def test_custom_values(self):
        t = UsageTotals(total_tokens=1500, estimated_cost_usd=0.05)
        assert t.total_tokens == 1500
        assert t.estimated_cost_usd == 0.05


class TestUsageTracker:
    def test_init(self):
        t = UsageTracker()
        assert t._records == {}
        assert t._path is None

    def test_init_with_path(self):
        t = UsageTracker(path="/tmp/test.json")
        assert t._path == "/tmp/test.json"

    def test_session_totals_empty(self):
        t = UsageTracker()
        totals = t.session_totals()
        assert totals.total_tokens == 0
        assert totals.estimated_cost_usd == 0.0

    def test_session_totals_with_records(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        t.record_call("anthropic", "claude-3", 200, 100)
        totals = t.session_totals()
        assert totals.total_tokens == 450
        assert totals.estimated_cost_usd > 0

    def test_record_call_new_key(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        key = "openai/gpt-4"
        assert key in t._records
        assert t._records[key].input_tokens == 100
        assert t._records[key].output_tokens == 50

    def test_record_call_existing_key(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        t.record_call("openai", "gpt-4", 200, 100)
        key = "openai/gpt-4"
        assert t._records[key].input_tokens == 300
        assert t._records[key].output_tokens == 150
        assert t._records[key].call_count == 2

    def test_record_call_with_cost_tier(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50, cost_tier=CostTier.HIGH)
        key = "openai/gpt-4"
        assert t._records[key].total_cost_estimated > 0

    def test_summary_empty(self):
        t = UsageTracker()
        assert t.summary() == "No LLM usage this session."

    def test_summary_with_records(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        summary = t.summary()
        assert "LLM calls: 1" in summary
        assert "Tokens:" in summary
        assert "Est. cost:" in summary

    def test_summary_multiple_records(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        t.record_call("anthropic", "claude-3", 200, 100)
        summary = t.summary()
        assert "LLM calls: 2" in summary

    def test_to_dict_empty(self):
        t = UsageTracker()
        assert t.to_dict() == {}

    def test_to_dict_with_records(self):
        t = UsageTracker()
        t.record_call("openai", "gpt-4", 100, 50)
        d = t.to_dict()
        assert "openai/gpt-4" in d
        assert d["openai/gpt-4"]["input_tokens"] == 100

    def test_save_without_path(self):
        t = UsageTracker()
        t.save()

    def test_save_with_path(self, tmp_path: Path):
        path = str(tmp_path / "usage.json")
        t = UsageTracker(path=path)
        t.record_call("openai", "gpt-4", 100, 50)
        t.save()
        assert Path(path).exists()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert "openai/gpt-4" in data

    def test_save_creates_parent_dir(self, tmp_path: Path):
        path = str(tmp_path / "sub" / "usage.json")
        t = UsageTracker(path=path)
        t.record_call("openai", "gpt-4", 100, 50)
        t.save()
        assert Path(path).exists()

    def test_save_exception_logged(self, tmp_path: Path, caplog):
        caplog.set_level(logging.DEBUG)
        t = UsageTracker(path=str(tmp_path))
        with patch.object(Path, "mkdir", side_effect=OSError("permission denied")):
            t.record_call("openai", "gpt-4", 100, 50)
            t.save()
            assert "Failed to save usage tracker" in caplog.text

    def test_load_returns_tracker(self, tmp_path: Path):
        path = str(tmp_path / "usage.json")
        original = UsageTracker(path=path)
        original.record_call("openai", "gpt-4", 100, 50)
        original.save()
        loaded = UsageTracker.load(path)
        assert isinstance(loaded, UsageTracker)
        assert "openai/gpt-4" in loaded._records
        assert loaded._records["openai/gpt-4"].input_tokens == 100

    def test_load_file_not_found(self, tmp_path: Path):
        path = str(tmp_path / "nonexistent.json")
        loaded = UsageTracker.load(path)
        assert loaded._records == {}

    def test_load_json_decode_error(self, tmp_path: Path):
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("{invalid", encoding="utf-8")
        loaded = UsageTracker.load(path)
        assert loaded._records == {}
