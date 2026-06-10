# SPDX-License-Identifier: AGPL-3.0-or-later

import json

import pytest

from siyarix.session_log import (
    CommandEntry,
    SafetyEvent,
    SessionLog,
    SessionLogger,
    session_logger,
)


@pytest.fixture
def logger(tmp_path):
    return SessionLogger(log_dir=tmp_path)


@pytest.fixture
def sample_log():
    return SessionLog(
        session_id="test-session-1",
        timestamp_start="2024-01-01T00:00:00",
        timestamp_end="",
        persona="bug_hunter",
        llm_provider="openai",
        llm_model="gpt-4",
        user="testuser",
        commands=[
            CommandEntry(
                id=1,
                timestamp="2024-01-01T00:00:01",
                input="nmap -sV target",
                output_summary="open ports found",
            ),
        ],
        tool_usage={"nmap": 1, "gobuster": 2},
        safety_events=[
            SafetyEvent(type="permission_gate", command="rm -rf /", action="blocked"),
        ],
    )


class TestSessionLog:
    def test_to_dict(self, sample_log):
        d = sample_log.to_dict()
        assert d["session_id"] == "test-session-1"
        assert d["commands"][0]["input"] == "nmap -sV target"
        assert d["tool_usage"]["nmap"] == 1
        assert d["safety_events"][0]["type"] == "permission_gate"

    def test_from_dict(self, sample_log):
        d = sample_log.to_dict()
        restored = SessionLog.from_dict(d)
        assert restored.session_id == "test-session-1"
        assert len(restored.commands) == 1
        assert restored.commands[0].input == "nmap -sV target"
        assert restored.tool_usage["gobuster"] == 2

    def test_from_dict_empty(self):
        restored = SessionLog.from_dict({})
        assert restored.session_id == ""

    def test_session_log_dataclass_defaults(self):
        s = SessionLog()
        assert s.session_id == ""
        assert s.commands == []
        assert s.tool_usage == {}
        assert s.safety_events == []

    def test_command_entry_defaults(self):
        c = CommandEntry()
        assert c.id == 0
        assert c.input == ""

    def test_safety_event_defaults(self):
        e = SafetyEvent()
        assert e.type == "permission_gate"
        assert e.command == ""


class TestSessionLogger:
    def test_init_creates_dir(self, tmp_path):
        sub = tmp_path / "logs"
        _logger = SessionLogger(log_dir=sub)
        assert sub.exists()

    def test_save(self, logger, sample_log):
        path = logger.save(sample_log)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["session_id"] == "test-session-1"

    def test_load(self, logger, sample_log):
        logger.save(sample_log)
        loaded = logger.load("test-session-1")
        assert loaded is not None
        assert loaded.session_id == "test-session-1"

    def test_load_not_found(self, logger):
        assert logger.load("nonexistent") is None

    def test_load_corrupt(self, logger, sample_log):
        path = logger._path("test-session-1")
        path.write_text("not json", encoding="utf-8")
        loaded = logger.load("test-session-1")
        assert loaded is None

    def test_list_logs(self, logger, sample_log):
        logger.save(sample_log)
        logs = logger.list_logs()
        assert len(logs) == 1
        assert logs[0]["session_id"] == "test-session-1"
        assert logs[0]["commands"] == 1

    def test_list_logs_empty_dir(self, tmp_path):
        empty_logger = SessionLogger(log_dir=tmp_path / "empty")
        empty_logger._log_dir.mkdir(parents=True, exist_ok=True)
        assert empty_logger.list_logs() == []

    def test_list_logs_skips_corrupt(self, logger, sample_log):
        logger.save(sample_log)
        corrupt = logger._log_dir / "corrupt.json"
        corrupt.write_text("bad json", encoding="utf-8")
        logs = logger.list_logs()
        ids = [log["session_id"] for log in logs]
        assert "test-session-1" in ids

    def test_delete(self, logger, sample_log):
        logger.save(sample_log)
        assert logger.delete("test-session-1") is True
        assert logger.delete("test-session-1") is False

    def test_delete_not_found(self, logger):
        assert logger.delete("nonexistent") is False

    def test_export_markdown(self, logger, sample_log):
        logger.save(sample_log)
        md = logger.export_markdown("test-session-1")
        assert md is not None
        assert "# Session Log" in md
        assert "nmap" in md
        assert "gobuster" in md
        assert "permission_gate" in md

    def test_export_markdown_not_found(self, logger):
        assert logger.export_markdown("nonexistent") is None

    def test_export_json_str(self, logger, sample_log):
        logger.save(sample_log)
        js = logger.export_json_str("test-session-1")
        assert js is not None
        data = json.loads(js)
        assert data["session_id"] == "test-session-1"

    def test_export_json_str_not_found(self, logger):
        assert logger.export_json_str("nonexistent") is None

    def test_export_sarif(self, logger, sample_log):
        logger.save(sample_log)
        sarif_str = logger.export_sarif("test-session-1")
        assert sarif_str is not None
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "CMD-0001"

    def test_export_sarif_not_found(self, logger):
        assert logger.export_sarif("nonexistent") is None

    def test_add_safety_event(self, logger, sample_log):
        logger.save(sample_log)
        result = logger.add_safety_event("test-session-1", "some command", "allowed")
        assert result is True
        loaded = logger.load("test-session-1")
        assert len(loaded.safety_events) == 2
        assert loaded.safety_events[1].command == "some command"

    def test_add_safety_event_not_found(self, logger):
        assert logger.add_safety_event("nonexistent", "cmd", "action") is False

    def test_add_command(self, logger, sample_log):
        logger.save(sample_log)
        result = logger.add_command(
            "test-session-1",
            input_text="nuclei -t cves",
            output_summary="found vulns",
            ai_plan=["scan", "analyze"],
        )
        assert result is True
        loaded = logger.load("test-session-1")
        assert len(loaded.commands) == 2
        assert loaded.commands[1].id == 2
        assert loaded.commands[1].input == "nuclei -t cves"
        assert loaded.commands[1].ai_plan == ["scan", "analyze"]

    def test_add_command_not_found(self, logger):
        assert logger.add_command("nonexistent", "cmd") is False

    def test_track_tool_usage(self, logger, sample_log):
        logger.save(sample_log)
        result = logger.track_tool_usage("test-session-1", "nuclei", count=3)
        assert result is True
        loaded = logger.load("test-session-1")
        assert loaded.tool_usage["nuclei"] == 3

    def test_track_tool_usage_not_found(self, logger):
        assert logger.track_tool_usage("nonexistent", "tool") is False

    def test_update_end_time(self, logger, sample_log):
        logger.save(sample_log)
        result = logger.update_end_time("test-session-1")
        assert result is True
        loaded = logger.load("test-session-1")
        assert loaded.timestamp_end != ""

    def test_update_end_time_not_found(self, logger):
        assert logger.update_end_time("nonexistent") is False

    def test_create_log(self, logger):
        log = logger.create_log(
            session_id="new-session",
            persona="pentester",
            llm_provider="ollama",
            llm_model="llama3",
            user="alice",
        )
        assert log.session_id == "new-session"
        assert log.persona == "pentester"
        assert log.timestamp_start != ""
        loaded = logger.load("new-session")
        assert loaded is not None

    def test_module_singleton(self):
        assert session_logger is not None
        assert isinstance(session_logger, SessionLogger)

    def test_path_format(self, logger):
        path = logger._path("abc-123")
        assert path.name == "abc-123.json"
