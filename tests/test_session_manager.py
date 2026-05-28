# SPDX-License-Identifier: AGPL-3.0-or-later


import pytest

from siyarix.session_manager import (
    CommandHistory,
    SessionMeta,
    SessionRegistry,
    command_history,
    session_registry,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("SIYARIX_CONFIG_DIR", raising=False)


@pytest.fixture
def cmd_history(tmp_path):
    return CommandHistory(db_path=tmp_path / "cmd.db")


@pytest.fixture
def registry(tmp_path):
    return SessionRegistry(db_path=tmp_path / "sessions.db")


class TestCommandHistory:
    def test_init_creates_db(self, tmp_path):
        db = tmp_path / "test.db"
        _ch = CommandHistory(db_path=db)
        assert db.exists()

    def test_add_command(self, cmd_history):
        cmd_history.add("nmap -sV 10.0.0.1", session_id="s1", result="success", duration_ms=1500.0, tool="nmap")
        recent = cmd_history.recent(limit=10)
        assert len(recent) >= 1
        assert recent[0]["command"] == "nmap -sV 10.0.0.1"

    def test_add_with_metadata(self, cmd_history):
        cmd_history.add("curl target", session_id="s1", custom_key="custom_val")
        recent = cmd_history.recent()
        assert any(r["command"] == "curl target" for r in recent)

    def test_search(self, cmd_history):
        cmd_history.add("nmap scanme.nmap.org", session_id="s1")
        cmd_history.add("gobuster dir -u target", session_id="s1")
        results = cmd_history.search("nmap")
        assert len(results) >= 1
        assert all("nmap" in r["command"] for r in results)

    def test_search_no_results(self, cmd_history):
        assert cmd_history.search("nonexistent-cmd-that-never-exists") == []

    def test_recent_empty(self, cmd_history):
        recent = cmd_history.recent(limit=100)
        assert recent == []

    def test_most_used(self, cmd_history):
        cmd_history.add("nmap", session_id="s1")
        cmd_history.add("nmap", session_id="s1")
        cmd_history.add("curl", session_id="s1")
        most = cmd_history.most_used(limit=10)
        assert len(most) >= 2
        cmd_counts = dict(most)
        assert cmd_counts["nmap"] >= 2

    def test_clear(self, cmd_history):
        cmd_history.add("test command", session_id="s1")
        cmd_history.clear()
        assert cmd_history.count() == 0

    def test_count(self, cmd_history):
        assert cmd_history.count() == 0
        cmd_history.add("cmd1", session_id="s1")
        assert cmd_history.count() == 1

    def test_add_multiple_sessions(self, cmd_history):
        cmd_history.add("cmd1", session_id="s1")
        cmd_history.add("cmd2", session_id="s2")
        assert cmd_history.count() == 2

    def test_get_conn_returns_connection(self, cmd_history):
        conn = cmd_history._get_conn()
        assert conn is not None
        conn.close()


class TestSessionRegistry:
    def test_init_creates_db(self, tmp_path):
        db = tmp_path / "sessions.db"
        _sr = SessionRegistry(db_path=db)
        assert db.exists()

    def test_register_and_get(self, registry):
        meta = SessionMeta(
            session_id="abc-123",
            name="Test Session",
            mode="integrated",
            target="10.0.0.1",
            tags=["web", "critical"],
            notes="Important session",
        )
        registry.register(meta)
        retrieved = registry.get_session("abc-123")
        assert retrieved is not None
        assert retrieved.session_id == "abc-123"
        assert retrieved.name == "Test Session"
        assert "web" in retrieved.tags
        assert retrieved.notes == "Important session"

    def test_get_session_not_found(self, registry):
        assert registry.get_session("nonexistent") is None

    def test_update_active(self, registry):
        meta = SessionMeta(session_id="s1")
        registry.register(meta)
        registry.update_active("s1", message_count=5)
        retrieved = registry.get_session("s1")
        assert retrieved is not None
        assert retrieved.message_count == 5
        assert retrieved.last_active != ""

    def test_list_sessions(self, registry):
        registry.register(SessionMeta(session_id="s1"))
        registry.register(SessionMeta(session_id="s2"))
        sessions = registry.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_empty(self, registry):
        assert registry.list_sessions() == []

    def test_delete_session_existing(self, registry):
        registry.register(SessionMeta(session_id="s1"))
        assert registry.delete_session("s1") is True
        assert registry.get_session("s1") is None

    def test_delete_session_not_found(self, registry):
        assert registry.delete_session("nonexistent") is False

    def test_tag_session(self, registry):
        registry.register(SessionMeta(session_id="s1"))
        registry.tag_session("s1", "critical", "web")
        retrieved = registry.get_session("s1")
        assert "critical" in retrieved.tags
        assert "web" in retrieved.tags

    def test_tag_session_not_found(self, registry):
        registry.tag_session("nonexistent", "tag1")

    def test_tag_session_adds_to_existing(self, registry):
        registry.register(SessionMeta(session_id="s1", tags=["existing"]))
        registry.tag_session("s1", "new-tag")
        retrieved = registry.get_session("s1")
        assert "existing" in retrieved.tags
        assert "new-tag" in retrieved.tags

    def test_find_by_target(self, registry):
        registry.register(SessionMeta(session_id="s1", target="10.0.0.1"))
        registry.register(SessionMeta(session_id="s2", target="192.168.1.1"))
        results = registry.find_by_target("10.0.0")
        assert len(results) == 1
        assert results[0].session_id == "s1"

    def test_find_by_target_no_results(self, registry):
        assert registry.find_by_target("nonexistent") == []

    def test_find_by_tag(self, registry):
        registry.register(SessionMeta(session_id="s1", tags=["critical"]))
        registry.register(SessionMeta(session_id="s2", tags=["low"]))
        results = registry.find_by_tag("critical")
        assert len(results) == 1
        assert results[0].session_id == "s1"

    def test_find_by_tag_no_results(self, registry):
        assert registry.find_by_tag("nonexistent") == []

    def test_register_updates_existing(self, registry):
        registry.register(SessionMeta(session_id="s1", name="Original"))
        registry.register(SessionMeta(session_id="s1", name="Updated"))
        retrieved = registry.get_session("s1")
        assert retrieved.name == "Updated"

    def test_row_to_meta(self, registry):
        class MockRow(dict):
            def __getitem__(self, key):
                return self.get(key)
            def keys(self):
                return self.keys()
        row = MockRow(
            session_id="r1", name="R1", mode="integrated", target="t1",
            created_at="2024-01-01", last_active="2024-01-02",
            message_count=3, tags_json='["a","b"]', notes="notes"
        )
        meta = SessionRegistry._row_to_meta(row)
        assert meta.session_id == "r1"
        assert meta.tags == ["a", "b"]

    def test_row_to_meta_empty_tags(self, registry):
        class MockRow(dict):
            def __getitem__(self, key):
                return self.get(key)
            def keys(self):
                return self.keys()
        row = MockRow(
            session_id="r2", name="R2", mode="integrated", target="",
            created_at="", last_active="", message_count=0,
            tags_json="", notes=""
        )
        meta = SessionRegistry._row_to_meta(row)
        assert meta.tags == []

    def test_register_with_defaults(self, registry):
        meta = SessionMeta(session_id="auto")
        registry.register(meta)
        retrieved = registry.get_session("auto")
        assert retrieved.created_at != ""

    def test_module_singletons(self):
        assert command_history is not None
        assert session_registry is not None
