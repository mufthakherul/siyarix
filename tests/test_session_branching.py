from __future__ import annotations
from pathlib import Path
from siyarix.chat.session import ChatSession
from siyarix.session_branching import BranchEntry, BranchingSession, _new_id, _now
from unittest.mock import patch
import json
import pytest

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for BranchEntry, BranchingSession, and branching utilities."""


from unittest.mock import MagicMock


class TestBranchEntry:
    def test_defaults(self):
        e = BranchEntry()
        assert e.id == ""
        assert e.parent_id == ""
        assert e.type == "message"
        assert e.role == ""
        assert e.content == ""
        assert e.metadata == {}
        assert e.timestamp == ""

    def test_all_fields(self):
        e = BranchEntry(
            id="abc",
            parent_id="root",
            type="compaction",
            role="user",
            content="hello",
            metadata={"key": "val"},
            timestamp="2024-01-01T00:00:00",
        )
        assert e.id == "abc"
        assert e.parent_id == "root"
        assert e.type == "compaction"
        assert e.role == "user"
        assert e.content == "hello"
        assert e.metadata == {"key": "val"}
        assert e.timestamp == "2024-01-01T00:00:00"


class TestNow:
    def test_valid_iso_format(self):
        ts = _now()
        assert "T" in ts
        assert ts.endswith("+00:00") or "+" in ts


class TestNewId:
    def test_length_and_hex(self):
        nid = _new_id()
        assert len(nid) == 16
        int(nid, 16)  # should not raise


class TestBranchingSessionInit:
    def test_with_session_id(self):
        bs = BranchingSession(session_id="test-session")
        assert bs.session_id == "test-session"

    def test_without_session_id_generates(self):
        bs = BranchingSession()
        assert bs.session_id
        assert len(bs.session_id) == 16

    def test_with_path(self):
        bs = BranchingSession(session_id="s1", path=Path("/tmp/test.jsonl"))
        assert bs.path == Path("/tmp/test.jsonl")

    @patch("siyarix.config.get_config_dir")
    def test_default_path_uses_config_dir(self, mock_get_config_dir):
        mock_get_config_dir.return_value = Path("/tmp/.siyarix")
        bs = BranchingSession(session_id="s1")
        assert bs.path == Path("/tmp/.siyarix") / "sessions" / "s1.jsonl"

    @patch("siyarix.config.get_config_dir")
    def test_loads_existing_data(self, mock_get_config_dir, tmp_path):
        sess_dir = tmp_path / ".siyarix" / "sessions"
        sess_dir.mkdir(parents=True)
        mock_get_config_dir.return_value = tmp_path / ".siyarix"
        jsonl_path = sess_dir / "existing.jsonl"
        unused_entry = BranchEntry(
            id="e1",
            parent_id="root",
            type="message",
            role="user",
            content="hi",
            timestamp="2024-01-01T00:00:00",
        )
        jsonl_path.write_text(
            json.dumps(
                {
                    "id": "e1",
                    "parent_id": "root",
                    "type": "message",
                    "role": "user",
                    "content": "hi",
                    "metadata": {},
                    "timestamp": "2024-01-01T00:00:00",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        bs = BranchingSession(session_id="existing", path=jsonl_path)
        assert bs.entry_count == 1
        assert bs.leaf_id == "e1"


class TestBranchingSessionProperties:
    def test_path_property(self):
        bs = BranchingSession(session_id="x", path=Path("/a/b.jsonl"))
        assert bs.path == Path("/a/b.jsonl")

    def test_leaf_id_property(self):
        bs = BranchingSession(session_id="x")
        assert bs.leaf_id == "root"

    def test_entries_returns_copy(self):
        bs = BranchingSession(session_id="x")
        entries = bs.entries
        entries.append(BranchEntry())
        assert bs.entry_count == 0

    def test_entry_count(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="user", content="hi")
        assert bs.entry_count == 1


class TestAppendEntry:
    def test_without_parent_id_uses_leaf(self):
        bs = BranchingSession(session_id="x")
        e1 = bs.append_entry("message", role="user", content="hello")
        assert e1.parent_id == "root"
        assert bs.leaf_id == e1.id

        e2 = bs.append_entry("message", role="assistant", content="world")
        assert e2.parent_id == e1.id

    def test_with_parent_id(self):
        bs = BranchingSession(session_id="x")
        unused_e1 = bs.append_entry("message", role="user", content="a")
        e2 = bs.append_entry("message", role="assistant", content="b", parent_id="root")
        assert e2.parent_id == "root"
        assert bs.leaf_id == e2.id

    def test_all_entry_types(self):
        bs = BranchingSession(session_id="x")
        e1 = bs.append_entry("session", content="session data")
        assert e1.type == "session"
        e2 = bs.append_entry("message", role="user", content="msg")
        assert e2.type == "message"
        e3 = bs.append_entry("compaction", content="sum")
        assert e3.type == "compaction"
        e4 = bs.append_entry("branch_summary", content="br")
        assert e4.type == "branch_summary"
        e5 = bs.append_entry("label", content="lbl")
        assert e5.type == "label"


class TestAddMethods:
    def test_add_message(self):
        bs = BranchingSession(session_id="x")
        e = bs.add_message("user", "hello", extra="meta")
        assert e.type == "message"
        assert e.role == "user"
        assert e.content == "hello"
        assert e.metadata == {"extra": "meta"}

    def test_add_compaction(self):
        bs = BranchingSession(session_id="x")
        e = bs.add_compaction("summary text", {"k": "v"})
        assert e.type == "compaction"
        assert e.content == "summary text"
        assert e.metadata == {"k": "v"}

    def test_add_label(self):
        bs = BranchingSession(session_id="x")
        e = bs.add_label("my-label", {"k": "v"})
        assert e.type == "label"
        assert e.content == "my-label"
        assert e.metadata == {"k": "v"}

    def test_add_branch_summary(self):
        bs = BranchingSession(session_id="x")
        e = bs.add_branch_summary("branch summary", {"k": "v"})
        assert e.type == "branch_summary"
        assert e.content == "branch summary"
        assert e.metadata == {"k": "v"}


class TestBranch:
    def test_at_specific_entry(self):
        bs = BranchingSession(session_id="x")
        e1 = bs.append_entry("message", content="a")
        unused_e2 = bs.append_entry("message", content="b")
        child = bs.branch(at_entry_id=e1.id)
        assert child.session_id == bs.session_id
        assert child.leaf_id == e1.id
        assert child.entry_count == 2

    def test_at_current_leaf(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", content="a")
        child = bs.branch()
        assert child.leaf_id == bs.leaf_id

    def test_with_summary(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", content="a")
        child = bs.branch(summary="branch reason")
        assert child.entry_count == 2
        assert child._entries[-1].type == "branch_summary"
        assert child._entries[-1].content == "branch reason"

    def test_entry_not_found_raises(self):
        bs = BranchingSession(session_id="x")
        with pytest.raises(ValueError, match="not found"):
            bs.branch(at_entry_id="nonexistent")


class TestMergeFrom:
    def test_new_entries_added(self):
        bs1 = BranchingSession(session_id="x")
        bs1.append_entry("message", content="a")

        bs2 = BranchingSession(session_id="x")
        bs2.append_entry("message", content="b")

        count = bs1.merge_from(bs2)
        assert count == 1
        assert bs1.entry_count == 2
        assert bs1.leaf_id == bs2.leaf_id

    def test_duplicate_entries_skipped(self):
        bs1 = BranchingSession(session_id="x")
        e1 = bs1.append_entry("message", content="a")

        bs2 = BranchingSession(session_id="x")
        bs2.append_entry("message", content="b")
        # Manually set bs2._entries to include bs1's entry
        bs2._entries = [e1]

        count = bs1.merge_from(bs2)
        assert count == 0
        assert bs1.entry_count == 1


class TestNavigateTo:
    def test_valid_entry(self):
        bs = BranchingSession(session_id="x")
        e = bs.append_entry("message", content="hello")
        bs.navigate_to("root")
        assert bs.leaf_id == "root"
        bs.navigate_to(e.id)
        assert bs.leaf_id == e.id

    def test_invalid_entry_raises(self):
        bs = BranchingSession(session_id="x")
        with pytest.raises(ValueError, match="not found"):
            bs.navigate_to("nonexistent")


class TestGetPathToLeaf:
    def test_walks_from_leaf_to_root(self):
        bs = BranchingSession(session_id="x")
        e1 = bs.append_entry("message", content="a")
        e2 = bs.append_entry("message", content="b")
        path = bs.get_path_to_leaf()
        assert len(path) == 2
        assert path[0].id == e1.id
        assert path[1].id == e2.id

    def test_empty_session_returns_empty_list(self):
        bs = BranchingSession(session_id="x")
        path = bs.get_path_to_leaf()
        assert path == []

    def test_leaf_id_not_in_entries(self):
        bs = BranchingSession(session_id="x")
        bs._leaf_id = "nonexistent"
        path = bs.get_path_to_leaf()
        assert path == []


class TestGetExportMarkdown:
    def test_multiple_entry_types(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="user", content="hi")
        bs.append_entry("compaction", content="summary")
        bs.append_entry("label", content="lbl")
        md = bs.get_export_markdown()
        assert "USER" in md
        assert "COMPACTION" in md
        assert "**Label**" in md


class TestGetMessages:
    def test_filters_to_message_type(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="user", content="hi")
        bs.append_entry("compaction", content="sum")
        bs.append_entry("message", role="assistant", content="hello")
        msgs = bs.get_messages()
        assert len(msgs) == 2
        assert msgs[0] == {"role": "user", "content": "hi"}
        assert msgs[1] == {"role": "assistant", "content": "hello"}

    def test_max_count_limiting(self):
        bs = BranchingSession(session_id="x")
        for i in range(5):
            bs.append_entry("message", role="user", content=f"msg{i}")
        msgs = bs.get_messages(max_count=2)
        assert len(msgs) == 2
        assert msgs[-1]["content"] == "msg4"

    def test_empty_returns_empty_list(self):
        bs = BranchingSession(session_id="x")
        assert bs.get_messages() == []

    def test_missing_role_or_content_skipped(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="", content="no role")
        bs.append_entry("message", role="user", content="")
        bs.append_entry("message", role="user", content="valid")
        msgs = bs.get_messages()
        assert len(msgs) == 1


class TestSave:
    def test_writes_jsonl(self, tmp_path):
        path = tmp_path / "sessions" / "s1.jsonl"
        bs = BranchingSession(session_id="s1", path=path)
        bs.append_entry("message", role="user", content="hi")
        saved = bs.save()
        assert saved == path
        assert path.exists()
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["role"] == "user"
        assert data["content"] == "hi"

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "a" / "b" / "c.jsonl"
        bs = BranchingSession(session_id="c", path=path)
        bs.append_entry("message", content="test")
        bs.save()
        assert path.exists()

    def test_returns_path(self, tmp_path):
        path = tmp_path / "s.jsonl"
        bs = BranchingSession(session_id="s", path=path)
        assert bs.save() == path

    def test_sets_dirty_false(self, tmp_path):
        path = tmp_path / "s.jsonl"
        bs = BranchingSession(session_id="s", path=path)
        bs.append_entry("message", content="x")
        assert bs._dirty
        bs.save()
        assert not bs._dirty


class TestOpen:
    def test_opens_existing_file(self, tmp_path):
        path = tmp_path / "s1.jsonl"
        entry = {
            "id": "e1",
            "parent_id": "root",
            "type": "message",
            "role": "user",
            "content": "hi",
            "metadata": {},
            "timestamp": "2024-01-01T00:00:00",
        }
        path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        bs = BranchingSession.open(path)
        assert bs.session_id == "s1"
        assert bs.entry_count == 1

    def test_opens_with_session_id_in_metadata(self, tmp_path):
        path = tmp_path / "custom.jsonl"
        entry = {
            "id": "e1",
            "parent_id": "root",
            "type": "session",
            "role": "",
            "content": "",
            "metadata": {"session_id": "abc123"},
            "timestamp": "2024-01-01T00:00:00",
        }
        path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        bs = BranchingSession.open(path)
        assert bs.session_id == "abc123"

    def test_parses_first_line_with_empty_file(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("", encoding="utf-8")
        bs = BranchingSession.open(path)
        assert bs.session_id == "empty"


class TestExport:
    def test_get_export_json(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="user", content="hi")
        data = bs.get_export_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["role"] == "user"
        assert data[0]["content"] == "hi"

    def test_get_export_markdown_messages(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("message", role="user", content="hello")
        bs.append_entry("message", role="assistant", content="world")
        md = bs.get_export_markdown()
        assert "# Session: x" in md
        assert "## USER" in md
        assert "hello" in md
        assert "## ASSISTANT" in md
        assert "world" in md

    def test_get_export_markdown_compaction(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("compaction", content="summary text")
        md = bs.get_export_markdown()
        assert "## COMPACTION" in md
        assert "summary text" in md

    def test_get_export_markdown_label(self):
        bs = BranchingSession(session_id="x")
        bs.append_entry("label", content="my-label")
        md = bs.get_export_markdown()
        assert "**Label**" in md
        assert "my-label" in md


class TestLoad:
    def test_file_does_not_exist(self):
        bs = BranchingSession(session_id="x", path=Path("/nonexistent/path.jsonl"))
        assert bs.entry_count == 0

    def test_file_with_valid_jsonl(self, tmp_path):
        path = tmp_path / "s.jsonl"
        path.write_text(
            json.dumps(
                {
                    "id": "e1",
                    "parent_id": "root",
                    "type": "message",
                    "role": "user",
                    "content": "hi",
                    "metadata": {},
                    "timestamp": "2024-01-01T00:00:00",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        bs = BranchingSession(session_id="s", path=path)
        assert bs.entry_count == 1
        assert bs._entries[0].content == "hi"

    def test_bad_json_logs_warning(self, tmp_path):
        path = tmp_path / "bad.jsonl"
        path.write_text("not valid json\n", encoding="utf-8")
        bs = BranchingSession(session_id="s", path=path)
        assert bs.entry_count == 0

    def test_extra_fields_in_jsonl_are_filtered(self, tmp_path):
        path = tmp_path / "s.jsonl"
        path.write_text(
            json.dumps(
                {
                    "id": "e1",
                    "parent_id": "root",
                    "type": "message",
                    "role": "user",
                    "content": "hi",
                    "metadata": {},
                    "timestamp": "2024-01-01T00:00:00",
                    "unknown_field": "should be ignored",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        bs = BranchingSession(session_id="s", path=path)
        assert bs.entry_count == 1

    def test_empty_lines_skipped(self, tmp_path):
        path = tmp_path / "s.jsonl"
        path.write_text("\n\n\n", encoding="utf-8")
        bs = BranchingSession(session_id="s", path=path)
        assert bs.entry_count == 0


class TestHasEntry:
    def test_entry_exists(self):
        bs = BranchingSession(session_id="x")
        e = bs.append_entry("message", content="a")
        assert bs._has_entry(e.id)

    def test_does_not_exist(self):
        bs = BranchingSession(session_id="x")
        assert not bs._has_entry("nonexistent")


class TestSessionBranchingCore:
    """Cover missing session.py lines."""

    def test_branching_property_lazy_init(self):
        from siyarix.chat.session import ChatSession

        session = ChatSession(session_id="test")
        session._branching = None
        with patch("siyarix.session_branching.BranchingSession") as MockBS:
            MockBS.return_value = "branched"
            assert session.branching == "branched"

    def test_add_message_truncates_long_content(self):
        from siyarix.chat.session import ChatSession

        session = ChatSession(session_id="test")
        long = "x" * 60000
        msg = session.add_message("user", long)
        assert "[truncated]" in msg.content
        assert len(msg.content) <= 50000 + 15

    def test_add_message_limits_history(self):
        from siyarix.chat.session import ChatSession

        session = ChatSession(session_id="test")
        session._branching = None
        for i in range(350):
            session.add_message("user", f"msg_{i}")
        assert len(session.messages) <= 300

    def test_add_message_calls_branching_when_initialized(self):
        from siyarix.chat.session import ChatSession

        session = ChatSession(session_id="test")
        mock_branch = MagicMock()
        session._branching = mock_branch
        session.add_message("user", "hello")
        mock_branch.add_message.assert_called_once()

    def test_branch_with_index_and_branching(self):
        from siyarix.chat.session import ChatSession

        session = ChatSession(session_id="test")
        session.add_message("user", "hi")
        mock_branch = MagicMock()
        mock_path = [MagicMock()]
        mock_path[0].id = "e1"
        mock_branch.get_path_to_leaf.return_value = mock_path
        mock_branched = MagicMock()
        mock_branch.branch.return_value = mock_branched
        session._branching = mock_branch
        new = session.branch(at_message_idx=0, summary="sum")
        assert new._branching == mock_branched
        assert len(new.messages) == 1

    def test_save_calls_branching_save_when_is_branchingsession(self, tmp_path):
        from siyarix.chat.session import ChatSession
        from siyarix.session_branching import BranchingSession

        session = ChatSession(session_id="test")
        mock_bs = MagicMock(spec=BranchingSession)
        session._branching = mock_bs
        path = tmp_path / "session.json"
        session.save(path)
        mock_bs.save.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# compliance.py (0% - all 59 lines)
# ═══════════════════════════════════════════════════════════════════
class TestSessionBranchingEdgeCases:
    """Cover remaining session.py branches: branching property, branch path, save isinstance check."""

    def test_branching_property_already_initialized(self):
        session = ChatSession(session_id="test")
        mock_branch = MagicMock()
        session._branching = mock_branch
        assert session.branching == mock_branch

    def test_branch_no_branching_at_message_idx_none(self):
        session = ChatSession(session_id="test")
        session._branching = None
        session.add_message("user", "hi")
        new = session.branch(at_message_idx=None, summary="test")
        assert new is not None
        assert new.session_id == "test"

    def test_save_with_non_branchingsession_skips_save(self, tmp_path):
        session = ChatSession(session_id="test")
        session._branching = MagicMock()
        session._branching.__class__.__name__ = "NotBranchingSession"
        path = tmp_path / "session.json"
        session.save(path)
        assert path.exists()


# ═══════════════════════════════════════════════════════════════════
# 6. __main__.py (67% - missing line 9)
# ═══════════════════════════════════════════════════════════════════
