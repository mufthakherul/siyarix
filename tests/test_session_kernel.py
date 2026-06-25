from pathlib import Path
from unittest.mock import MagicMock

from siyarix.chat.session import ChatSession
from siyarix.compat import SessionKernel, SessionPersistenceLevel

# SPDX-License-Identifier: AGPL-3.0-or-later


def test_session_kernel_save_load_roundtrip(tmp_path: Path) -> None:
    kernel = SessionKernel(base_dir=tmp_path)
    session = kernel.start(
        objective="scan campaign",
        scope="example.com",
        persistence=SessionPersistenceLevel.WORKSPACE,
    )
    op = kernel.add_operation(session, "scan example.com with nmap", "integrated", "medium")
    kernel.update_operation(
        session,
        op.operation_id,
        state="completed",
        retries=1,
        artifact="plan-123",
        audit_hash="abc123",
    )
    kernel.save(session)

    loaded = kernel.load(session.session_id)
    assert loaded is not None
    assert loaded.objective == "scan campaign"
    assert len(loaded.operations) == 1
    assert loaded.operations[0].state == "completed"
    assert loaded.operations[0].artifacts == ["plan-123"]


class TestSessionEdgeCases:
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
class TestSessionBranchEdge:
    """Lines 82-84: at_message_idx >= len(path) branch (entry_id stays None)."""

    def test_branch_index_out_of_range(self):
        session = ChatSession(session_id="test")
        session.add_message("user", "hi")
        session.add_message("user", "there")
        mock_branch = MagicMock()
        mock_path = [MagicMock(), MagicMock()]
        mock_path[0].id = "e1"
        mock_path[1].id = "e2"
        mock_branch.get_path_to_leaf.return_value = mock_path
        mock_branched = MagicMock()
        mock_branch.branch.return_value = mock_branched
        session._branching = mock_branch
        # at_message_idx=5 > len(path)=2 => entry_id stays None
        new = session.branch(at_message_idx=5, summary="test")
        assert new._branching == mock_branched
        assert len(new.messages) == 2
        mock_branch.branch.assert_called_once_with(at_entry_id=None, summary="test")


# ═══════════════════════════════════════════════════════════════════
# 4. chat/commands.py (99% - missing 122->124) — save edge case
# ═══════════════════════════════════════════════════════════════════
