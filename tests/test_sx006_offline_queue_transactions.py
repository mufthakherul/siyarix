# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-006: OfflineCommandQueue write paths use explicit SQLite transactions."""

from __future__ import annotations

import sqlite3

import pytest

from siyarix.offline_queue import OfflineCommandQueue, OfflineCommandReplay


@pytest.fixture
def queue(tmp_path):
    q = OfflineCommandQueue(db_path=tmp_path / "offline_queue.db")
    yield q
    q.close()


class TestSX006Transactions:
    def test_enqueue_survives_close_and_reopen(self, tmp_path):
        db = tmp_path / "persist.db"
        q1 = OfflineCommandQueue(db_path=db)
        cmd_id = q1.enqueue("scan target.example", target="target.example")
        assert q1.get_pending_count() == 1
        q1.close()

        q2 = OfflineCommandQueue(db_path=db)
        pending = q2.dequeue()
        assert len(pending) == 1
        assert pending[0].id == cmd_id
        assert pending[0].instruction == "scan target.example"
        # dequeue atomically claims rows as processing
        assert pending[0].status == "processing"
        assert q2.get_pending_count() == 1  # pending+processing counted together
        q2.close()

    def test_status_updates_commit(self, tmp_path):
        db = tmp_path / "status.db"
        q1 = OfflineCommandQueue(db_path=db)
        cmd_id = q1.enqueue("do work")
        q1.mark_processing(cmd_id)
        q1.mark_completed(cmd_id, summary="ok")
        q1.close()

        q2 = OfflineCommandQueue(db_path=db)
        assert q2.get_completed_count() == 1
        assert q2.get_pending_count() == 0
        rows = q2.get_all()
        assert rows[0].status == "completed"
        assert rows[0].result_summary == "ok"
        q2.close()

    def test_mark_failed_retry_and_persist(self, tmp_path):
        db = tmp_path / "retry.db"
        q1 = OfflineCommandQueue(db_path=db)
        cmd_id = q1.enqueue("flaky", max_attempts=2)
        q1.mark_processing(cmd_id)
        q1.mark_failed(cmd_id, "boom1")  # attempts=1 < max → pending
        q1.mark_processing(cmd_id)
        q1.mark_failed(cmd_id, "boom2")  # attempts=2 >= max → failed
        q1.close()

        q2 = OfflineCommandQueue(db_path=db)
        assert q2.get_failed_count() == 1
        n = q2.retry_failed()
        assert n == 1
        q2.close()

        q3 = OfflineCommandQueue(db_path=db)
        assert q3.get_pending_count() == 1
        assert q3.get_failed_count() == 0
        q3.close()

    def test_transaction_rollback_on_error(self, queue):
        with pytest.raises(sqlite3.Error):
            with queue._transaction() as conn:
                conn.execute(
                    "INSERT INTO queued_commands (id, instruction) VALUES (?, ?)",
                    ("rollback-me", "should not persist"),
                )
                raise sqlite3.OperationalError("simulated failure")

        assert queue.get_pending_count() == 0
        assert all(c.id != "rollback-me" for c in queue.get_all())

    def test_dequeue_atomic_claim_is_exclusive(self, tmp_path):
        db = tmp_path / "claim.db"
        q = OfflineCommandQueue(db_path=db)
        a = q.enqueue("a")
        b = q.enqueue("b")
        first = q.dequeue(batch_size=1)
        second = q.dequeue(batch_size=2)
        assert [c.id for c in first] == [a]
        assert [c.id for c in second] == [b]
        assert all(c.status == "processing" for c in first + second)
        q.close()

    def test_dequeue_waits_for_dependencies(self, tmp_path):
        db = tmp_path / "deps.db"
        q = OfflineCommandQueue(db_path=db)
        parent = q.enqueue("parent")
        child = q.enqueue("child", dependencies=[parent])
        first = q.dequeue(batch_size=5)
        assert [c.id for c in first] == [parent]
        assert q.dequeue(batch_size=5) == []
        q.mark_completed(parent)
        second = q.dequeue(batch_size=5)
        assert [c.id for c in second] == [child]
        q.close()

    def test_reclaim_stale_processing(self, tmp_path):
        db = tmp_path / "reclaim.db"
        q = OfflineCommandQueue(db_path=db)
        cmd_id = q.enqueue("stuck")
        q.dequeue(batch_size=1)
        with q._transaction() as conn:
            conn.execute(
                "UPDATE queued_commands SET claimed_at = datetime('now', '-2 hours'), "
                "created_at = datetime('now', '-2 hours') WHERE id = ?",
                (cmd_id,),
            )
        n = q.reclaim_stale_processing(older_than_seconds=60)
        assert n == 1
        pending = q.dequeue(batch_size=1)
        assert pending[0].id == cmd_id
        q.close()

    def test_clear_completed_commits(self, tmp_path):
        db = tmp_path / "clear.db"
        q1 = OfflineCommandQueue(db_path=db)
        cmd_id = q1.enqueue("done")
        q1.mark_processing(cmd_id)
        q1.mark_completed(cmd_id)
        # Force old timestamp so clear_completed matches
        with q1._transaction() as conn:
            conn.execute(
                "UPDATE queued_commands SET created_at = datetime('now', '-30 days') WHERE id = ?",
                (cmd_id,),
            )
        cleared = q1.clear_completed(older_than_days=7)
        assert cleared == 1
        q1.close()

        q2 = OfflineCommandQueue(db_path=db)
        assert q2.get_completed_count() == 0
        q2.close()

    @pytest.mark.asyncio
    async def test_replay_all_exhausts_retries_and_stops(self, tmp_path) -> None:
        db = tmp_path / "replay.db"
        q = OfflineCommandQueue(db_path=db)
        q.enqueue("always-fail", max_attempts=2)
        replay = OfflineCommandReplay(q)

        async def _boom(_cmd):  # type: ignore[no-untyped-def]
            raise RuntimeError("nope")

        ok, fail = await replay.replay_all(executor_fn=_boom, batch_size=1, interval=0)
        assert ok == 0
        assert fail >= 1
        assert q.get_failed_count() == 1
        assert q.get_pending_count() == 0
        q.close()
