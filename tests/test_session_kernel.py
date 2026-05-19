from pathlib import Path

from phalanx.core.session_kernel import SessionKernel, SessionPersistenceLevel


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

