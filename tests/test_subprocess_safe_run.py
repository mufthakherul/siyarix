import subprocess
import sys
from nexsec.executor import safe_run_sync


def test_safe_run_sync_basic():
    # Basic command should succeed (cross-platform using Python)
    res = safe_run_sync([sys.executable, "-c", "print('hello')"], timeout=5)
    assert isinstance(res, subprocess.CompletedProcess)
    assert res.returncode == 0
    assert "hello" in res.stdout


def test_safe_run_sync_rejects_suspicious():
    # Command parts containing shell metacharacters should be rejected
    try:
        safe_run_sync(["/bin/sh", "-c", "echo hi; rm -rf /"])
        raised = False
    except ValueError:
        raised = True
    assert raised, "Expected ValueError for suspicious command parts"

