# SPDX-License-Identifier: AGPL-3.0-or-later

import sys

from siyarix.subprocess_utils import safe_run_sync, ExecutionResult


def test_safe_run_sync_basic():
    res = safe_run_sync([sys.executable, "-c", "print('hello')"], timeout=5)
    assert isinstance(res, ExecutionResult)
    assert res.exit_code == 0
    assert "hello" in res.stdout


def test_safe_run_sync_rejects_suspicious():
    try:
        safe_run_sync(["/bin/sh", "-c", "echo hi; rm -rf /"])
        raised = False
    except ValueError:
        raised = True
    assert raised, "Expected ValueError for suspicious command parts"
