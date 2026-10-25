# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plugin load preflight (SX-A01).

Plugins still register tools **in-process** (the registry API requires it).
Before ``exec_module``, we optionally run a scrubbed-subprocess syntax/compile
preflight so malformed or trivially hostile entrypoints fail closed outside the
host interpreter. This is **not** full OS isolation — document that gap honestly.
"""

from __future__ import annotations

import ast
import logging
import os
import sys
from pathlib import Path

from siyarix.subprocess_utils import safe_run_sync

logger = logging.getLogger(__name__)

_PREFLIGHT_SCRIPT = r"""
import ast
import sys
from pathlib import Path
path = Path(sys.argv[1])
src = path.read_text(encoding="utf-8")
tree = ast.parse(src, filename=str(path))
compile(tree, str(path), "exec")
print("ok")
"""


def plugin_preflight_enabled() -> bool:
    """Preflight defaults on under production flags; opt out with ``=0``."""
    raw = os.getenv("SIYARIX_PLUGIN_PREFLIGHT", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    # Default: on when production posture is asserted.
    return os.getenv("SIYARIX_PRODUCTION", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    } or os.getenv("SIYARIX_REQUIRE_MASTER_PASSWORD", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def preflight_plugin_entrypoint(entry_path: Path, *, timeout: float = 15.0) -> None:
    """Raise ``ValueError`` if the entrypoint fails scrubbed-subprocess compile.

    Always runs a host-side ``ast.parse`` first (cheap). When preflight is
    enabled, also compiles in a child process with secret-scrubbed env.
    """
    path = Path(entry_path)
    if not path.is_file():
        raise ValueError(f"Plugin entrypoint missing: {path}")
    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read plugin entrypoint {path}: {exc}") from exc
    try:
        tree = ast.parse(src, filename=str(path))
        compile(tree, str(path), "exec")
    except SyntaxError as exc:
        raise ValueError(f"Plugin entrypoint syntax error: {exc}") from exc

    if not plugin_preflight_enabled():
        return

    result = safe_run_sync(
        [sys.executable, "-c", _PREFLIGHT_SCRIPT, str(path.resolve())],
        timeout=timeout,
    )
    if result.exit_code != 0:
        err = (result.stderr or result.stdout or "").strip()[:400]
        raise ValueError(
            f"Plugin subprocess preflight failed for {path.name}: {err or 'nonzero exit'}"
        )
    logger.debug("Plugin preflight ok for %s", path)
