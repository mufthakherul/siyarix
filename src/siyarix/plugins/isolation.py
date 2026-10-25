# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plugin load preflight (SX-A01).

Plugins still register tools **in-process** (the registry API requires it).
Before ``exec_module``, we optionally run a scrubbed-subprocess syntax/compile
preflight so malformed or trivially hostile entrypoints fail closed outside the
host interpreter.

When ``bwrap`` (bubblewrap) is available and OS-isolate is enabled, the compile
child is wrapped with ``--unshare-net`` / ``--die-with-parent`` and a read-only
view of the host filesystem. That hardens the *preflight* process only — it is
still **not** full OS isolation of ``register_tools``. Document that gap honestly.
"""

from __future__ import annotations

import ast
import logging
import os
import shutil
import sys
from pathlib import Path

from siyarix.subprocess_utils import safe_run_sync

logger = logging.getLogger(__name__)

# Imports that are disproportionate for a plugin registration entrypoint.
# Fail-closed under production / explicit OS-isolate; warn otherwise.
_DANGEROUS_IMPORT_ROOTS = frozenset(
    {
        "ctypes",
        "cffi",
        "pty",
        "fcntl",
        "multiprocessing",
        "pickle",
        "marshal",
        "code",
        "codeop",
        "importlib.machinery",
        # SX-A01+: process / network pivots disproportionate for register_tools.
        "subprocess",
        "socket",
        "http.server",
        "xmlrpc",
        "xmlrpc.server",
        "multiprocessing.shared_memory",
    }
)

# Builtin / attribute call names that must not appear in production entrypoints.
_DANGEROUS_CALL_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint",
        "input",  # interactive stdin hijack during load
    }
)

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


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _production_posture() -> bool:
    return _truthy("SIYARIX_PRODUCTION") or _truthy("SIYARIX_REQUIRE_MASTER_PASSWORD")


def plugin_preflight_enabled() -> bool:
    """Preflight defaults on under production flags; opt out with ``=0``."""
    raw = os.getenv("SIYARIX_PLUGIN_PREFLIGHT", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return _production_posture()


def plugin_os_isolate_enabled() -> bool:
    """Optional bubblewrap wrap for the preflight child.

    Defaults on under production when ``bwrap`` exists; set
    ``SIYARIX_PLUGIN_OS_ISOLATE=0`` to disable, ``=1`` / ``=force`` to require
    (force fails closed if ``bwrap`` is missing).
    """
    raw = os.getenv("SIYARIX_PLUGIN_OS_ISOLATE", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on", "force"}:
        return True
    return _production_posture()


def plugin_os_isolate_required() -> bool:
    return os.getenv("SIYARIX_PLUGIN_OS_ISOLATE", "").strip().lower() == "force"


def _imported_modules_from_tree(tree: ast.AST) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name or ""
                if name:
                    mods.add(name)
                    mods.add(name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("."):
                continue
            if mod:
                mods.add(mod)
                mods.add(mod.split(".", 1)[0])
            for alias in node.names:
                # from importlib import machinery → treat as importlib.machinery
                if mod and alias.name:
                    mods.add(f"{mod}.{alias.name}")
    return mods


def _call_basename(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _check_dangerous_calls(tree: ast.AST, path: Path) -> None:
    hits: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_basename(node.func)
        if name and name in _DANGEROUS_CALL_NAMES:
            hits.add(name)
    if not hits:
        return
    msg = (
        f"Plugin entrypoint {path.name} calls high-risk builtins for "
        f"register_tools: {', '.join(sorted(hits))}"
    )
    if _production_posture() or plugin_os_isolate_enabled():
        raise ValueError(msg)
    logger.warning("%s (allowed outside production posture)", msg)


def _check_dangerous_imports(tree: ast.AST, path: Path) -> None:
    mods = _imported_modules_from_tree(tree)
    hits: set[str] = set()
    for mod in mods:
        if mod in _DANGEROUS_IMPORT_ROOTS:
            hits.add(mod)
            continue
        for banned in _DANGEROUS_IMPORT_ROOTS:
            if mod == banned or mod.startswith(banned + "."):
                hits.add(banned)
                break
    if not hits:
        return
    msg = (
        f"Plugin entrypoint {path.name} imports high-risk modules for "
        f"register_tools: {', '.join(sorted(hits))}"
    )
    if _production_posture() or plugin_os_isolate_enabled():
        raise ValueError(msg)
    logger.warning("%s (allowed outside production posture)", msg)


def _bwrap_prefix(entry_path: Path) -> list[str] | None:
    """Return bubblewrap argv prefix, or None if unavailable / disabled."""
    if not plugin_os_isolate_enabled():
        return None
    bwrap = shutil.which("bwrap")
    if not bwrap:
        if plugin_os_isolate_required():
            raise ValueError(
                "SIYARIX_PLUGIN_OS_ISOLATE=force but bubblewrap (bwrap) is not installed"
            )
        logger.info(
            "SIYARIX_PLUGIN_OS_ISOLATE requested but bwrap missing; "
            "continuing with scrubbed-subprocess preflight only"
        )
        return None
    resolved = str(entry_path.resolve())
    parent = str(entry_path.resolve().parent)
    # Minimal sandbox: RO root, private /tmp, no network, die with parent.
    # Bind the plugin directory RO so the entrypoint remains readable.
    return [
        bwrap,
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--proc",
        "/proc",
        "--ro-bind",
        parent,
        parent,
        "--unshare-net",
        "--die-with-parent",
        "--chdir",
        parent,
    ]


def preflight_plugin_entrypoint(entry_path: Path, *, timeout: float = 15.0) -> None:
    """Raise ``ValueError`` if the entrypoint fails scrubbed-subprocess compile.

    Always runs a host-side ``ast.parse`` first (cheap). When preflight is
    enabled, also compiles in a child process with secret-scrubbed env,
    optionally under bubblewrap.
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

    _check_dangerous_imports(tree, path)
    _check_dangerous_calls(tree, path)

    if not plugin_preflight_enabled():
        return

    cmd = [sys.executable, "-c", _PREFLIGHT_SCRIPT, str(path.resolve())]
    try:
        prefix = _bwrap_prefix(path)
    except ValueError:
        raise
    if prefix:
        cmd = prefix + cmd
        logger.debug("Plugin preflight using bubblewrap for %s", path)

    result = safe_run_sync(cmd, timeout=timeout)
    if result.exit_code != 0:
        err = (result.stderr or result.stdout or "").strip()[:400]
        raise ValueError(
            f"Plugin subprocess preflight failed for {path.name}: {err or 'nonzero exit'}"
        )
    logger.debug("Plugin preflight ok for %s", path)
