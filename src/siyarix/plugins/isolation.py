# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plugin load preflight (SX-A01) — not a sandbox.

Plugins still register tools **in-process** via ``register_tools`` (the registry
API requires it). There is **no OS isolation** of that call: preflight and
optional bubblewrap harden only a *compile* child, never the host interpreter
that subsequently ``exec_module``s the plugin.

Before ``exec_module``, we optionally run a scrubbed-subprocess syntax/compile
preflight so malformed or trivially hostile entrypoints fail closed outside the
host interpreter. Host-side AST also rejects high-risk imports/calls under
production posture (including ``import os as o; o.system(...)`` and
``from os import system`` style bypasses).

When ``bwrap`` (bubblewrap) is available and OS-isolate is enabled, the compile
child is wrapped with ``--unshare-net`` / ``--die-with-parent`` and a read-only
view of the host filesystem. That hardens the *preflight* process only —
**preflight ≠ sandbox**. Document that gap honestly; trusted plugins remain
fully trusted in-process code.
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

# ``os.system`` / ``subprocess.run`` style attribute calls (SX-A01+).
# ``posix`` / ``nt`` are OS-specific aliases that expose the same pivots.
_DANGEROUS_ATTR_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execl"),
        ("os", "spawn"),
        ("os", "spawnl"),
        ("os", "spawnv"),
        ("posix", "system"),
        ("posix", "popen"),
        ("posix", "execv"),
        ("posix", "execve"),
        ("posix", "execl"),
        ("posix", "spawn"),
        ("posix", "spawnl"),
        ("posix", "spawnv"),
        ("nt", "system"),
        ("nt", "popen"),
        ("nt", "spawn"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
    }
)
_DANGEROUS_MODULE_ROOTS_FOR_ATTR = frozenset({"os", "posix", "nt", "subprocess", "builtins"})

# ``from <mod> import <name>`` bindings that are disproportionate for register_tools.
# Keys are import roots; values are banned leaf names (system/popen/exec*/eval-related).
_OS_LIKE_EXEC_NAMES = frozenset(
    {
        "system",
        "popen",
        "execv",
        "execve",
        "execl",
        "execlp",
        "execvp",
        "execvpe",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }
)
_DANGEROUS_FROM_IMPORT_NAMES: dict[str, frozenset[str]] = {
    "os": _OS_LIKE_EXEC_NAMES,
    "posix": _OS_LIKE_EXEC_NAMES,
    "nt": frozenset({"system", "popen", "spawn", "spawnl", "spawnv"}),
    "subprocess": frozenset(
        {
            "run",
            "call",
            "Popen",
            "check_output",
            "check_call",
            "getoutput",
            "getstatusoutput",
        }
    ),
    "builtins": frozenset(_DANGEROUS_CALL_NAMES),
    "builtin": frozenset(_DANGEROUS_CALL_NAMES),  # rare misspelling path
}

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
    """Preflight defaults on under production flags; opt out with ``=0``.

    Preflight is a compile/syntax gate only — it does **not** sandbox
    ``register_tools`` (still in-process on the host).
    """
    raw = os.getenv("SIYARIX_PLUGIN_PREFLIGHT", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return _production_posture()


def plugin_os_isolate_enabled() -> bool:
    """Optional bubblewrap wrap for the *preflight* child only (not register_tools).

    Defaults on under production when ``bwrap`` exists; set
    ``SIYARIX_PLUGIN_OS_ISOLATE=0`` to disable, ``=1`` / ``=force`` to require
    (force fails closed if ``bwrap`` is missing). Preflight ≠ OS sandbox of
    in-process plugin execution.
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


def _module_alias_map(tree: ast.AST) -> dict[str, str]:
    """Map local names → canonical module roots (``import os as o`` → ``o``→``os``).

    Also follows simple assignments (``o = os`` / ``o = aliased``) so residual
    hunter assignment pivots are closed.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if not alias.name:
                continue
            root = alias.name.split(".", 1)[0]
            local = alias.asname or alias.name.split(".", 1)[0]
            aliases[local] = root
            # ``import os`` also binds the root name itself.
            aliases.setdefault(root, root)

    # Propagate ``o = os`` / ``p = o`` style aliases (fixed-point, shallow).
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
                continue
            src = aliases.get(node.value.id, node.value.id)
            if src not in _DANGEROUS_MODULE_ROOTS_FOR_ATTR:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and aliases.get(target.id) != src:
                    aliases[target.id] = src
                    changed = True
    return aliases


def _getattr_dangerous_pair(
    call: ast.Call,
    module_aliases: dict[str, str],
) -> tuple[str, str] | None:
    """Detect ``getattr(os, \"system\")`` / ``getattr(o, \"system\")``."""
    func = call.func
    if not isinstance(func, ast.Name) or func.id != "getattr":
        return None
    if len(call.args) < 2:
        return None
    obj, attr_node = call.args[0], call.args[1]
    if not isinstance(obj, ast.Name):
        return None
    if not isinstance(attr_node, ast.Constant) or not isinstance(attr_node.value, str):
        return None
    root = module_aliases.get(obj.id, obj.id)
    return (root, attr_node.value)


def _import_module_root(call: ast.Call) -> str | None:
    """Return module root for ``importlib.import_module(\"os\")`` style calls."""
    func = call.func
    is_import_module = False
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        if isinstance(func.value, ast.Name) and func.value.id in {"importlib", "il"}:
            is_import_module = True
        elif isinstance(func.value, ast.Attribute) and func.value.attr == "importlib":
            is_import_module = True
    elif isinstance(func, ast.Name) and func.id == "import_module":
        is_import_module = True
    if not is_import_module or not call.args:
        return None
    arg0 = call.args[0]
    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
        return arg0.value.split(".", 1)[0]
    return None


def _from_import_bindings(tree: ast.AST) -> dict[str, tuple[str, str]]:
    """Map local names → ``(module_root, imported_name)`` for ``from X import Y``.

    Relative imports are ignored. ``from os import system as s`` → ``s``→``(os, system)``.
    """
    bindings: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = node.module or ""
        if not mod or mod.startswith("."):
            continue
        root = mod.split(".", 1)[0]
        for alias in node.names:
            if not alias.name or alias.name == "*":
                continue
            local = alias.asname or alias.name
            bindings[local] = (root, alias.name)
    return bindings


def _banned_from_import_hits(tree: ast.AST) -> set[str]:
    """Return display labels for banned ``from … import …`` names (SEC-02)."""
    hits: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = node.module or ""
        if not mod or mod.startswith("."):
            continue
        root = mod.split(".", 1)[0]
        banned = _DANGEROUS_FROM_IMPORT_NAMES.get(root)
        if not banned:
            # Also match full module keys (e.g. future expansion).
            banned = _DANGEROUS_FROM_IMPORT_NAMES.get(mod)
        if not banned:
            continue
        for alias in node.names:
            if alias.name == "*":
                hits.add(f"from {mod} import *")
                continue
            if alias.name in banned:
                hits.add(f"from {mod} import {alias.name}")
    return hits


def _call_basename(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _attr_call_pair(node: ast.AST) -> tuple[str, str] | None:
    """Return ``(module_or_name, attr)`` for ``os.system`` / ``subprocess.run`` calls."""
    if not isinstance(node, ast.Attribute):
        return None
    if isinstance(node.value, ast.Name):
        return (node.value.id, node.attr)
    return None


def _resolve_attr_call_pair(
    pair: tuple[str, str],
    module_aliases: dict[str, str],
) -> tuple[str, str]:
    """Resolve ``import os as o; o.system`` → ``(os, system)``."""
    local, attr = pair
    return (module_aliases.get(local, local), attr)


def _check_dangerous_calls(tree: ast.AST, path: Path) -> None:
    hits: set[str] = set()
    module_aliases = _module_alias_map(tree)
    from_bindings = _from_import_bindings(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Bare name: eval(...), or from-import alias ``system(...)`` / ``s(...)``.
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in _DANGEROUS_CALL_NAMES:
                hits.add(name)
            binding = from_bindings.get(name)
            if binding:
                root, imported = binding
                if (root, imported) in _DANGEROUS_ATTR_CALLS:
                    hits.add(f"{root}.{imported}")
                banned = _DANGEROUS_FROM_IMPORT_NAMES.get(root)
                if banned and imported in banned:
                    hits.add(f"{root}.{imported}")
                if imported in _DANGEROUS_CALL_NAMES:
                    hits.add(imported)
            # getattr(os, "system") as a call expression (may be nested below).
            gpair = _getattr_dangerous_pair(node, module_aliases)
            if gpair and gpair in _DANGEROUS_ATTR_CALLS:
                hits.add(f"getattr({gpair[0]}, {gpair[1]!r})")
            continue

        # getattr(os, "system")("id") — Call whose func is itself getattr(...).
        if isinstance(node.func, ast.Call):
            gpair = _getattr_dangerous_pair(node.func, module_aliases)
            if gpair and gpair in _DANGEROUS_ATTR_CALLS:
                hits.add(f"getattr({gpair[0]}, {gpair[1]!r})")

        name = _call_basename(node.func)
        if name and name in _DANGEROUS_CALL_NAMES:
            # Attribute form ending in eval/exec etc. (rare); keep Name.attr path.
            hits.add(name)
        pair = _attr_call_pair(node.func)
        if pair:
            resolved = _resolve_attr_call_pair(pair, module_aliases)
            if resolved in _DANGEROUS_ATTR_CALLS:
                hits.add(f"{resolved[0]}.{resolved[1]}")
            # Unresolved Name.attr still checked via original pair (existing path).
            elif pair in _DANGEROUS_ATTR_CALLS:
                hits.add(f"{pair[0]}.{pair[1]}")
            continue

        # importlib.import_module("os").system(...)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            mod_root = _import_module_root(node.func.value)
            if mod_root and (mod_root, node.func.attr) in _DANGEROUS_ATTR_CALLS:
                hits.add(f"import_module({mod_root!r}).{node.func.attr}")
            elif mod_root in _DANGEROUS_MODULE_ROOTS_FOR_ATTR and node.func.attr in _OS_LIKE_EXEC_NAMES:
                hits.add(f"import_module({mod_root!r}).{node.func.attr}")

        # Standalone importlib.import_module("os") / ("subprocess") — tripwire.
        mod_root = _import_module_root(node)
        if mod_root in _DANGEROUS_MODULE_ROOTS_FOR_ATTR:
            hits.add(f"import_module({mod_root!r})")

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
    hits.update(_banned_from_import_hits(tree))
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
    """Return bubblewrap argv prefix, or None if unavailable / disabled.

    Wraps the preflight *compile* child only — not in-process ``register_tools``.
    """
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
            "continuing with scrubbed-subprocess preflight only "
            "(preflight ≠ sandbox for register_tools)"
        )
        return None
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
    """Raise ``ValueError`` if the entrypoint fails host AST / scrubbed compile.

    Always runs a host-side ``ast.parse`` first (cheap), including alias-aware
    dangerous-call and from-import checks. When preflight is enabled, also
    compiles in a child process with secret-scrubbed env, optionally under
    bubblewrap.

    This is **not** OS isolation of ``register_tools``: a passing preflight
    still loads the plugin in-process on the host interpreter.
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
        logger.debug(
            "Plugin preflight using bubblewrap for %s (compile child only; "
            "register_tools remains in-process)",
            path,
        )

    result = safe_run_sync(cmd, timeout=timeout)
    if result.exit_code != 0:
        err = (result.stderr or result.stdout or "").strip()[:400]
        raise ValueError(
            f"Plugin subprocess preflight failed for {path.name}: {err or 'nonzero exit'}"
        )
    logger.debug("Plugin preflight ok for %s (not a sandbox)", path)
