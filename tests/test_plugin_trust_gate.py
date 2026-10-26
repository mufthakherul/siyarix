# SPDX-License-Identifier: AGPL-3.0-or-later
"""SIYARIX_TRUST_PLUGINS must gate in-process plugin execution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from siyarix.plugins.loader import PluginLoader
from siyarix.plugins.manager import PluginManager
from siyarix.plugins.models import (
    PluginManifest,
    PluginMetadata,
    PluginStatus,
    PluginType,
)


def test_manager_refuses_load_without_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is False
    assert mgr._installed_plugins["demo"].status == PluginStatus.DISABLED
    assert "SIYARIX_TRUST_PLUGINS" in (mgr._installed_plugins["demo"].error_message or "")


def test_legacy_loader_refuses_without_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")
    loader = PluginLoader(MagicMock(), MagicMock(), plugins_dir=plugins)
    with pytest.raises(PermissionError, match="SIYARIX_TRUST_PLUGINS"):
        loader._load_plugin(entry)


def test_production_requires_force_not_lab_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SX-A01: SIYARIX_TRUST_PLUGINS=1 is insufficient under production flags."""
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "1")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is False
    err = mgr._installed_plugins["demo"].error_message or ""
    assert "force" in err
    assert mgr._installed_plugins["demo"].status == PluginStatus.DISABLED


def test_production_allows_force_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "1")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(_graph=MagicMock(_nodes={})),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    # registry._graph._nodes needs to support .keys() for tool snapshot
    mgr.registry._graph._nodes = {}
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is True
    assert mgr._installed_plugins["demo"].status == PluginStatus.ACTIVE


def test_preflight_rejects_syntax_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "1")
    monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")  # host AST still runs
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "bad.py"
    entry.write_text("def broken(\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["bad"] = PluginMetadata(
        manifest=PluginManifest(name="bad", version="0.0.1", entrypoint="bad.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("bad") is False
    assert "syntax" in (mgr._installed_plugins["bad"].error_message or "").lower()


def test_preflight_blocks_ctypes_under_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "risky.py"
    entry.write_text(
        "import ctypes\n\ndef register_tools(reg):\n    pass\n",
        encoding="utf-8",
    )
    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["risky"] = PluginMetadata(
        manifest=PluginManifest(name="risky", version="0.0.1", entrypoint="risky.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("risky") is False
    assert "ctypes" in (mgr._installed_plugins["risky"].error_message or "")


def test_preflight_blocks_os_system_attr_under_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "ossys.py"
    entry.write_text(
        "import os\n\ndef register_tools(reg):\n    os.system('id')\n",
        encoding="utf-8",
    )
    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["ossys"] = PluginMetadata(
        manifest=PluginManifest(name="ossys", version="0.0.1", entrypoint="ossys.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("ossys") is False
    assert "os.system" in (mgr._installed_plugins["ossys"].error_message or "")


def test_preflight_blocks_eval_and_subprocess_under_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()

    for name, src, needle in (
        (
            "evaly",
            "def register_tools(reg):\n    eval('1')\n",
            "eval",
        ),
        (
            "subpy",
            "import subprocess\n\ndef register_tools(reg):\n    pass\n",
            "subprocess",
        ),
    ):
        entry = plugins / f"{name}.py"
        entry.write_text(src, encoding="utf-8")
        mgr = PluginManager(
            registry=MagicMock(),
            provider_manager=MagicMock(),
            plugins_dir=plugins,
            config_dir=tmp_path,
        )
        mgr._installed_plugins[name] = PluginMetadata(
            manifest=PluginManifest(name=name, version="0.0.1", entrypoint=f"{name}.py"),
            path=entry,
            plugin_type=PluginType.SINGLE_FILE,
            status=PluginStatus.ACTIVE,
        )
        mgr._config_data = {"disabled": []}
        assert mgr.load_plugin(name) is False, name
        assert needle in (mgr._installed_plugins[name].error_message or ""), name


def test_os_isolate_force_requires_bwrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from siyarix.plugins import isolation as iso

    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "force")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "1")
    monkeypatch.setattr(iso.shutil, "which", lambda _name: None)
    entry = tmp_path / "ok.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bubblewrap"):
        iso.preflight_plugin_entrypoint(entry)


def _production_preflight_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")


def test_preflight_blocks_import_alias_os_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: ``import os as o; o.system(...)`` must not bypass attr detection."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "alias_os.py"
    entry.write_text(
        "import os as o\n\ndef register_tools(reg):\n    o.system('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"os\.system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_from_import_os_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: ``from os import system; system(...)`` must be detected."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "from_os_system.py"
    entry.write_text(
        "from os import system\n\ndef register_tools(reg):\n    system('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"(os\.system|from os import system)"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_from_import_os_system_as_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: ``from os import system as s; s(...)`` must be detected."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "from_os_as.py"
    entry.write_text(
        "from os import system as s\n\ndef register_tools(reg):\n    s('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"(os\.system|from os import system)"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_from_import_alias_call_via_ast_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SEC-02: call-path resolves ``from os import system as s; s(...)`` even alone."""
    import ast

    from siyarix.plugins import isolation as iso

    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")
    src = "from os import system as s\ns('id')\n"
    tree = ast.parse(src)
    # Bypass import-ban path: exercise call checker with from-import binding only.
    with pytest.raises(ValueError, match=r"os\.system"):
        iso._check_dangerous_calls(tree, Path("alias_call.py"))


def test_preflight_blocks_dangerous_from_import_without_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: banned from-imports fail closed even if the name is unused."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "from_only.py"
    entry.write_text(
        "from os import popen\n\ndef register_tools(reg):\n    pass\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"from os import popen"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_from_builtins_eval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: ``from builtins import eval`` is banned under production."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "from_builtins.py"
    entry.write_text(
        "from builtins import eval\n\ndef register_tools(reg):\n    eval('1')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"(eval|from builtins import eval)"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_subprocess_import_alias_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-02: ``import subprocess as sp; sp.run(...)`` resolves via alias map."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "alias_sp.py"
    entry.write_text(
        "import subprocess as sp\n\ndef register_tools(reg):\n    sp.run(['id'])\n",
        encoding="utf-8",
    )
    # Whole-module ``subprocess`` import is already banned; alias path must still
    # surface as subprocess (import root and/or resolved attr call).
    with pytest.raises(ValueError, match=r"subprocess"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_getattr_os_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``getattr(os, \"system\")(\"id\")`` must fail closed."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "getattr_os.py"
    entry.write_text(
        "import os\n\ndef register_tools(reg):\n    getattr(os, 'system')('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"getattr|system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_importlib_import_module_os_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``importlib.import_module(\"os\").system(...)`` must fail closed."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "importlib_os.py"
    entry.write_text(
        "import importlib\n\n"
        "def register_tools(reg):\n"
        "    importlib.import_module('os').system('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"import_module|system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_assignment_alias_os_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``o = os; o.system(...)`` assignment pivot must fail closed."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "assign_os.py"
    entry.write_text(
        "import os\n\ndef register_tools(reg):\n    o = os\n    o.system('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"os\.system|system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_posix_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``import posix; posix.system(...)`` must fail closed."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "posix_sys.py"
    entry.write_text(
        "import posix\n\ndef register_tools(reg):\n    posix.system('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"posix\.system|system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_bound_os_system_attr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``syscall = os.system; syscall('id')`` must fail closed."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "bound_sys.py"
    entry.write_text(
        "import os\n\ndef register_tools(reg):\n    syscall = os.system\n    syscall('id')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"os\.system|system"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_blocks_os_execvp_attr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Residual: ``os.execvp`` must match from-import ban set."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "execvp.py"
    entry.write_text(
        "import os\n\ndef register_tools(reg):\n    os.execvp('id', ['id'])\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"execvp"):
        iso.preflight_plugin_entrypoint(entry)


def test_preflight_allows_benign_trusted_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legitimate trusted plugins must still pass host AST under production."""
    from siyarix.plugins import isolation as iso

    _production_preflight_env(monkeypatch)
    entry = tmp_path / "benign.py"
    entry.write_text(
        "from __future__ import annotations\n\n"
        "def register_tools(reg):\n"
        "    return None\n",
        encoding="utf-8",
    )
    iso.preflight_plugin_entrypoint(entry)  # must not raise


def test_plugin_manager_singleton_lock_exists() -> None:
    assert hasattr(PluginManager, "_instance_lock")
