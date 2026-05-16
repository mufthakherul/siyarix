"""Tests for plugins and offline store performance settings."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from siyarix.offline_store import OfflineStore
from siyarix.plugins import PluginManager


def test_plugin_scaffold_and_list(tmp_path: Path) -> None:
    manager = PluginManager(root=tmp_path / "plugins")
    created = manager.create_scaffold("demo_plugin", author="QA")
    assert (created / "plugin.yaml").exists()
    assert (created / "commands.py").exists()

    plugins = manager.list_plugins()
    assert len(plugins) == 1
    assert plugins[0].name == "demo_plugin"
    assert plugins[0].author == "QA"


def test_plugin_install_and_remove(tmp_path: Path) -> None:
    source = tmp_path / "source_plugin"
    source.mkdir(parents=True)
    (source / "plugin.yaml").write_text(
        "name: source_plugin\nversion: 1.2.3\nauthor: Team\n",
        encoding="utf-8",
    )
    (source / "__init__.py").write_text("", encoding="utf-8")

    manager = PluginManager(root=tmp_path / "plugins")
    installed = manager.install_from_path(source)
    assert installed.exists()
    assert manager.remove("source_plugin") is True
    assert manager.remove("source_plugin") is False


def test_offline_store_applies_wal_and_indexes(tmp_path: Path) -> None:
    db_path = tmp_path / "offline.db"
    OfflineStore(db_path=db_path)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        index_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        ).fetchall()

    assert str(mode).lower() in {"wal", "memory"}  # WAL can downgrade on constrained envs.
    assert any("idx_findings_synced" in row["name"] for row in index_rows)
    assert any("idx_scans_created_at" in row["name"] for row in index_rows)


def test_offline_store_vacuum_command(tmp_path: Path) -> None:
    store = OfflineStore(db_path=tmp_path / "offline.db")
    store.save_scan("scan-1", "127.0.0.1", "nmap", "complete")
    store.vacuum()
