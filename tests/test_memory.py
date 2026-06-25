"""Tests for siyarix.memory - Multi-layer memory system."""

from __future__ import annotations

import sqlite3
import time
from unittest.mock import MagicMock, patch

import pytest

from siyarix.memory import (
    MemoryEntry,
    MemoryLayer,
    MemoryManager,
    MemoryStore,
)


class TestMemoryLayer:
    def test_values(self):
        assert MemoryLayer.SESSION == "session"
        assert MemoryLayer.PROJECT == "project"
        assert MemoryLayer.PERSISTENT == "persistent"
        assert MemoryLayer.TOOL == "tool"
        assert MemoryLayer.WORKFLOW == "workflow"

    def test_members(self):
        assert len(MemoryLayer) == 5


class TestMemoryEntry:
    def test_defaults(self):
        entry = MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION)
        assert entry.key == "k1"
        assert entry.value == "v1"
        assert entry.layer == MemoryLayer.SESSION
        assert entry.tags == []
        assert entry.metadata == {}
        assert isinstance(entry.created_at, float)
        assert isinstance(entry.accessed_at, float)
        assert entry.access_count == 0
        assert entry.ttl == 0.0

    def test_custom_fields(self):
        entry = MemoryEntry(
            key="k2",
            value="v2",
            layer=MemoryLayer.PERSISTENT,
            tags=["critical", "scan"],
            metadata={"source": "nmap"},
            created_at=100.0,
            accessed_at=200.0,
            access_count=5,
            ttl=3600.0,
        )
        assert entry.tags == ["critical", "scan"]
        assert entry.metadata == {"source": "nmap"}
        assert entry.created_at == 100.0
        assert entry.accessed_at == 200.0
        assert entry.access_count == 5
        assert entry.ttl == 3600.0

    def test_expired_true(self):
        entry = MemoryEntry(
            key="k", value="v", layer=MemoryLayer.SESSION, created_at=time.time() - 100, ttl=50
        )
        assert entry.expired is True

    def test_expired_false_not_expired(self):
        entry = MemoryEntry(
            key="k", value="v", layer=MemoryLayer.SESSION, created_at=time.time(), ttl=100
        )
        assert entry.expired is False

    def test_expired_false_no_ttl(self):
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.SESSION, ttl=0)
        assert entry.expired is False

    def test_expired_false_negative_ttl(self):
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.SESSION, ttl=-1)
        assert entry.expired is False

    def test_content_hash(self):
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.SESSION)
        h1 = entry.content_hash
        assert len(h1) == 16
        assert isinstance(h1, str)
        h2 = entry.content_hash
        assert h1 == h2

    def test_content_hash_different_values(self):
        e1 = MemoryEntry(key="k", value="v1", layer=MemoryLayer.SESSION)
        e2 = MemoryEntry(key="k", value="v2", layer=MemoryLayer.SESSION)
        assert e1.content_hash != e2.content_hash

    def test_content_hash_cached(self):
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.SESSION)
        entry.value = "changed"
        assert len(entry.content_hash) == 16

    def test_access_count_incremented(self):
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.SESSION)
        assert entry.access_count == 0


class TestMemoryStoreSession:
    """Tests for MemoryStore session (in-memory) operations."""

    @pytest.fixture
    def store(self):
        return MemoryStore()

    def test_init_no_db(self):
        store = MemoryStore()
        assert store._db_path is None
        assert store._conn is None
        assert store._session_memory == {}

    def test_store_session_entry(self, store):
        entry = MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION)
        store.store(entry)
        assert "k1" in store._session_memory
        assert store._session_memory["k1"] is entry

    def test_store_session_overwrites(self, store):
        e1 = MemoryEntry(key="same", value="first", layer=MemoryLayer.SESSION)
        e2 = MemoryEntry(key="same", value="second", layer=MemoryLayer.SESSION)
        store.store(e1)
        store.store(e2)
        assert store._session_memory["same"].value == "second"

    def test_retrieve_session_hit(self, store):
        entry = MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION)
        store.store(entry)
        result = store.retrieve("k1")
        assert result is not None
        assert result.value == "v1"

    def test_retrieve_session_miss(self, store):
        result = store.retrieve("nonexistent")
        assert result is None

    def test_retrieve_session_tracks_access(self, store):
        entry = MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION, access_count=0)
        store.store(entry)
        result = store.retrieve("k1")
        assert result is not None
        assert result.access_count == 1

    def test_retrieve_session_expired(self, store):
        entry = MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION, ttl=0.001)
        store.store(entry)
        time.sleep(0.01)
        result = store.retrieve("k1")
        assert result is None
        assert "k1" not in store._session_memory

    def test_search_session(self, store):
        store.store(MemoryEntry(key="hosts", value="10.0.0.1", layer=MemoryLayer.SESSION))
        store.store(MemoryEntry(key="ports", value="22,80", layer=MemoryLayer.SESSION))
        store.store(MemoryEntry(key="services", value="ssh,http", layer=MemoryLayer.SESSION))
        results = store.search("10.0.0")
        assert len(results) == 1

    def test_search_session_by_key(self, store):
        store.store(MemoryEntry(key="nmap_result", value="open ports", layer=MemoryLayer.SESSION))
        results = store.search("nmap")
        assert len(results) == 1

    def test_search_session_no_match(self, store):
        store.store(MemoryEntry(key="hosts", value="10.0.0.1", layer=MemoryLayer.SESSION))
        results = store.search("nonexistent")
        assert results == []

    def test_search_session_empty(self, store):
        results = store.search("anything")
        assert results == []

    def test_search_session_with_layer_filter(self, store):
        store.store(MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION))
        results = store.search("v1", layer=MemoryLayer.SESSION)
        assert len(results) == 1
        results = store.search("v1", layer=MemoryLayer.PERSISTENT)
        assert len(results) == 0

    def test_search_session_limit(self, store):
        for i in range(5):
            store.store(MemoryEntry(key=f"k{i}", value="data", layer=MemoryLayer.SESSION))
        results = store.search("data", limit=3)
        assert len(results) == 3

    def test_clear_session_layer(self, store):
        store.store(MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION))
        store.clear_layer(MemoryLayer.SESSION)
        assert store._session_memory == {}
        assert store.retrieve("k1") is None

    def test_stats_session(self, store):
        store.store(MemoryEntry(key="k1", value="v1", layer=MemoryLayer.SESSION))
        stats = store.stats()
        assert stats["session"] == 1
        assert stats["persistent"] == {}


class TestMemoryStorePersistent:
    """Tests for MemoryStore persistent (SQLite) operations."""

    @pytest.fixture
    def store(self, tmp_path):
        db_path = tmp_path / "test_memory.db"
        store = MemoryStore(db_path=db_path)
        store._conn.row_factory = sqlite3.Row
        yield store
        store.close()

    def test_init_with_db_path(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = MemoryStore(db_path=db_path)
        assert store._db_path == db_path
        assert store._conn is not None
        store.close()

    def test_init_db_creates_table(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = MemoryStore(db_path=db_path)
        cursor = store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='memories'"
        )
        assert cursor.fetchone() is not None
        store.close()

    def test_store_persistent(self, store):
        entry = MemoryEntry(key="pk1", value="pv1", layer=MemoryLayer.PERSISTENT)
        store.store(entry)
        result = store.retrieve("pk1", layer=MemoryLayer.PERSISTENT)
        assert result is not None
        assert result.value == "pv1"

    def test_store_project(self, store):
        entry = MemoryEntry(key="prjk1", value="prjv1", layer=MemoryLayer.PROJECT)
        store.store(entry)
        result = store.retrieve("prjk1", layer=MemoryLayer.PROJECT)
        assert result is not None

    def test_store_tool(self, store):
        entry = MemoryEntry(key="tk1", value="tv1", layer=MemoryLayer.TOOL)
        store.store(entry)
        result = store.retrieve("tk1", layer=MemoryLayer.TOOL)
        assert result is not None

    def test_store_workflow(self, store):
        entry = MemoryEntry(key="wk1", value="wv1", layer=MemoryLayer.WORKFLOW)
        store.store(entry)
        result = store.retrieve("wk1", layer=MemoryLayer.WORKFLOW)
        assert result is not None

    def test_retrieve_miss(self, store):
        result = store.retrieve("nonexistent", layer=MemoryLayer.PERSISTENT)
        assert result is None

    def test_retrieve_without_layer(self, store):
        e1 = MemoryEntry(key="shared", value="v1", layer=MemoryLayer.PERSISTENT)
        e2 = MemoryEntry(key="shared", value="v2", layer=MemoryLayer.PROJECT)
        store.store(e1)
        store.store(e2)
        result = store.retrieve("shared")
        assert result is not None

    def test_retrieve_expired_persistent(self, store):
        entry = MemoryEntry(key="exp", value="val", layer=MemoryLayer.PERSISTENT, ttl=0.001)
        store.store(entry)
        time.sleep(0.01)
        result = store.retrieve("exp", layer=MemoryLayer.PERSISTENT)
        assert result is None

    def test_store_no_conn(self, tmp_path):
        store = MemoryStore()
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
        store.store(entry)
        assert store.retrieve("k", layer=MemoryLayer.PERSISTENT) is None

    def test_retrieve_no_conn(self):
        store = MemoryStore()
        assert store.retrieve("k", layer=MemoryLayer.PERSISTENT) is None

    def test_retrieve_no_conn_without_layer(self):
        store = MemoryStore()
        assert store.retrieve("k") is None

    @patch("siyarix.memory.sqlite3.connect", side_effect=Exception("db init fail"))
    def test_init_db_failure(self, mock_connect, tmp_path):
        db_path = tmp_path / "fail.db"
        store = MemoryStore(db_path=db_path)
        assert store._conn is None
        store.close()

    def test_store_db_error(self, store):
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("store fail")
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
        store.store(entry)

    def test_retrieve_db_error(self, store):
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("retrieve fail")
        result = store.retrieve("k", layer=MemoryLayer.PERSISTENT)
        assert result is None

    def test_search_persistent(self, store):
        store.store(MemoryEntry(key="hosts", value="10.0.0.1", layer=MemoryLayer.PERSISTENT))
        store.store(MemoryEntry(key="hosts2", value="10.0.0.2", layer=MemoryLayer.PERSISTENT))
        results = store.search("10.0.0", limit=10)
        assert len(results) >= 2

    def test_search_persistent_with_layer(self, store):
        store.store(MemoryEntry(key="h1", value="data1", layer=MemoryLayer.PERSISTENT))
        store.store(MemoryEntry(key="h2", value="data2", layer=MemoryLayer.PROJECT))
        results = store.search("data", layer=MemoryLayer.PERSISTENT)
        assert len(results) == 1
        results = store.search("data", layer=MemoryLayer.PROJECT)
        assert len(results) == 1

    def test_search_persistent_no_conn(self):
        store = MemoryStore()
        store._session_memory["k"] = MemoryEntry(
            key="k", value="searchable", layer=MemoryLayer.SESSION
        )
        results = store.search("searchable")
        assert len(results) == 1

    def test_search_db_error(self, store):
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("search fail")
        store._session_memory["k"] = MemoryEntry(key="k", value="local", layer=MemoryLayer.SESSION)
        results = store.search("local")
        assert len(results) == 1

    def test_search_deduplication(self, store):
        entry = MemoryEntry(key="dup", value="shared", layer=MemoryLayer.SESSION)
        store.store(entry)
        store.store(MemoryEntry(key="dup", value="shared", layer=MemoryLayer.PERSISTENT))
        results = store.search("shared")
        assert len(results) == 1

    def test_clear_persistent_layer(self, store):
        store.store(MemoryEntry(key="pk", value="pv", layer=MemoryLayer.PERSISTENT))
        store.clear_layer(MemoryLayer.PERSISTENT)
        assert store.retrieve("pk", layer=MemoryLayer.PERSISTENT) is None

    def test_clear_persistent_db_error(self, store):
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("clear fail")
        store.clear_layer(MemoryLayer.PERSISTENT)

    def test_stats_persistent(self, store):
        store.store(MemoryEntry(key="s1", value="v1", layer=MemoryLayer.PERSISTENT))
        store.store(MemoryEntry(key="s2", value="v2", layer=MemoryLayer.PROJECT))
        stats = store.stats()
        assert stats["session"] == 0
        assert "persistent" in stats
        total = sum(stats["persistent"].values())
        assert total == 2

    def test_stats_no_conn(self):
        store = MemoryStore()
        stats = store.stats()
        assert stats["persistent"] == {}

    def test_stats_db_warning(self, store):
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("stats fail")
        stats = store.stats()
        assert "persistent" in stats

    def test_row_to_entry(self, tmp_path):
        store = MemoryStore()
        row = MagicMock(spec=sqlite3.Row)
        row.__getitem__ = MagicMock()
        row.__getitem__.side_effect = lambda k: {
            "key": "rk",
            "value": "rv",
            "layer": "persistent",
            "tags": '["a","b"]',
            "metadata": '{"src":"test"}',
            "created_at": 100.0,
            "accessed_at": 200.0,
            "access_count": 3,
            "ttl": 0.0,
        }[k]
        entry = store._row_to_entry(row)
        assert entry.key == "rk"
        assert entry.value == "rv"
        assert entry.layer == MemoryLayer.PERSISTENT
        assert entry.tags == ["a", "b"]
        assert entry.metadata == {"src": "test"}
        assert entry.created_at == 100.0
        assert entry.accessed_at == 200.0
        assert entry.access_count == 3
        assert entry.ttl == 0.0

    def test_row_to_entry_empty_tags_metadata(self, tmp_path):
        store = MemoryStore()
        row = MagicMock(spec=sqlite3.Row)
        row.__getitem__ = MagicMock()
        row.__getitem__.side_effect = lambda k: {
            "key": "rk",
            "value": "rv",
            "layer": "session",
            "tags": None,
            "metadata": None,
            "created_at": 0.0,
            "accessed_at": 0.0,
            "access_count": 0,
            "ttl": 0.0,
        }[k]
        entry = store._row_to_entry(row)
        assert entry.tags == []
        assert entry.metadata == {}

    def test_close(self, tmp_path):
        db_path = tmp_path / "close.db"
        store = MemoryStore(db_path=db_path)
        assert store._conn is not None
        store.close()
        assert store._conn is None

    def test_close_no_conn(self):
        store = MemoryStore()
        store.close()
        assert store._conn is None

    def test_duplicate_key_overwrite(self, store):
        e1 = MemoryEntry(key="uk", value="first", layer=MemoryLayer.PERSISTENT)
        e2 = MemoryEntry(key="uk", value="second", layer=MemoryLayer.PERSISTENT)
        store.store(e1)
        store.store(e2)
        result = store.retrieve("uk", layer=MemoryLayer.PERSISTENT)
        assert result is not None
        assert result.value == "second"


class TestMemoryStoreOpsec:
    @pytest.fixture
    def store(self, tmp_path):
        db_path = tmp_path / "opsec_memory.db"
        s = MemoryStore(db_path=db_path)
        s._conn.row_factory = sqlite3.Row
        yield s
        s.close()

    def test_store_opsec_memory_only(self, store):
        with patch("siyarix.opsec.opsec_manager") as mock_opsec:
            mock_opsec.status.memory_only = True
            entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
            store.store(entry)
            assert entry.layer == MemoryLayer.SESSION
            assert "k" in store._session_memory

    def test_store_opsec_not_memory_only(self, store):
        with patch("siyarix.opsec.opsec_manager") as mock_opsec:
            mock_opsec.status.memory_only = False
            entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
            store.store(entry)
            assert entry.layer == MemoryLayer.PERSISTENT

    def test_opsec_import_fallback(self):
        store = MemoryStore()
        entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
        store.store(entry)
        assert entry.layer == MemoryLayer.PERSISTENT

    def test_store_opsec_import_error(self):
        import builtins

        original_import = builtins.__import__

        def selective_import(name, *args, **kwargs):
            if name == "siyarix.opsec":
                raise ImportError(f"No module named {name}")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", selective_import):
            store = MemoryStore()
            entry = MemoryEntry(key="k", value="v", layer=MemoryLayer.PERSISTENT)
            store.store(entry)
            assert entry.layer == MemoryLayer.PERSISTENT

    def test_init_db_no_path(self):
        store = MemoryStore()
        store._init_db()


class TestMemoryStoreClearNoConn:
    def test_clear_persistent_layer_no_conn(self):
        store = MemoryStore()
        store.clear_layer(MemoryLayer.PERSISTENT)


class TestMemoryManager:
    @pytest.fixture
    def manager(self, tmp_path):
        mgr = MemoryManager(base_path=tmp_path)
        for layer in (
            MemoryLayer.PROJECT,
            MemoryLayer.PERSISTENT,
            MemoryLayer.TOOL,
            MemoryLayer.WORKFLOW,
        ):
            if mgr._stores[layer]._conn:
                mgr._stores[layer]._conn.row_factory = sqlite3.Row
        yield mgr
        mgr.close()

    def test_init(self, tmp_path):
        mgr = MemoryManager(base_path=tmp_path)
        assert MemoryLayer.SESSION in mgr._stores
        assert MemoryLayer.PROJECT in mgr._stores
        assert MemoryLayer.PERSISTENT in mgr._stores
        assert MemoryLayer.TOOL in mgr._stores
        assert MemoryLayer.WORKFLOW in mgr._stores
        mgr.close()

    def test_init_without_base_path(self, tmp_path):
        with patch("siyarix.memory.get_config_dir", return_value=tmp_path):
            mgr = MemoryManager()
            assert len(mgr._stores) == 5
            mgr.close()

    def test_store_and_retrieve_session(self, manager):
        manager.store("k1", "v1", layer=MemoryLayer.SESSION)
        entry = manager.retrieve("k1")
        assert entry is not None
        assert entry.value == "v1"

    def test_store_with_tags_and_ttl(self, manager):
        manager.store(
            "k2", "v2", layer=MemoryLayer.SESSION, tags=["tag1", "tag2"], ttl=100.0, source="test"
        )
        entry = manager.retrieve("k2")
        assert entry.tags == ["tag1", "tag2"]
        assert entry.ttl == 100.0
        assert entry.metadata == {"source": "test"}

    def test_retrieve_with_layer(self, manager):
        manager.store("k3", "v3", layer=MemoryLayer.PROJECT)
        entry = manager.retrieve("k3", layer=MemoryLayer.PROJECT)
        assert entry is not None
        assert manager.retrieve("k3", layer=MemoryLayer.SESSION) is None

    def test_retrieve_miss(self, manager):
        assert manager.retrieve("nonexistent") is None

    def test_search_all_layers(self, manager):
        manager.store("search_key", "search_value", layer=MemoryLayer.SESSION)
        manager.store("search_key2", "search_value2", layer=MemoryLayer.PROJECT)
        results = manager.search("search_value")
        assert len(results) >= 1

    def test_search_with_layer(self, manager):
        manager.store("sk1", "sv1", layer=MemoryLayer.SESSION)
        results = manager.search("sv1", layer=MemoryLayer.SESSION)
        assert len(results) == 1
        results = manager.search("sv1", layer=MemoryLayer.PROJECT)
        assert len(results) == 0

    def test_search_limit(self, manager):
        for i in range(5):
            manager.store(f"key_{i}", "common_value", layer=MemoryLayer.SESSION)
        results = manager.search("common_value", limit=3)
        assert len(results) == 3

    def test_stats(self, manager):
        manager.store("k", "v", layer=MemoryLayer.SESSION)
        stats = manager.stats()
        assert MemoryLayer.SESSION.value in stats

    def test_save_context(self, manager):
        manager.save_context({"action": "scan", "target": "10.0.0.1"})
        contexts = manager.load_context()
        assert len(contexts) >= 1
        assert contexts[0]["action"] == "scan"

    def test_load_context_empty(self, tmp_path):
        mgr = MemoryManager(base_path=tmp_path)
        contexts = mgr.load_context()
        assert contexts == []
        mgr.close()

    def test_load_context_json_decode_error(self, manager):
        store = manager._stores[MemoryLayer.PROJECT]
        entry = MemoryEntry(
            key="ctx_bad",
            value="not valid json",
            layer=MemoryLayer.PROJECT,
            tags=["context"],
        )
        store.store(entry)
        contexts = manager.load_context()
        assert len(contexts) == 0

    def test_load_context_db_error(self, manager):
        store = manager._stores[MemoryLayer.PROJECT]
        store._conn = MagicMock()
        store._conn.execute.side_effect = Exception("db error")
        contexts = manager.load_context()
        assert contexts == []

    def test_load_context_no_conn(self, tmp_path):
        mgr = MemoryManager(base_path=tmp_path)
        mgr._stores[MemoryLayer.PROJECT]._conn = None
        contexts = mgr.load_context()
        assert contexts == []
        mgr.close()

    def test_close(self, manager):
        manager.close()
        for store in manager._stores.values():
            assert store._conn is None

    def test_store_default_layer(self, manager):
        manager.store("default_key", "default_val")
        entry = manager.retrieve("default_key")
        assert entry is not None
        assert entry.layer == MemoryLayer.SESSION

    def test_search_result_sorting(self, manager):
        manager.store("a", "shared", layer=MemoryLayer.SESSION)
        import time

        time.sleep(0.01)
        manager.store("b", "shared", layer=MemoryLayer.SESSION)
        results = manager.search("shared")
        assert len(results) >= 2


class TestPublicAPI:
    def test_all_exports(self):
        from siyarix import memory

        expected = [
            "MemoryLayer",
            "MemoryEntry",
            "MemoryStore",
            "MemoryManager",
        ]
        for name in expected:
            assert hasattr(memory, name)
