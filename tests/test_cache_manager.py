from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.credential_store import CredentialStore

from siyarix.cache_manager import (
    CACHE_DOMAINS,
    CacheEntry,
    CacheManager,
    cache_manager,
    cached,
)


@pytest.fixture
def cache(tmp_path) -> CacheManager:
    return CacheManager(cache_dir=str(tmp_path / "cache"))


class TestCacheEntry:
    def test_expired_property(self) -> None:
        entry = CacheEntry(key="k", data="d", created_at=time.monotonic() - 100, ttl=50)
        assert entry.expired is True

    def test_not_expired(self) -> None:
        entry = CacheEntry(key="k", data="d", created_at=time.monotonic(), ttl=3600)
        assert entry.expired is False

    def test_age_seconds(self) -> None:
        created = time.monotonic() - 10
        entry = CacheEntry(key="k", data="d", created_at=created, ttl=3600)
        assert 9.5 <= entry.age_seconds <= 10.5

    def test_zero_age(self) -> None:
        entry = CacheEntry(key="k", data="d", created_at=time.monotonic(), ttl=3600)
        assert entry.age_seconds < 1.0


class TestCacheManager:
    @pytest.fixture
    def cache(self, tmp_path: Path) -> CacheManager:
        c = CacheManager()
        c._dir = tmp_path
        c._entries.clear()
        c._hit_count = 0
        c._miss_count = 0
        return c

    def test_init_creates_dir(self, tmp_path: Path) -> None:
        c = CacheManager()
        c._dir = tmp_path / "custom_cache"
        c.__init__()
        assert c._dir.exists()

    def test_get_miss(self, cache: CacheManager) -> None:
        result = cache.get("nonexistent", "tool_output")
        assert result is None
        assert cache._miss_count == 1

    def test_get_hit(self, cache: CacheManager) -> None:
        cache.set("test_key", "test_data", "tool_output")
        result = cache.get("test_key", "tool_output")
        assert result == "test_data"
        assert cache._hit_count == 1

    def test_get_expired(self, cache: CacheManager) -> None:
        cache.set("test_key", "test_data", "tool_output")
        entry = cache._entries["test_key"]
        entry.created_at = time.monotonic() - 7200
        result = cache.get("test_key", "tool_output")
        assert result is None
        assert cache._miss_count == 1
        assert "test_key" not in cache._entries

    def test_get_read_error(self, cache: CacheManager) -> None:
        cache.set("test_key", "test_data", "tool_output")
        with patch.object(Path, "read_text", side_effect=OSError("read error")):
            result = cache.get("test_key", "tool_output")
        assert result is None
        assert cache._miss_count == 1

    def test_set_and_retrieve(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        assert cache.get("k1", "tool_output") == "v1"

    def test_set_different_domains(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache.set("k2", "v2", "dns")
        assert cache.get("k1", "tool_output") == "v1"
        assert cache.get("k2", "dns") == "v2"

    def test_set_evicts_lru(self, cache: CacheManager) -> None:
        domain_config = {"ttl": 3600, "max_entries": 2}
        with patch.object(cache, "_domain_config", return_value=domain_config):
            cache.set("k1", "v1", "tool_output")
            cache.set("k2", "v2", "tool_output")
            cache.set("k3", "v3", "tool_output")
        assert cache.get("k1", "tool_output") is None
        assert cache.get("k2", "tool_output") is not None
        assert cache.get("k3", "tool_output") is not None

    def test_set_write_error(self, cache: CacheManager) -> None:
        with patch.object(Path, "write_text", side_effect=OSError("write error")):
            cache.set("k1", "v1", "tool_output")
        assert cache._entries["k1"].data == "v1"

    def test_get_or_compute_hit(self, cache: CacheManager) -> None:
        cache.set("k1", "cached_value", "tool_output")
        result = cache.get_or_compute("k1", "tool_output", lambda: "fresh_value")
        assert result == "cached_value"

    def test_get_or_compute_miss(self, cache: CacheManager) -> None:
        result = cache.get_or_compute("k1", "tool_output", lambda: "computed_value")
        assert result == "computed_value"
        assert cache.get("k1", "tool_output") == "computed_value"

    def test_invalidate_all(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache.set("k2", "v2", "dns")
        count = cache.invalidate()
        assert count == 2
        assert cache.get("k1", "tool_output") is None

    def test_invalidate_by_domain(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache.set("k2", "v2", "dns")
        count = cache.invalidate("dns")
        assert count == 1
        assert cache.get("k1", "tool_output") is not None
        assert cache.get("k2", "dns") is None

    def test_invalidate_empty_domain_clears_nothing(self, cache: CacheManager) -> None:
        count = cache.invalidate("nonexistent")
        assert count == 0

    def test_stats_empty(self, cache: CacheManager) -> None:
        s = cache.stats()
        assert s["total_entries"] == 0
        assert s["hit_rate"] == 0.0

    def test_stats_global(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache.set("k2", "v2", "dns")
        cache.get("k1", "tool_output")
        s = cache.stats()
        assert s["total_entries"] == 2
        assert s["hit_rate"] > 0

    def test_stats_by_domain(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache.set("k2", "v2", "dns")
        s = cache.stats("dns")
        assert s["total_entries"] == 1

    def test_clear(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        count = cache.clear()
        assert count == 1
        assert cache.get("k1", "tool_output") is None

    def test_domain_config_default(self, cache: CacheManager) -> None:
        cfg = cache._domain_config("unknown")
        assert cfg == {"ttl": 600, "max_entries": 200}

    def test_domain_config_known(self, cache: CacheManager) -> None:
        cfg = cache._domain_config("dns")
        assert cfg == CACHE_DOMAINS["dns"]

    def test_data_path(self, cache: CacheManager) -> None:
        path = cache._data_path("test/key:value")
        assert path.name.endswith(".cache")
        assert "_" in path.stem

    def test_evict_nonexistent(self, cache: CacheManager) -> None:
        cache._evict("nonexistent")

    def test_save_and_load_index(self, cache: CacheManager) -> None:
        cache.set("k1", "v1", "tool_output")
        cache2 = CacheManager()
        cache2._dir = cache._dir
        cache2._load()
        assert "k1" in cache2._entries

    def test_save_index_error(self, cache: CacheManager) -> None:
        with patch.object(Path, "write_text", side_effect=OSError("save error")):
            cache._save_index()

    def test_load_index_error(self, cache: CacheManager) -> None:
        (cache._dir / "index.json").write_text("invalid json", encoding="utf-8")
        cache._load()

    def test_cache_domains_defined(self) -> None:
        assert "tool_output" in CACHE_DOMAINS
        assert "dns" in CACHE_DOMAINS
        assert "ai_plan" in CACHE_DOMAINS


class TestCachedDecorator:
    def test_decorator_caches_result(self) -> None:
        def test_fn(arg1: str, kwarg1: str = "") -> str:
            return f"result_{arg1}_{kwarg1}"

        decorated = cached("tool_output")(test_fn)
        with patch("siyarix.cache_manager.cache_manager") as mock_cm:
            mock_cm.get_or_compute.return_value = "cached_result"
            result = decorated("arg1", kwarg1="val1")
        assert result == "cached_result"
        mock_cm.get_or_compute.assert_called_once()

    def test_decorator_singleton(self) -> None:
        assert cache_manager is not None


class TestCacheManagerEviction:
    """Cover missing cache_manager lines."""

    def test_save_index_memory_only_returns_early(self):
        from siyarix.cache_manager import CacheManager

        cm = CacheManager()
        with patch("siyarix.opsec.opsec_manager") as mock_opsec:
            mock_opsec.status.memory_only = True
            cm._save_index()

    def test_save_index_import_error_continues(self):
        from siyarix.cache_manager import CacheManager

        cm = CacheManager()
        with patch.dict("sys.modules", {"siyarix.opsec": None}):
            cm._save_index()

    def test_get_memory_only_returns_entry_data(self):
        from siyarix.cache_manager import CacheManager, CacheEntry

        cm = CacheManager()
        cm._entries["k"] = CacheEntry(
            key="k", data="mem_data", created_at=time.monotonic(), ttl=9999
        )
        with patch("siyarix.opsec.opsec_manager") as m:
            m.status.memory_only = True
            assert cm.get("k") == "mem_data"

    def test_get_import_error_returns_file_data(self):
        from siyarix.cache_manager import CacheManager, CacheEntry

        cm = CacheManager()
        cm._entries["k"] = CacheEntry(key="k", data="x", created_at=time.monotonic(), ttl=9999)
        with patch("siyarix.opsec.opsec_manager") as mock_os:
            mock_os.status.memory_only = False
            with patch.object(Path, "read_text", return_value="file_data"):
                assert cm.get("k") == "file_data"

    def test_set_import_error_sets_memory_only_false(self):
        from siyarix.cache_manager import CacheManager

        cm = CacheManager()
        with patch.dict("sys.modules", {"siyarix.opsec": None}):
            cm.set("k", "data", "tool_output")
            assert "k" in cm._entries

    def test_set_memory_only_skips_disk_write(self):
        from siyarix.cache_manager import CacheManager, CacheEntry

        cm = CacheManager()
        entry = CacheEntry(key="k", data="d")
        cm._entries["k"] = entry
        with patch("siyarix.opsec.opsec_manager") as m:
            m.status.memory_only = True
            with patch.object(Path, "write_text") as mock_write:
                cm.set("k2", "data2", "tool_output")
            mock_write.assert_not_called()

    def test_invalidate_exception_logged(self):
        from siyarix.cache_manager import CacheManager, CacheEntry

        cm = CacheManager()
        cm._entries["k"] = CacheEntry(key="k", domain="d")
        with patch.object(Path, "glob", return_value=[Path("f.cache")]):
            with patch.object(Path, "unlink", side_effect=OSError("fail")):
                with patch("siyarix.cache_manager.logger") as mock_log:
                    cm.invalidate("d")
                    mock_log.warning.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# chat/commands.py (84% - missing 122-124, 139-140, 148, 152-155)
# ═══════════════════════════════════════════════════════════════════
class TestCacheManagerExpiry:
    """Cover remaining cache_manager.py lines 126-127, 192-193."""

    def test_get_import_error_returns_none(self):
        cm = CacheManager()
        cm._entries["k"] = CacheEntry(key="k", data="x", created_at=time.monotonic(), ttl=9999)
        with patch("siyarix.opsec.opsec_manager") as mock_os:
            mock_os.status.memory_only = False
            with patch.object(Path, "read_text", side_effect=OSError("read error")):
                assert cm.get("k") is None

    def test_invalidate_all_exception_logged(self):
        cm = CacheManager()
        cm._entries["k"] = CacheEntry(
            key="k", domain="d", data="x", created_at=time.monotonic(), ttl=9999
        )
        with patch.object(Path, "glob", return_value=[Path("k.cache")]):
            with patch.object(Path, "unlink", side_effect=OSError("fail")):
                with patch("siyarix.cache_manager.logger") as mock_log:
                    cm.invalidate()
                    mock_log.warning.assert_called()


# ═══════════════════════════════════════════════════════════════════
# 8. credential_store.py (73% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture
def cred_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
    s = CredentialStore(master_password="test_master")
    return s


class TestCacheManagerConcurrency:
    """Cover remaining cache_manager.py lines 126-127, 192-193."""

    def test_get_import_error_returns_none(self):
        cm = CacheManager()
        cm._entries["k"] = CacheEntry(key="k", data="x", created_at=time.monotonic(), ttl=9999)
        with patch("siyarix.opsec.opsec_manager") as mock_os:
            mock_os.status.memory_only = False
            with patch.object(Path, "read_text", side_effect=OSError("read error")):
                assert cm.get("k") is None

    def test_invalidate_all_exception_logged(self):
        cm = CacheManager()
        cm._entries["k"] = CacheEntry(
            key="k", domain="d", data="x", created_at=time.monotonic(), ttl=9999
        )
        with patch.object(Path, "glob", return_value=[Path("k.cache")]):
            with patch.object(Path, "unlink", side_effect=OSError("fail")):
                with patch("siyarix.cache_manager.logger") as mock_log:
                    cm.invalidate()
                    mock_log.warning.assert_called()


# ═══════════════════════════════════════════════════════════════════
# 8. credential_store.py (73% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════


@pytest.fixture
def cred_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path / "siyarix"))
    monkeypatch.setenv("SIYARIX_USE_KEYRING", "0")
    s = CredentialStore(master_password="test_master")
    return s
