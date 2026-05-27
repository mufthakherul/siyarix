"""Intelligent caching system — tool output, AI plans, DNS lookups, WHOIS data.

Provides TTL-based caching with LRU eviction, size tracking,
and persistent storage to disk. Reduces redundant operations
and speeds up repeated scans.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".siyarix" / "cache"

F = TypeVar("F", bound=Callable[..., Any])

CACHE_DOMAINS = {
    "tool_output": {"ttl": 3600, "max_entries": 500},
    "ai_plan": {"ttl": 7200, "max_entries": 200},
    "whois": {"ttl": 86400, "max_entries": 1000},
    "dns": {"ttl": 300, "max_entries": 2000},
    "nmap": {"ttl": 3600, "max_entries": 500},
    "httpx": {"ttl": 1800, "max_entries": 500},
}


@dataclass
class CacheEntry:
    key: str = ""
    data: str = ""
    domain: str = ""
    created_at: float = 0.0
    ttl: float = 3600.0
    size_bytes: int = 0
    hit_count: int = 0

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.created_at > self.ttl

    @property
    def age_seconds(self) -> float:
        return time.monotonic() - self.created_at


class CacheManager:
    """Domain-aware LRU cache with TTL expiration and disk persistence."""

    def __init__(self) -> None:
        self._dir = CACHE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, CacheEntry] = {}
        self._hit_count: int = 0
        self._miss_count: int = 0
        self._load()

    def _load(self) -> None:
        idx = self._dir / "index.json"
        if idx.exists():
            try:
                entries = json.loads(idx.read_text(encoding="utf-8"))
                for key, data in entries.items():
                    self._entries[key] = CacheEntry(**data)
            except Exception as exc:
                logger.debug("Cache index load failed: %s", exc)

    def _save_index(self) -> None:
        try:
            entries = {key: {
                "key": e.key, "domain": e.domain,
                "created_at": e.created_at, "ttl": e.ttl,
                "size_bytes": e.size_bytes, "hit_count": e.hit_count,
            } for key, e in self._entries.items()}
            (self._dir / "index.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.debug("Cache index save failed: %s", exc)

    def _domain_config(self, domain: str) -> dict[str, Any]:
        return CACHE_DOMAINS.get(domain, {"ttl": 600, "max_entries": 200})

    def _data_path(self, key: str) -> Path:
        safe = key.replace("/", "_").replace("\\", "_").replace(":", "_")
        return self._dir / f"{safe[:200]}.cache"

    def get(self, key: str, domain: str = "tool_output") -> str | None:
        entry = self._entries.get(key)
        if entry is None or entry.expired:
            self._miss_count += 1
            if entry and entry.expired:
                self._evict(key)
            return None

        entry.hit_count += 1
        self._hit_count += 1
        try:
            return self._data_path(key).read_text(encoding="utf-8")
        except Exception:
            self._miss_count += 1
            return None

    def set(self, key: str, data: str, domain: str = "tool_output") -> None:
        config = self._domain_config(domain)
        now = time.monotonic()
        entry = CacheEntry(
            key=key, data=data[:100], domain=domain,
            created_at=now, ttl=config["ttl"],
            size_bytes=len(data.encode("utf-8")),
        )

        # Enforce max entries — evict oldest/LRU
        domain_entries = {k: v for k, v in self._entries.items() if v.domain == domain}
        if len(domain_entries) >= config["max_entries"]:
            oldest = min(domain_entries.keys(), key=lambda k: domain_entries[k].hit_count)
            self._evict(oldest)

        self._entries[key] = entry
        try:
            self._data_path(key).write_text(data, encoding="utf-8")
        except Exception as exc:
            logger.debug("Cache write failed for %s: %s", key, exc)
        self._save_index()

    def _evict(self, key: str) -> None:
        self._entries.pop(key, None)
        try:
            self._data_path(key).unlink()
        except Exception as exc:
            logger.warning("Failed to delete cache key %s: %s", key, exc)

    def get_or_compute(self, key: str, domain: str, compute_fn: Callable[[], str]) -> str:
        cached = self.get(key, domain)
        if cached is not None:
            return cached
        result = compute_fn()
        self.set(key, result, domain)
        return result

    def invalidate(self, domain: str = "") -> int:
        if not domain:
            count = len(self._entries)
            self._entries.clear()
            for f in self._dir.glob("*.cache"):
                try:
                    f.unlink()
                except Exception as exc:
                    logger.warning("Failed to evict %s: %s", f.name, exc)
            self._save_index()
            return count
        keys = [k for k, v in self._entries.items() if v.domain == domain]
        for k in keys:
            self._evict(k)
        self._save_index()
        return len(keys)

    def stats(self, domain: str = "") -> dict[str, Any]:
        if domain:
            entries: list[CacheEntry] = [e for e in self._entries.values() if e.domain == domain]
        else:
            entries = list(self._entries.values())

        if not entries:
            return {"total_entries": 0, "total_size_bytes": 0, "hit_rate": 0.0}

        total_size = sum(e.size_bytes for e in entries)
        total_requests = self._hit_count + self._miss_count
        hit_rate = self._hit_count / total_requests if total_requests > 0 else 0.0

        return {
            "total_entries": len(entries),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "domains": list(set(e.domain for e in entries)),
            "hit_count": self._hit_count,
            "miss_count": self._miss_count,
            "hit_rate": round(hit_rate, 3),
            "oldest_entry_age_s": round(min(e.age_seconds for e in entries), 1) if entries else 0,
        }

    def clear(self) -> int:
        return self.invalidate()


cache_manager = CacheManager()


def cached(domain: str = "tool_output") -> Callable[[F], F]:
    """Decorator: caches function return value by (func_name, args, kwargs)."""
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            return cache_manager.get_or_compute(key, domain, lambda: str(func(*args, **kwargs)))
        return wrapper  # type: ignore
    return decorator


__all__ = ["CacheManager", "CacheEntry", "cache_manager", "cached", "CACHE_DOMAINS"]
