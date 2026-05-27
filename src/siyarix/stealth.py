"""Stealth and evasion module.

Implements operational security measures for covert scanning operations
as described in Chapter 20.1. Provides randomized User-Agent rotation,
request jitter, distributed routing, and decoy traffic generation.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


EVASION_LEVELS = {
    "none": {
        "jitter_pct": 0,
        "user_agent_rotate": False,
        "proxy_chain": False,
        "decoy_traffic": False,
    },
    "light": {
        "jitter_pct": 10,
        "user_agent_rotate": True,
        "proxy_chain": False,
        "decoy_traffic": False,
    },
    "medium": {
        "jitter_pct": 30,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": False,
    },
    "heavy": {
        "jitter_pct": 50,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": True,
    },
    "paranoid": {
        "jitter_pct": 80,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": True,
    },
}


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.4.0",
    "Wget/1.21.4",
]


PROXY_CHAINS = [
    "socks5://127.0.0.1:9050",
    "http://127.0.0.1:8118",
    "socks4://127.0.0.1:9050",
    "http://127.0.0.1:3128",
]

DECOY_PAYLOADS = [
    {"path": "/wp-login.php", "method": "POST", "data": "log=admin&pwd=admin123"},
    {"path": "/.env", "method": "GET"},
    {"path": "/admin/", "method": "GET"},
    {"path": "/api/v1/users", "method": "GET"},
    {"path": "/phpinfo.php", "method": "GET"},
]


@dataclass
class StealthConfig:
    """Configuration for stealth/evasion mode."""

    enabled: bool = False
    evasion_level: str = "none"
    jitter_percentage: int = 0
    rotate_user_agents: bool = False
    use_proxy_chain: bool = False
    use_decoy_traffic: bool = False
    proxy_list: list[str] = field(default_factory=lambda: list(PROXY_CHAINS))
    user_agents: list[str] = field(default_factory=lambda: list(USER_AGENTS))
    decoy_payloads: list[dict[str, Any]] = field(
        default_factory=lambda: list(DECOY_PAYLOADS)
    )
    max_concurrent_decoy_requests: int = 2
    proxy_rotation_interval: int = 60  # seconds

    def apply_level(self, level: str) -> None:
        config = EVASION_LEVELS.get(level, EVASION_LEVELS["none"])
        self.evasion_level = level
        self.jitter_percentage = config["jitter_pct"]
        self.rotate_user_agents = bool(config["user_agent_rotate"])
        self.use_proxy_chain = bool(config["proxy_chain"])
        self.use_decoy_traffic = bool(config["decoy_traffic"])
        self.enabled = level != "none"

    def score(self) -> float:
        """Calculate a stealth effectiveness score (0-10)."""
        score = 0.0
        if self.jitter_percentage >= 30:
            score += 3.0
        elif self.jitter_percentage >= 10:
            score += 1.5
        if self.rotate_user_agents:
            score += 2.0
        if self.use_proxy_chain:
            score += 2.5
        if self.use_decoy_traffic:
            score += 1.5
        if self.evasion_level == "paranoid":
            score = min(score + 1.0, 10.0)
        return round(score, 1)


class StealthEngine:
    """Stealth and evasion engine for covert operations."""

    def __init__(self, config: StealthConfig | None = None) -> None:
        self._config = config or StealthConfig()
        self._proxy_index = 0
        self._last_proxy_rotation: float = 0.0

    @property
    def config(self) -> StealthConfig:
        return self._config

    def enable(self, level: str = "medium") -> None:
        self._config.apply_level(level)
        logger.info(
            "Stealth mode enabled: %s (score: %.1f/10)", level, self._config.score()
        )

    def disable(self) -> None:
        self._config.apply_level("none")
        logger.info("Stealth mode disabled")

    def get_current_user_agent(self) -> str:
        if not self._config.rotate_user_agents:
            return USER_AGENTS[0]
        return random.choice(self._config.user_agents)

    def get_randomized_delay(self, base_ms: float) -> float:
        if self._config.jitter_percentage <= 0:
            return base_ms
        jitter_range = base_ms * (self._config.jitter_percentage / 100.0)
        return base_ms + random.uniform(-jitter_range, jitter_range)

    def get_current_proxy(self) -> str | None:
        if not self._config.use_proxy_chain:
            return None
        self._rotate_proxy_if_needed()
        if not self._config.proxy_list:
            return None
        self._proxy_index = (self._proxy_index + 1) % len(self._config.proxy_list)
        return self._config.proxy_list[self._proxy_index]

    def _rotate_proxy_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_proxy_rotation > self._config.proxy_rotation_interval:
            random.shuffle(self._config.proxy_list)
            self._last_proxy_rotation = now
            self._proxy_index = 0

    def get_decoy_requests(self, target: str) -> list[dict[str, Any]]:
        if not self._config.use_decoy_traffic:
            return []
        count = min(
            self._config.max_concurrent_decoy_requests, len(self._config.decoy_payloads)
        )
        selected = random.sample(self._config.decoy_payloads, count)
        return [
            {
                "url": f"{target.rstrip('/')}{p['path']}",
                "method": p.get("method", "GET"),
                "data": p.get("data", ""),
                "user_agent": self.get_current_user_agent(),
            }
            for p in selected
        ]

    def get_config(self) -> StealthConfig:
        return self._config

    def set_config(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
        self._config.enabled = self._config.evasion_level != "none"

    def set_level(self, level: str) -> None:
        self._config.apply_level(level)

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": self._config.enabled,
            "level": self._config.evasion_level,
            "stealth_score": self._config.score(),
            "jitter_pct": self._config.jitter_percentage,
            "rotate_ua": self._config.rotate_user_agents,
            "proxy_chain": self._config.use_proxy_chain,
            "decoy_traffic": self._config.use_decoy_traffic,
            "proxy_count": (
                len(self._config.proxy_list) if self._config.use_proxy_chain else 0
            ),
            "user_agents_pool": (
                len(self._config.user_agents) if self._config.rotate_user_agents else 0
            ),
        }


__all__ = ["StealthEngine", "StealthConfig", "EVASION_LEVELS"]
