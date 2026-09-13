# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool Configuration & Customization Manager for Siyarix.

Manages user-defined tool overrides (custom binary paths, default flags,
risk levels, timeouts, enable/disable states) and completely custom tools
stored in ~/.siyarix/tools.json.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)


@dataclass
class ToolOverride:
    """Modifications applied on top of built-in or detected tools."""

    binary_path: str | None = None
    default_args: list[str] = field(default_factory=list)
    risk_level: str | None = None
    category: str | None = None
    timeout: int | None = None
    env: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolOverride:
        return cls(
            binary_path=data.get("binary_path"),
            default_args=list(data.get("default_args", [])),
            risk_level=data.get("risk_level"),
            category=data.get("category"),
            timeout=data.get("timeout"),
            env=dict(data.get("env", {})),
            enabled=data.get("enabled", True),
            description=data.get("description"),
        )


@dataclass
class CustomToolDefinition:
    """A user-defined custom tool or script."""

    name: str
    binary: str
    description: str = ""
    category: str = "utility"
    risk_level: str = "safe"
    default_args: list[str] = field(default_factory=list)
    timeout: int = 120
    env: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    version_args: list[str] = field(default_factory=lambda: ["--version"])
    version_pattern: str = r"(\d+(?:\.\d+)+)"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CustomToolDefinition:
        return cls(
            name=data["name"],
            binary=data.get("binary", data["name"]),
            description=data.get("description", ""),
            category=data.get("category", "utility"),
            risk_level=data.get("risk_level", "safe"),
            default_args=list(data.get("default_args", [])),
            timeout=data.get("timeout", 120),
            env=dict(data.get("env", {})),
            enabled=data.get("enabled", True),
            version_args=list(data.get("version_args", ["--version"])),
            version_pattern=data.get("version_pattern", r"(\d+(?:\.\d+)+)"),
        )


class ToolConfigManager:
    """Thread-safe manager for user tool modifications and custom tools."""

    _instance: Optional[ToolConfigManager] = None
    _instance_lock = threading.Lock()

    def __init__(self, config_file: Path | None = None) -> None:
        self._config_file = config_file or (get_config_dir() / "tools.json")
        self._lock = threading.RLock()
        self._overrides: dict[str, ToolOverride] = {}
        self._custom_tools: dict[str, CustomToolDefinition] = {}
        self.load()

    @classmethod
    def get_instance(cls, config_file: Path | None = None) -> ToolConfigManager:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(config_file)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    def load(self) -> None:
        """Load tools.json from disk."""
        with self._lock:
            if not self._config_file.exists():
                self._overrides = {}
                self._custom_tools = {}
                return

            try:
                content = self._config_file.read_text(encoding="utf-8")
                if not content.strip():
                    self._overrides = {}
                    self._custom_tools = {}
                    return
                data = json.loads(content)
                self._overrides = {
                    k: ToolOverride.from_dict(v) for k, v in data.get("overrides", {}).items()
                }
                self._custom_tools = {
                    k: CustomToolDefinition.from_dict(v)
                    for k, v in data.get("custom_tools", {}).items()
                }
            except Exception as e:
                logger.error("Failed to load %s: %s", self._config_file, e)
                self._overrides = {}
                self._custom_tools = {}

    def save(self) -> None:
        """Save current configuration to tools.json."""
        with self._lock:
            data = {
                "overrides": {k: v.to_dict() for k, v in self._overrides.items()},
                "custom_tools": {k: v.to_dict() for k, v in self._custom_tools.items()},
            }
            try:
                self._config_file.parent.mkdir(parents=True, exist_ok=True)
                self._config_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception as e:
                logger.error("Failed to save %s: %s", self._config_file, e)

    # ── Overrides ──────────────────────────────────────────────────────────

    def get_override(self, tool_name: str) -> ToolOverride | None:
        with self._lock:
            return self._overrides.get(tool_name)

    def set_override(self, tool_name: str, **kwargs: Any) -> ToolOverride:
        with self._lock:
            override = self._overrides.get(tool_name) or ToolOverride()
            for key, val in kwargs.items():
                if hasattr(override, key):
                    setattr(override, key, val)
            self._overrides[tool_name] = override

        self.save()
        return override

    def remove_override(self, tool_name: str) -> bool:
        with self._lock:
            removed = self._overrides.pop(tool_name, None)
        if removed:
            self.save()
            return True
        return False

    def list_overrides(self) -> dict[str, ToolOverride]:
        with self._lock:
            return dict(self._overrides)

    # ── Custom Tools ───────────────────────────────────────────────────────

    def add_custom_tool(self, tool: CustomToolDefinition) -> None:
        with self._lock:
            self._custom_tools[tool.name] = tool
        self.save()

    def get_custom_tool(self, name: str) -> CustomToolDefinition | None:
        with self._lock:
            return self._custom_tools.get(name)

    def remove_custom_tool(self, name: str) -> bool:
        with self._lock:
            removed = self._custom_tools.pop(name, None)
        if removed:
            self.save()
            return True
        return False

    def list_custom_tools(self) -> dict[str, CustomToolDefinition]:
        with self._lock:
            return dict(self._custom_tools)

    # ── Enable / Disable ───────────────────────────────────────────────────

    def enable_tool(self, tool_name: str) -> bool:
        with self._lock:
            if tool_name in self._custom_tools:
                self._custom_tools[tool_name].enabled = True
            else:
                override = self._overrides.get(tool_name) or ToolOverride()
                override.enabled = True
                self._overrides[tool_name] = override
        self.save()
        return True

    def disable_tool(self, tool_name: str) -> bool:
        with self._lock:
            if tool_name in self._custom_tools:
                self._custom_tools[tool_name].enabled = False
            else:
                override = self._overrides.get(tool_name) or ToolOverride()
                override.enabled = False
                self._overrides[tool_name] = override
        self.save()
        return True

    def is_tool_enabled(self, tool_name: str) -> bool:
        with self._lock:
            if tool_name in self._custom_tools:
                return self._custom_tools[tool_name].enabled
            override = self._overrides.get(tool_name)
            if override is not None:
                return override.enabled
            return True

    def reset(self, tool_name: str | None = None) -> None:
        """Reset a specific tool modification or all modifications."""
        with self._lock:
            if tool_name:
                self._overrides.pop(tool_name, None)
            else:
                self._overrides.clear()
        self.save()


__all__ = [
    "ToolOverride",
    "CustomToolDefinition",
    "ToolConfigManager",
]
