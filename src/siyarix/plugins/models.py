# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data models and manifest schemas for the Siyarix plugin architecture."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from siyarix.tool_models import RiskLevel, ToolCategory

logger = logging.getLogger(__name__)


class PluginStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
    UNINSTALLED = "uninstalled"


class PluginType(StrEnum):
    PACKAGE = "package"
    SINGLE_FILE = "single_file"


@dataclass
class PluginDependency:
    name: str
    version_spec: str = ""
    dep_type: str = "python"  # "python" or "binary"

    @classmethod
    def from_any(cls, item: Any) -> PluginDependency:
        if isinstance(item, str):
            # E.g. "requests>=2.28.0" or "requests"
            for op in (">=", "<=", "==", "!=", "~=", ">", "<"):
                if op in item:
                    name, _, spec = item.partition(op)
                    return cls(
                        name=name.strip(), version_spec=f"{op}{spec.strip()}", dep_type="python"
                    )
            return cls(name=item.strip(), dep_type="python")
        if isinstance(item, dict):
            return cls(
                name=str(item.get("name", "")),
                version_spec=str(item.get("version", item.get("version_spec", ""))),
                dep_type=str(item.get("type", item.get("dep_type", "python"))),
            )
        return cls(name=str(item))


@dataclass
class PluginCapabilityInfo:
    tools: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    parsers: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginCapabilityInfo:
        return cls(
            tools=list(data.get("tools", [])),
            providers=list(data.get("providers", [])),
            parsers=list(data.get("parsers", [])),
            hooks=list(data.get("hooks", [])),
        )


@dataclass
class PluginManifest:
    name: str
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    license: str = "AGPL-3.0-or-later"
    homepage: str = ""
    entrypoint: str = "plugin.py"
    category: ToolCategory | str = ToolCategory.UTILITY
    risk_level: RiskLevel | str = RiskLevel.SAFE
    tags: list[str] = field(default_factory=list)
    dependencies: list[PluginDependency] = field(default_factory=list)
    capabilities: PluginCapabilityInfo = field(default_factory=PluginCapabilityInfo)
    min_siyarix_version: str = "0.1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginManifest:
        raw_cat = data.get("category", ToolCategory.UTILITY.value)
        try:
            category = ToolCategory(raw_cat)
        except ValueError:
            category = ToolCategory.UTILITY

        raw_risk = data.get("risk_level", RiskLevel.SAFE.value)
        try:
            risk_level = RiskLevel(raw_risk)
        except ValueError:
            risk_level = RiskLevel.SAFE

        deps_raw = data.get("dependencies", [])
        dependencies = [PluginDependency.from_any(d) for d in deps_raw]

        caps_raw = data.get("capabilities", {})
        capabilities = (
            PluginCapabilityInfo.from_dict(caps_raw)
            if isinstance(caps_raw, dict)
            else PluginCapabilityInfo()
        )

        return cls(
            name=str(data.get("name", "unnamed_plugin")),
            version=str(data.get("version", "1.0.0")),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            license=str(data.get("license", "AGPL-3.0-or-later")),
            homepage=str(data.get("homepage", "")),
            entrypoint=str(data.get("entrypoint", "plugin.py")),
            category=category,
            risk_level=risk_level,
            tags=[str(t) for t in data.get("tags", [])],
            dependencies=dependencies,
            capabilities=capabilities,
            min_siyarix_version=str(data.get("min_siyarix_version", "0.1.0")),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_file(cls, path: Path) -> PluginManifest:
        if not path.exists():
            raise FileNotFoundError(f"Plugin manifest file not found: {path}")

        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import-untyped]

                data = yaml.safe_load(content) or {}
            except ImportError:
                data = {}
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and ":" in line:
                        k, _, v = line.partition(":")
                        data[k.strip()] = v.strip().strip("'\"")
        else:
            data = json.loads(content)

        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(self.category, ToolCategory):
            d["category"] = self.category.value
        if isinstance(self.risk_level, RiskLevel):
            d["risk_level"] = self.risk_level.value
        return d


@dataclass
class PluginMetadata:
    manifest: PluginManifest
    status: PluginStatus = PluginStatus.ACTIVE
    plugin_type: PluginType = PluginType.PACKAGE
    path: Path = field(default_factory=lambda: Path("."))
    error_message: str | None = None
    loaded_at: float | None = None
    registered_tools: list[str] = field(default_factory=list)
    registered_providers: list[str] = field(default_factory=list)
    registered_parsers: list[str] = field(default_factory=list)
