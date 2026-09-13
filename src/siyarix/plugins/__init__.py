# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Dynamic Plugin Architecture."""

from __future__ import annotations

from .loader import PluginLoader
from .manager import PluginManager
from .models import (
    PluginCapabilityInfo,
    PluginDependency,
    PluginManifest,
    PluginMetadata,
    PluginStatus,
    PluginType,
)

__all__ = [
    "PluginCapabilityInfo",
    "PluginDependency",
    "PluginLoader",
    "PluginManager",
    "PluginManifest",
    "PluginMetadata",
    "PluginStatus",
    "PluginType",
]
