# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dynamic Plugin Loader for Siyarix."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

from siyarix.config import get_config_dir
from siyarix.providers.manager import ProviderManager
from siyarix.registry import ToolRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discovers and loads external plugins."""

    def __init__(self, registry: ToolRegistry, provider_manager: ProviderManager) -> None:
        self.registry = registry
        self.provider_manager = provider_manager
        self.plugins_dir = get_config_dir() / "plugins"
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

    def load_all(self) -> None:
        """Scan and load all .py plugins from the plugins directory."""
        if not self.plugins_dir.exists():
            return

        for p in self.plugins_dir.glob("*.py"):
            if p.name.startswith("_"):
                continue
            try:
                self._load_plugin(p)
            except Exception as e:
                logger.error("Failed to load plugin %s: %s", p.name, e)

    def _load_plugin(self, path: Path) -> None:
        """Dynamically load a single python file as a plugin."""
        module_name = f"siyarix_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if not spec or not spec.loader:
            raise ImportError(f"Could not load spec for {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Look for standard hooks
        if hasattr(module, "register_tools"):
            module.register_tools(self.registry)
            logger.info("Plugin %s registered tools", module_name)

        if hasattr(module, "register_providers"):
            module.register_providers(self.provider_manager)
            logger.info("Plugin %s registered providers", module_name)
