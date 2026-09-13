# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dynamic Plugin Loader for Siyarix (backed by enterprise PluginManager)."""

from __future__ import annotations

import logging
from pathlib import Path

from siyarix.config import get_config_dir
from siyarix.plugins.manager import PluginManager
from siyarix.providers.manager import ProviderManager
from siyarix.registry import ToolRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discovers and loads external plugins using the enterprise PluginManager."""

    def __init__(
        self,
        registry: ToolRegistry,
        provider_manager: ProviderManager,
        plugins_dir: Path | None = None,
    ) -> None:
        self.registry = registry
        self.provider_manager = provider_manager
        self.plugins_dir = plugins_dir or (get_config_dir() / "plugins")
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.manager = PluginManager.get_instance(
            registry=self.registry,
            provider_manager=self.provider_manager,
            plugins_dir=self.plugins_dir,
        )

    def load_all(self) -> None:
        """Scan and load all plugins from the plugins directory."""
        self.manager.load_all()

    def _load_plugin(self, path: Path) -> None:
        """Dynamically load a single python file or directory as a plugin."""
        self.manager.install(str(path), force=True)
