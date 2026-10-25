# SPDX-License-Identifier: AGPL-3.0-or-later
"""Legacy dynamic Plugin Loader for Siyarix.

Prefer :class:`siyarix.plugins.manager.PluginManager` for installs and loads.
This module remains for compatibility but sandboxes paths and delegates to
PluginManager when possible.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from siyarix.config import get_config_dir
from siyarix.providers.manager import ProviderManager
from siyarix.registry import ToolRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discovers and loads external plugins (sandboxed compatibility shim)."""

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

    def load_all(self) -> None:
        """Scan and load plugins via PluginManager sandbox when available."""
        if not self.plugins_dir.exists():
            return

        try:
            from siyarix.plugins.manager import PluginManager

            mgr = PluginManager(
                registry=self.registry,
                provider_manager=self.provider_manager,
                plugins_dir=self.plugins_dir,
            )
            mgr.discover()
            for name in list(mgr._installed_plugins.keys()):
                try:
                    mgr.load_plugin(name)
                except Exception as exc:
                    logger.error("Failed to load plugin %s: %s", name, exc)
            return
        except Exception as exc:
            logger.debug("PluginManager unavailable; using legacy sandbox load: %s", exc)

        for p in sorted(self.plugins_dir.glob("*.py")):
            if p.name.startswith("_"):
                continue
            try:
                self._load_plugin(p)
            except Exception as e:
                logger.error("Failed to load plugin %s: %s", p.name, e)

    def _load_plugin(self, path: Path) -> None:
        """Dynamically load a single python file as a plugin (path-sandboxed)."""
        import importlib.util

        from siyarix.plugins.manager import _assert_under_dir

        safe_path = _assert_under_dir(path, self.plugins_dir, what="legacy plugin path")
        if safe_path.suffix != ".py" or safe_path.name.startswith("_"):
            raise ValueError(f"Refusing to load non-plugin path: {path}")

        module_name = f"siyarix_plugin_{safe_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(safe_path))
        if not spec or not spec.loader:
            raise ImportError(f"Could not load spec for {safe_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        if hasattr(module, "register_tools"):
            module.register_tools(self.registry)
            logger.info("Plugin %s registered tools", module_name)

        if hasattr(module, "register_providers"):
            module.register_providers(self.provider_manager)
            logger.info("Plugin %s registered providers", module_name)
