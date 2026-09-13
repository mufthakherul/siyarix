# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enterprise Plugin Manager for Siyarix.

Provides dynamic discovery, sandboxed loading, lifecycle hooks, configuration
management, remote registry search, and installation.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from siyarix.config import get_config_dir
from siyarix.plugins.models import (
    PluginManifest,
    PluginMetadata,
    PluginStatus,
    PluginType,
)
from siyarix.providers.manager import ProviderManager
from siyarix.registry import ToolRegistry
from siyarix.tool_models import ToolCategory

logger = logging.getLogger(__name__)

OFFICIAL_REGISTRY_URL = "https://raw.githubusercontent.com/siyarix/siyarix-plugins/main/index.json"
OFFICIAL_REPO_URL = "https://github.com/siyarix/siyarix-plugins.git"


class PluginManager:
    """Enterprise manager for discovery, loading, lifecycle, and remote registry."""

    _instance: PluginManager | None = None

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        provider_manager: ProviderManager | None = None,
        plugins_dir: Path | None = None,
        config_dir: Path | None = None,
    ) -> None:
        self.registry = registry or ToolRegistry()
        self.provider_manager = provider_manager or ProviderManager.get_instance()
        self.config_dir = config_dir or get_config_dir()
        self.plugins_dir = plugins_dir or (self.config_dir / "plugins")
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / "plugins_config.json"

        self._installed_plugins: dict[str, PluginMetadata] = {}
        self._loaded_modules: dict[str, Any] = {}
        self._plugin_tools_map: dict[str, list[str]] = {}  # plugin_name -> [tool_names]
        self._config_data: dict[str, Any] = self._load_config()

    @classmethod
    def get_instance(
        cls,
        registry: ToolRegistry | None = None,
        provider_manager: ProviderManager | None = None,
        plugins_dir: Path | None = None,
    ) -> PluginManager:
        if cls._instance is None:
            cls._instance = cls(
                registry=registry,
                provider_manager=provider_manager,
                plugins_dir=plugins_dir,
            )
        elif registry is not None:
            cls._instance.registry = registry
        return cls._instance

    # -----------------------------------------------------------------------
    # Configuration & State Storage
    # -----------------------------------------------------------------------

    def _load_config(self) -> dict[str, Any]:
        if self.config_file.exists():
            try:
                data = json.loads(self.config_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception as e:
                logger.warning("Failed to parse plugins_config.json: %s", e)
        return {"disabled": [], "registry_mirrors": []}

    def _save_config(self) -> None:
        try:
            self.config_file.write_text(json.dumps(self._config_data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to save plugins_config.json: %s", e)

    def is_enabled(self, name: str) -> bool:
        disabled = self._config_data.get("disabled", [])
        return name not in disabled

    # -----------------------------------------------------------------------
    # Discovery & Scanning
    # -----------------------------------------------------------------------

    def discover(self) -> dict[str, PluginMetadata]:
        """Scan the plugins directory for package and single-file plugins."""
        discovered: dict[str, PluginMetadata] = {}
        if not self.plugins_dir.exists():
            return discovered

        # 1. Package plugins (directories containing plugin.yaml or plugin.json)
        for item in self.plugins_dir.iterdir():
            if not item.is_dir() or item.name.startswith((".", "_")):
                continue

            manifest_path = None
            for candidate in ("plugin.yaml", "plugin.yml", "plugin.json"):
                p = item / candidate
                if p.exists():
                    manifest_path = p
                    break

            if manifest_path:
                try:
                    manifest = PluginManifest.from_file(manifest_path)
                    meta = PluginMetadata(
                        manifest=manifest,
                        status=(
                            PluginStatus.ACTIVE
                            if self.is_enabled(manifest.name)
                            else PluginStatus.DISABLED
                        ),
                        plugin_type=PluginType.PACKAGE,
                        path=item,
                    )
                    discovered[manifest.name] = meta
                except Exception as e:
                    logger.error("Failed to parse manifest for plugin %s: %s", item.name, e)
                    # Record error plugin
                    fallback_manifest = PluginManifest(
                        name=item.name, description="Invalid manifest"
                    )
                    discovered[item.name] = PluginMetadata(
                        manifest=fallback_manifest,
                        status=PluginStatus.ERROR,
                        plugin_type=PluginType.PACKAGE,
                        path=item,
                        error_message=str(e),
                    )

        # 2. Standalone single-file plugins (*.py)
        for p in self.plugins_dir.glob("*.py"):
            if p.name.startswith(("_", ".")):
                continue
            name = p.stem
            if name in discovered:
                continue

            # Synthesize manifest from single-file docstrings or default attributes
            manifest = self._manifest_from_py_file(p)
            meta = PluginMetadata(
                manifest=manifest,
                status=PluginStatus.ACTIVE if self.is_enabled(name) else PluginStatus.DISABLED,
                plugin_type=PluginType.SINGLE_FILE,
                path=p,
            )
            discovered[name] = meta

        self._installed_plugins.update(discovered)
        return self._installed_plugins

    def _manifest_from_py_file(self, path: Path) -> PluginManifest:
        """Create a default manifest from a single Python file."""
        name = path.stem
        desc = f"Single-file Siyarix plugin: {name}"
        version = "1.0.0"
        author = "Community"
        category = ToolCategory.UTILITY

        try:
            content = path.read_text(encoding="utf-8")
            # Extract docstring if present
            if '"""' in content:
                parts = content.split('"""')
                if len(parts) >= 3:
                    doc = parts[1].strip()
                    if doc:
                        desc = doc.split("\n")[0]
        except Exception:
            pass

        return PluginManifest(
            name=name,
            version=version,
            description=desc,
            author=author,
            entrypoint=path.name,
            category=category,
            tags=["standalone", name],
        )

    # -----------------------------------------------------------------------
    # Loading & Unloading
    # -----------------------------------------------------------------------

    def load_all(self) -> int:
        """Discover and load all enabled plugins."""
        self.discover()
        loaded_count = 0

        for name, meta in list(self._installed_plugins.items()):
            if not self.is_enabled(name):
                meta.status = PluginStatus.DISABLED
                continue
            if meta.status == PluginStatus.ERROR:
                continue

            if self.load_plugin(name):
                loaded_count += 1

        return loaded_count

    def load_plugin(self, name: str) -> bool:
        """Load a single discovered plugin into the runtime."""
        meta = self._installed_plugins.get(name)
        if not meta:
            self.discover()
            meta = self._installed_plugins.get(name)

        if not meta:
            logger.warning("Plugin %s not found for loading", name)
            return False

        if not self.is_enabled(name):
            meta.status = PluginStatus.DISABLED
            return False

        entry_path = (
            meta.path
            if meta.plugin_type == PluginType.SINGLE_FILE
            else meta.path / meta.manifest.entrypoint
        )

        if not entry_path.exists():
            meta.status = PluginStatus.ERROR
            meta.error_message = f"Entrypoint not found: {entry_path}"
            logger.error(meta.error_message)
            return False

        module_name = f"siyarix_plugin_{name}"
        sys_path_added = False
        if meta.plugin_type == PluginType.PACKAGE:
            dir_str = str(meta.path)
            if dir_str not in sys.path:
                sys.path.insert(0, dir_str)
                sys_path_added = True

        try:
            # Snapshot registered tools to calculate which tools this plugin added
            existing_tools = set(self.registry._graph._nodes.keys())

            spec = importlib.util.spec_from_file_location(module_name, str(entry_path))
            if not spec or not spec.loader:
                raise ImportError(f"Could not load spec for {entry_path}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self._loaded_modules[name] = module

            # Execute standard extension hooks
            if hasattr(module, "register_tools"):
                module.register_tools(self.registry)

            if hasattr(module, "register_providers"):
                module.register_providers(self.provider_manager)

            if hasattr(module, "register_parsers"):
                try:
                    from siyarix.parsers import ParserRegistry

                    parser_reg = (
                        getattr(self.registry, "_parser_registry", None) or ParserRegistry()
                    )
                    module.register_parsers(parser_reg)
                except Exception as pe:
                    logger.debug("register_parsers hook ignored: %s", pe)

            if hasattr(module, "on_load"):
                try:
                    module.on_load()
                except Exception as oe:
                    logger.warning("Plugin %s on_load hook raised: %s", name, oe)

            # Record registered tools
            new_tools = set(self.registry._graph._nodes.keys()) - existing_tools
            meta.registered_tools = sorted(list(new_tools))
            self._plugin_tools_map[name] = meta.registered_tools

            meta.status = PluginStatus.ACTIVE
            meta.error_message = None
            meta.loaded_at = time.time()
            logger.info("Plugin %s successfully loaded with tools: %s", name, meta.registered_tools)
            return True

        except Exception as e:
            meta.status = PluginStatus.ERROR
            meta.error_message = str(e)
            logger.error("Failed to load plugin %s: %s", name, e, exc_info=True)
            return False
        finally:
            if sys_path_added and str(meta.path) in sys.path:
                try:
                    sys.path.remove(str(meta.path))
                except ValueError:
                    pass

    def unload_plugin(self, name: str) -> bool:
        """Unload plugin, unregistering its tools and hooks."""
        meta = self._installed_plugins.get(name)
        if not meta:
            return False

        # Deregister tools registered by this plugin
        tools = self._plugin_tools_map.get(name, []) or meta.registered_tools
        for tool_name in tools:
            try:
                self.registry.unregister(tool_name)
            except Exception as e:
                logger.debug("Failed unregistering tool %s: %s", tool_name, e)

        meta.registered_tools = []
        self._plugin_tools_map.pop(name, None)

        # Call on_unload hook if defined
        module = self._loaded_modules.pop(name, None)
        if module and hasattr(module, "on_unload"):
            try:
                module.on_unload()
            except Exception as e:
                logger.debug("Plugin %s on_unload hook failed: %s", name, e)

        module_name = f"siyarix_plugin_{name}"
        sys.modules.pop(module_name, None)

        meta.status = (
            PluginStatus.DISABLED if not self.is_enabled(name) else PluginStatus.UNINSTALLED
        )
        return True

    def reload_plugin(self, name: str) -> bool:
        """Hot-reload an installed plugin."""
        self.unload_plugin(name)
        return self.load_plugin(name)

    def enable(self, name: str) -> bool:
        """Enable an installed plugin."""
        disabled = self._config_data.get("disabled", [])
        if name in disabled:
            disabled.remove(name)
            self._config_data["disabled"] = disabled
            self._save_config()

        return self.load_plugin(name)

    def disable(self, name: str) -> bool:
        """Disable an installed plugin."""
        disabled = set(self._config_data.get("disabled", []))
        disabled.add(name)
        self._config_data["disabled"] = sorted(list(disabled))
        self._save_config()

        self.unload_plugin(name)
        if name in self._installed_plugins:
            self._installed_plugins[name].status = PluginStatus.DISABLED
        return True

    # -----------------------------------------------------------------------
    # Remote Registry & Management
    # -----------------------------------------------------------------------

    def fetch_registry_index(self, refresh: bool = False) -> list[dict[str, Any]]:
        """Fetch remote registry index of available plugins."""
        cache_file = self.config_dir / "registry_cache.json"

        # 1. First priority: Check local repo clone if present
        local_repo_index = self.plugins_dir.parent / "siyarix-plugins" / "index.json"
        # Also check workspace path e:\Documents\siyarix\siyarix-plugins\index.json
        workspace_repo_index = Path.cwd() / "siyarix-plugins" / "index.json"

        for p in (local_repo_index, workspace_repo_index):
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict) and "plugins" in data:
                        return list(data["plugins"])
                except Exception as e:
                    logger.debug("Failed reading local registry %s: %s", p, e)

        # 2. Check disk cache if recent (< 1 hour) and not forced refresh
        if not refresh and cache_file.exists():
            try:
                age = time.time() - cache_file.stat().st_mtime
                if age < 3600:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        return data
            except Exception:
                pass

        # 3. Fetch from GitHub remote registry
        urls = [OFFICIAL_REGISTRY_URL] + self._config_data.get("registry_mirrors", [])
        for url in urls:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Siyarix-PluginManager/1.0"},
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    raw = resp.read().decode("utf-8")
                    parsed = json.loads(raw)
                    plugins = parsed if isinstance(parsed, list) else parsed.get("plugins", [])
                    try:
                        cache_file.write_text(json.dumps(plugins, indent=2), encoding="utf-8")
                    except Exception:
                        pass
                    return list(plugins)
            except Exception as e:
                logger.debug("Failed fetching registry from %s: %s", url, e)

        # 4. Fallback to cached version if network fails
        if cache_file.exists():
            try:
                return list(json.loads(cache_file.read_text(encoding="utf-8")))
            except Exception:
                pass

        return []

    def search(
        self,
        query: str = "",
        category: str | None = None,
        tag: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search available plugins in the registry."""
        catalog = self.fetch_registry_index()
        results: list[dict[str, Any]] = []
        q_lower = query.lower().strip()

        installed = self.list_plugins()
        installed_names = {p.manifest.name for p in installed}

        for item in catalog:
            name = item.get("name", "")
            desc = item.get("description", "")
            tags = [str(t).lower() for t in item.get("tags", [])]
            cat = str(item.get("category", "")).lower()
            tools = [
                str(t).lower()
                for t in item.get("tools", item.get("capabilities", {}).get("tools", []))
            ]

            if category and cat != category.lower():
                continue
            if tag and tag.lower() not in tags:
                continue

            if q_lower:
                match = (
                    q_lower in name.lower()
                    or q_lower in desc.lower()
                    or any(q_lower in t for t in tags)
                    or any(q_lower in tl for tl in tools)
                    or q_lower in cat
                )
                if not match:
                    continue

            item_copy = dict(item)
            item_copy["installed"] = name in installed_names
            results.append(item_copy)

        return results

    def install(
        self,
        name_or_url: str,
        force: bool = False,
    ) -> PluginMetadata:
        """Install a plugin from registry name, git URL, or local path."""
        target_name = ""

        # Case A: Local directory or file path
        local_path = Path(name_or_url)
        if local_path.exists():
            if local_path.is_dir():
                target_name = local_path.name
                dest = self.plugins_dir / target_name
                if dest.exists():
                    if not force:
                        raise FileExistsError(f"Plugin '{target_name}' already exists.")
                    shutil.rmtree(dest)
                shutil.copytree(local_path, dest)
            else:
                target_name = local_path.stem
                dest = self.plugins_dir / local_path.name
                if dest.exists() and not force:
                    raise FileExistsError(f"Plugin '{target_name}' already exists.")
                shutil.copy2(local_path, dest)

            self.discover()
            self.load_plugin(target_name)
            return self._installed_plugins[target_name]

        # Case B: Git Repository URL
        if name_or_url.startswith(("http://", "https://", "git@")):
            repo_url = name_or_url
            target_name = repo_url.rstrip("/").split("/")[-1]
            if target_name.endswith(".git"):
                target_name = target_name[:-4]
            dest = self.plugins_dir / target_name

            if dest.exists():
                if not force:
                    raise FileExistsError(f"Plugin directory '{target_name}' already exists.")
                shutil.rmtree(dest)

            cmd = ["git", "clone", "--depth", "1", repo_url, str(dest)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Git clone failed: {res.stderr}")

            self._install_dependencies(dest)
            self.discover()
            self.load_plugin(target_name)
            return self._installed_plugins[target_name]

        # Case C: Registry Plugin Name
        target_name = name_or_url.strip()
        catalog = self.fetch_registry_index()
        entry = next((i for i in catalog if i.get("name") == target_name), None)

        # Check local plugins repo first
        local_plugins_repo = Path.cwd() / "siyarix-plugins" / "plugins" / target_name
        dest = self.plugins_dir / target_name

        if local_plugins_repo.exists():
            if dest.exists():
                if not force:
                    raise FileExistsError(f"Plugin '{target_name}' is already installed.")
                shutil.rmtree(dest)
            shutil.copytree(local_plugins_repo, dest)
        elif entry:
            # Check if entry provides a direct source git or subdirectory
            source_url = entry.get("source", "")
            if source_url and source_url.startswith("http"):
                return self.install(source_url, force=force)

            # Download plugin package from official siyarix-plugins repository
            dest.mkdir(parents=True, exist_ok=True)
            raw_base = f"https://raw.githubusercontent.com/siyarix/siyarix-plugins/main/plugins/{target_name}"
            files_to_fetch = ["plugin.yaml", "plugin.py", "README.md"]
            fetched_any = False

            for filename in files_to_fetch:
                file_url = f"{raw_base}/{filename}"
                try:
                    req = urllib.request.Request(
                        file_url, headers={"User-Agent": "Siyarix-PluginManager/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        (dest / filename).write_bytes(resp.read())
                        fetched_any = True
                except Exception as e:
                    logger.debug("Optional file %s not fetched: %s", filename, e)

            if not fetched_any:
                # Cleanup empty dest
                shutil.rmtree(dest, ignore_errors=True)
                raise RuntimeError(
                    f"Could not download plugin files for '{target_name}' from {raw_base}"
                )
        else:
            raise ValueError(f"Plugin '{target_name}' not found in registry or local paths.")

        self._install_dependencies(dest)
        self.discover()
        self.load_plugin(target_name)

        if target_name not in self._installed_plugins:
            raise RuntimeError(f"Plugin '{target_name}' installed but failed initial discovery.")

        return self._installed_plugins[target_name]

    def _install_dependencies(self, plugin_dir: Path) -> None:
        """Safely resolve plugin python dependencies."""
        req_file = plugin_dir / "requirements.txt"
        if req_file.exists():
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)],
                    capture_output=True,
                    timeout=60,
                )
            except Exception as e:
                logger.warning("Dependency installation warning for %s: %s", plugin_dir.name, e)

    def uninstall(self, name: str) -> bool:
        """Uninstall a plugin, removing files and deregistering tools."""
        self.unload_plugin(name)

        meta = self._installed_plugins.pop(name, None)
        if not meta or not meta.path.exists():
            return False

        try:
            if meta.path.is_dir():
                shutil.rmtree(meta.path)
            else:
                meta.path.unlink()
            return True
        except Exception as e:
            logger.error("Failed removing plugin %s path: %s", name, e)
            return False

    def update(self, name: str | None = None) -> list[str]:
        """Update one or all plugins from the registry."""
        updated = []
        targets = [name] if name else list(self._installed_plugins.keys())

        for t in targets:
            if t not in self._installed_plugins:
                continue
            meta = self._installed_plugins[t]
            # Check if git-controlled
            git_dir = meta.path / ".git"
            if git_dir.exists():
                res = subprocess.run(
                    ["git", "-C", str(meta.path), "pull", "--ff-only"],
                    capture_output=True,
                    text=True,
                )
                if res.returncode == 0:
                    self.reload_plugin(t)
                    updated.append(t)
            else:
                try:
                    self.install(t, force=True)
                    updated.append(t)
                except Exception as e:
                    logger.warning("Failed updating plugin %s: %s", t, e)

        return updated

    def info(self, name: str) -> dict[str, Any]:
        """Get rich runtime inspection data for an installed plugin."""
        meta = self._installed_plugins.get(name)
        if not meta:
            self.discover()
            meta = self._installed_plugins.get(name)

        if not meta:
            raise KeyError(f"Plugin '{name}' not installed.")

        m = meta.manifest
        return {
            "name": m.name,
            "version": m.version,
            "description": m.description,
            "author": m.author,
            "license": m.license,
            "homepage": m.homepage,
            "category": m.category.value if hasattr(m.category, "value") else str(m.category),
            "risk_level": m.risk_level.value
            if hasattr(m.risk_level, "value")
            else str(m.risk_level),
            "tags": m.tags,
            "status": meta.status.value,
            "plugin_type": meta.plugin_type.value,
            "path": str(meta.path),
            "registered_tools": meta.registered_tools or meta.manifest.capabilities.tools,
            "error_message": meta.error_message,
            "loaded_at": meta.loaded_at,
            "dependencies": [d.name for d in m.dependencies],
        }

    def list_plugins(self, auto_load: bool = True) -> list[PluginMetadata]:
        """Return list of all discovered and installed plugins."""
        if auto_load:
            self.load_all()
        else:
            self.discover()
        for p in self._installed_plugins.values():
            if not p.registered_tools and p.manifest.capabilities.tools:
                p.registered_tools = list(p.manifest.capabilities.tools)
        return sorted(list(self._installed_plugins.values()), key=lambda p: p.manifest.name)

    def create(self, name: str, category: str = "recon") -> Path:
        """Scaffold a new enterprise plugin directory."""
        slug = name.lower().replace("-", "_").strip()
        target_dir = self.plugins_dir / slug
        if target_dir.exists():
            raise FileExistsError(f"Plugin directory '{slug}' already exists.")

        target_dir.mkdir(parents=True)

        manifest = {
            "name": slug,
            "version": "1.0.0",
            "description": f"Custom Siyarix security plugin: {slug}",
            "author": os.environ.get("USER", os.environ.get("USERNAME", "Siyarix Developer")),
            "license": "AGPL-3.0-or-later",
            "category": category,
            "risk_level": "safe",
            "tags": [slug, category, "custom"],
            "entrypoint": "plugin.py",
            "capabilities": {
                "tools": [slug],
            },
        }
        (target_dir / "plugin.yaml").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        plugin_py = f'''# SPDX-License-Identifier: AGPL-3.0-or-later
"""{slug.title()} Security Plugin for Siyarix."""

from __future__ import annotations

import logging
from typing import Any

from siyarix.registry import ToolRegistry
from siyarix.tool_models import RiskLevel, ToolCapability, ToolCategory

logger = logging.getLogger(__name__)


async def run_{slug}(**kwargs: Any) -> dict[str, Any]:
    """Execute the {slug} operation."""
    target = kwargs.get("target", "unknown")
    logger.info("Executing {slug} on %s", target)
    return {{
        "status": "success",
        "output": f"[{slug.upper()}] Successfully executed against {{target}}.",
        "findings": [],
    }}


def register_tools(registry: ToolRegistry) -> None:
    """Register custom capabilities in Siyarix ToolRegistry."""
    cap = ToolCapability(
        name="{slug}",
        description="Custom security capability: {slug}",
        category=ToolCategory.{category.upper() if hasattr(ToolCategory, category.upper()) else "UTILITY"},
        risk_level=RiskLevel.SAFE,
        tags=["{slug}", "{category}"],
    )
    registry.register(cap, run_{slug})
    logger.info("Registered tool: {slug}")
'''
        (target_dir / "plugin.py").write_text(plugin_py, encoding="utf-8")
        (target_dir / "README.md").write_text(
            f"# {slug}\n\nCustom Siyarix security plugin.\n", encoding="utf-8"
        )

        return target_dir
