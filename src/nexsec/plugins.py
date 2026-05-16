"""Lightweight local plugin manager for CLI extensions (CA-8.1)."""

from __future__ import annotations

import os
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")
_DEFAULT_ROOT = Path(os.getenv("COSMICSEC_PLUGINS_DIR", str(Path.home() / ".cosmicsec" / "plugins")))

@dataclass
class PluginMetadata:
    name: str
    version: str = "0.1.0"
    author: str = "Unknown"
    description: str = ""
    path: str = ""
    enabled: bool = True
    source: str = "local"
    homepage: str = ""
    tags: str = ""

def _validate_plugin_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise ValueError("Invalid plugin name. Use 2-64 chars: letters, numbers, dash or underscore.")

def _parse_simple_yaml(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result

def _to_bool(value: str | bool | None, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() not in {"0", "false", "no", "off"}

def _write_plugin_yaml(path: Path, metadata: PluginMetadata) -> None:
    path.write_text(
        "\n".join(
            [
                f"name: {metadata.name}",
                f"version: {metadata.version}",
                f"author: {metadata.author}",
                f"description: {metadata.description}",
                f"enabled: {'true' if metadata.enabled else 'false'}",
                f"source: {metadata.source}",
                f"homepage: {metadata.homepage}",
                f"tags: {metadata.tags}",
                "",
            ]
        ),
        encoding="utf-8",
    )

class PluginManager:
    def __init__(self, root: Path | None = None) -> None:
        self._root = root or _DEFAULT_ROOT
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def list_plugins(self) -> list[PluginMetadata]:
        plugins: list[PluginMetadata] = []
        for entry in sorted(self._root.iterdir()):
            if not entry.is_dir():
                continue
            meta = _parse_simple_yaml(entry / "plugin.yaml")
            name = meta.get("name", entry.name)
            plugins.append(
                PluginMetadata(
                    name=name,
                    version=meta.get("version", "0.1.0"),
                    author=meta.get("author", "Unknown"),
                    description=meta.get("description", ""),
                    path=str(entry),
                    enabled=_to_bool(meta.get("enabled"), default=True),
                    source=meta.get("source", "local"),
                    homepage=meta.get("homepage", ""),
                    tags=meta.get("tags", ""),
                )
            )
        return plugins

    def get_plugin(self, name: str) -> PluginMetadata | None:
        _validate_plugin_name(name)
        for plugin in self.list_plugins():
            if plugin.name == name:
                return plugin
        return None

    def search(self, query: str) -> list[PluginMetadata]:
        needle = query.lower().strip()
        if not needle:
            return self.list_plugins()
        return [
            plugin
            for plugin in self.list_plugins()
            if needle in plugin.name.lower() or needle in plugin.description.lower()
        ]

    def create_scaffold(self, name: str, author: str = "Unknown") -> Path:
        _validate_plugin_name(name)
        plugin_dir = self._root / name
        if plugin_dir.exists():
            raise FileExistsError(f"Plugin '{name}' already exists.")
        plugin_dir.mkdir(parents=True, exist_ok=False)

        _write_plugin_yaml(
            plugin_dir / "plugin.yaml",
            PluginMetadata(
                name=name,
                version="0.1.0",
                author=author,
                description="Custom CosmicSec plugin",
                path=str(plugin_dir),
            ),
        )
        (plugin_dir / "__init__.py").write_text(
            f'"""Plugin package: {name}."""\n',
            encoding="utf-8",
        )
        (plugin_dir / "commands.py").write_text(
            (
                "from __future__ import annotations\n\n"
                "def register(app) -> None:\n"
                '    """Register additional Typer commands."""\n'
                "    return None\n"
            ),
            encoding="utf-8",
        )
        (plugin_dir / "parser.py").write_text(
            (
                "from __future__ import annotations\n\n"
                "def parse_tool_output(stdout: str) -> list[dict]:\n"
                '    """Return parsed findings for this plugin\'s custom tool."""\n'
                "    return []\n"
            ),
            encoding="utf-8",
        )
        return plugin_dir

    def install_from_path(self, source: Path) -> Path:
        if not source.exists() or not source.is_dir():
            raise FileNotFoundError(f"Plugin source path does not exist: {source}")
        name = source.name
        _validate_plugin_name(name)
        dest = self._root / name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source, dest)
        meta_path = dest / "plugin.yaml"
        if not meta_path.exists():
            _write_plugin_yaml(
                meta_path,
                PluginMetadata(
                    name=dest.name,
                    version="0.1.0",
                    author="Unknown",
                    description="Installed plugin",
                    path=str(dest),
                ),
            )
        return dest

    def remove(self, name: str) -> bool:
        _validate_plugin_name(name)
        plugin_dir = self._root / name
        if not plugin_dir.exists():
            return False
        shutil.rmtree(plugin_dir)
        return True

    def set_enabled(self, name: str, enabled: bool) -> PluginMetadata:
        _validate_plugin_name(name)
        plugin_dir = self._root / name
        if not plugin_dir.exists():
            raise FileNotFoundError(f"Plugin '{name}' not found.")

        existing = self.get_plugin(name) or PluginMetadata(name=name, path=str(plugin_dir))
        updated = PluginMetadata(
            name=existing.name,
            version=existing.version,
            author=existing.author,
            description=existing.description,
            path=str(plugin_dir),
            enabled=enabled,
            source=existing.source,
            homepage=existing.homepage,
            tags=existing.tags,
        )
        _write_plugin_yaml(plugin_dir / "plugin.yaml", updated)
        return updated

    def _load_module(self, module_file: Path, module_name: str) -> ModuleType:
        spec = spec_from_file_location(module_name, str(module_file))
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec for {module_file}")
        module = module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def load_command_plugins(self, app) -> list[str]:
        """Load and register enabled command plugins."""
        loaded: list[str] = []
        for plugin in self.list_plugins():
            if not plugin.enabled:
                continue
            module_file = Path(plugin.path) / "commands.py"
            if not module_file.exists():
                continue
            module = self._load_module(module_file, f"cosmicsec_plugin_{plugin.name}_commands")
            register = getattr(module, "register", None)
            if callable(register):
                register(app)
                loaded.append(plugin.name)
        return loaded

    def load_parser_plugins(self) -> dict[str, Callable[[str], list[dict]]]:
        """Load parse_tool_output hooks from enabled plugins."""
        parsers: dict[str, Callable[[str], list[dict]]] = {}
        for plugin in self.list_plugins():
            if not plugin.enabled:
                continue
            module_file = Path(plugin.path) / "parser.py"
            if not module_file.exists():
                continue
            module = self._load_module(module_file, f"cosmicsec_plugin_{plugin.name}_parser")
            parser_fn = getattr(module, "parse_tool_output", None)
            if callable(parser_fn):
                parsers[plugin.name] = parser_fn
        return parsers
