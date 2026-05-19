"""NexSec CLI — CA-2.4 Configuration Management.

Settings stored in ~/.nexsec/settings.toml — human-editable TOML format.
Provides a type-safe settings store with get/set/reset/list/edit support.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import logging
from pathlib import Path
from typing import Any

from nexsec.executor import safe_run_sync

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(os.getenv("NEXSEC_CONFIG_DIR", str(Path.home() / ".nexsec")))
_SETTINGS_FILE = _CONFIG_DIR / "settings.toml"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, Any] = {
    "default_output_format": "table",
    "default_parallel": 3,
    "scan_timeout": 300,
    "auto_sync": True,
    "color_theme": "default",
    "log_level": "info",
    "proxy": "",
    "proxy_pool": "",
    "client_profile": "desktop_chrome",
    "tls_verify": True,
    "history_retention_days": 90,
    "model_provider": "auto",
    "gemini_model": "gemini-1.5-pro",
    "openai_model": "gpt-4o",
    "anthropic_model": "claude-2.1",
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.1",
    "notifications_enabled": True,
}

# Human-readable descriptions
DESCRIPTIONS: dict[str, str] = {
    "default_output_format": "Default output format: table | json | yaml | csv",
    "default_parallel": "Max tools to run in parallel during --all scans",
    "scan_timeout": "Seconds before a running tool is killed",
    "auto_sync": "Automatically sync findings to server when connected",
    "color_theme": "Terminal color theme: system | default | dark | light | minimal | neon",
    "log_level": "Logging verbosity: debug | info | warning | error",
    "proxy": "HTTP proxy URL for all outbound connections (empty = none)",
    "proxy_pool": "Comma-separated proxy list used for rotation",
    "client_profile": "Preferred profile: desktop_chrome | desktop_firefox | android_mobile | ios_safari",
    "tls_verify": "Verify TLS certificates on HTTPS requests",
    "history_retention_days": "Days to keep scan history (0 = forever)",
    "model_provider": "Preferred model provider: auto | openai | gemini | ollama",
    "gemini_model": "Gemini model name (default: gemini-1.5-pro)",
    "openai_model": "OpenAI model name (default: gpt-4o)",
    "anthropic_model": "Anthropic/Claude model name (default: claude-2.1)",
    "ollama_url": "Ollama server URL (default: http://localhost:11434)",
    "ollama_model": "Ollama model name (default: llama3.1)",
    "notifications_enabled": "Show Rich panel notifications for key events",
}


def _try_load_toml(path: Path) -> dict[str, Any]:
    """Load TOML file; returns empty dict on any error."""
    if not path.exists():
        return {}
    try:
        try:
            import tomllib  # Python 3.11+

            return tomllib.loads(path.read_text())
        except ImportError:
            try:
                import tomli  # third-party

                return tomli.loads(path.read_text())
            except ImportError:
                # Fallback: very simple TOML parser for key = value lines
                result: dict[str, Any] = {}
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        # Convert types
                        if v.lower() in ("true", "false"):
                            result[k] = v.lower() == "true"
                        elif v.isdigit():
                            result[k] = int(v)
                        else:
                            try:
                                result[k] = float(v)
                            except ValueError:
                                result[k] = v
                return result
    except Exception:
        logger.exception("Failed to parse TOML file %s", path)
        return {}


def _write_toml(path: Path, data: dict[str, Any]) -> None:
    """Write dict as TOML (simple key = value format)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# NexSec Agent Settings\n# Edit directly or use: nexsec-agent config set <key> <value>\n"
    ]
    for key, value in sorted(data.items()):
        desc = DESCRIPTIONS.get(key, "")
        if desc:
            lines.append(f"# {desc}")
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        else:
            lines.append(f"{key} = {value}")
        lines.append("")
    path.write_text("\n".join(lines))


class SettingsStore:
    """TOML-backed settings manager for the NexSec CLI.

    All reads fall back to DEFAULTS when a key is not set.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _SETTINGS_FILE
        self._data: dict[str, Any] = {**DEFAULTS, **_try_load_toml(self._path)}

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Any:
        """Return value for *key*, falling back to default."""
        if key not in DEFAULTS:
            raise KeyError(f"Unknown setting: '{key}'. Run 'config list' to see valid keys.")
        return self._data.get(key, DEFAULTS[key])

    def set(self, key: str, value: str) -> Any:
        """Set *key* to *value* (string input is coerced to the correct type)."""
        if key not in DEFAULTS:
            raise KeyError(f"Unknown setting: '{key}'. Run 'config list' to see valid keys.")
        coerced = self._coerce(key, value)
        self._data[key] = coerced
        self._save()
        return coerced

    def reset(self, key: str | None = None) -> None:
        """Reset *key* (or all settings) to defaults."""
        if key:
            if key not in DEFAULTS:
                raise KeyError(f"Unknown setting: '{key}'.")
            self._data[key] = DEFAULTS[key]
        else:
            self._data = {**DEFAULTS}
        self._save()

    def list_all(self) -> list[dict[str, Any]]:
        """Return all settings as a list of dicts for display."""
        rows = []
        for key in sorted(DEFAULTS):
            current = self._data.get(key, DEFAULTS[key])
            default = DEFAULTS[key]
            rows.append(
                {
                    "key": key,
                    "value": str(current),
                    "default": str(default),
                    "description": DESCRIPTIONS.get(key, ""),
                    "modified": current != default,
                }
            )
        return rows

    def edit(self) -> None:
        """Open settings file in $EDITOR."""
        self._save()  # ensure file exists
        import platform as _platform

        default_editor = "notepad" if _platform.system().lower() == "windows" else "nano"
        editor = os.getenv("EDITOR", default_editor)
        try:
            safe_run_sync([editor, str(self._path)], timeout=0)
        except Exception as exc:
            # Fallback to subprocess.call if safe_run_sync fails for unexpected editors
            logger.exception(
                "Opening editor failed with safe_run_sync, falling back to subprocess.call: %s", exc
            )
            subprocess.call([editor, str(self._path)])  # nosec B603
        # Reload after editing
        self._data = {**DEFAULTS, **_try_load_toml(self._path)}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _coerce(self, key: str, value: str) -> Any:
        """Coerce string input to the expected type for *key*."""
        default = DEFAULTS[key]
        if isinstance(default, bool):
            return value.lower() in ("true", "1", "yes", "on")
        if isinstance(default, int):
            try:
                return int(value)
            except ValueError as exc:
                raise ValueError(f"'{key}' expects an integer, got '{value}'.") from exc
        if isinstance(default, float):
            try:
                return float(value)
            except ValueError as exc:
                raise ValueError(f"'{key}' expects a number, got '{value}'.") from exc
        return value  # string

    def _save(self) -> None:
        _write_toml(self._path, self._data)
