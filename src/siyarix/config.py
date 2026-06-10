# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix CLI — CA-2.4 Configuration Management.

Settings stored in ~/.siyarix/settings.toml — human-editable TOML format.
Provides a type-safe settings store with get/set/reset/list/edit support.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from siyarix.subprocess_utils import safe_run_sync

logger = logging.getLogger(__name__)

# Environment variable → config key mapping (Appendix B)
_ENV_TO_CONFIG: dict[str, str] = {
    "SIYARIX_CONFIG": "_config_path",
    "SIYARIX_HOME": "_home_dir",
    "SIYARIX_DEBUG": "log_level",
    "SIYARIX_PERSONA": "persona",
    "SIYARIX_PROVIDER": "model_provider",
    "SIYARIX_TIMEOUT": "scan_timeout",
    "SIYARIX_LOG_LEVEL": "log_level",
    "SIYARIX_NO_TELEMETRY": "_no_telemetry",
    "SIYARIX_SAFE_MODE": "_safe_mode",
}

_CONFIG_DIR = Path(os.getenv("SIYARIX_CONFIG_DIR",
                 os.getenv("SIYARIX_HOME", str(Path.home() / ".siyarix"))))
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
    "log_level": "warning",
    "proxy": "",
    "proxy_pool": "",
    "client_profile": "desktop_chrome",
    "tls_verify": True,
    "history_retention_days": 90,
    "model_provider": "auto",
    # Cloud provider models
    "openai_model": "gpt-5.4",
    "openai_vision_model": "gpt-5.4",
    "openai_fast_model": "gpt-5.4-mini",
    "anthropic_model": "claude-sonnet-4-6",
    "anthropic_vision_model": "claude-opus-4-8",
    "gemini_model": "gemini-3.5-flash",
    "gemini_vision_model": "gemini-3.5-pro",
    "gemini_fast_model": "gemini-2.5-flash",
    "groq_model": "llama-4-scout-17b-16e-instruct",
    "together_model": "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8",
    "openrouter_model": "openai/gpt-5.4",
    # New providers
    "deepseek_model": "deepseek-v4-flash",
    "xai_model": "grok-4.3",
    "mistral_model": "mistral-large-3",
    "perplexity_model": "sonar",
    "azure_model": "gpt-5.4",
    "azure_endpoint": "",
    # Local provider config
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.1",
    "lmstudio_url": "http://localhost:1234",
    "lmstudio_model": "",
    "llamacpp_url": "http://localhost:8080",
    "llamacpp_model": "",
    "vllm_url": "http://localhost:8000",
    "vllm_model": "",
    "localai_url": "http://localhost:8080",
    "localai_model": "",
    # Agent settings
    "agent_timeout": 1740,
    "notifications_enabled": True,
    "stealth_mode": False,
    "persona": "auto",
    "command_review": True,
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
    "model_provider": "Preferred model provider: auto | openai | gemini | anthropic | groq | together | openrouter | deepseek | xai | mistral | perplexity | azure | ollama | lmstudio | llamacpp | vllm | localai",
    "openai_model": "OpenAI model name (default: gpt-5.4)",
    "openai_vision_model": "OpenAI vision-capable model (default: gpt-5.4)",
    "openai_fast_model": "OpenAI fast/cheap model (default: gpt-5.4-mini)",
    "anthropic_model": "Anthropic/Claude model name (default: claude-sonnet-4-6)",
    "anthropic_vision_model": "Anthropic vision-capable model (default: claude-opus-4-8)",
    "gemini_model": "Gemini model name (default: gemini-3.5-flash)",
    "gemini_vision_model": "Gemini vision-capable model (default: gemini-3.5-pro)",
    "gemini_fast_model": "Gemini fast model (default: gemini-2.5-flash)",
    "groq_model": "Groq model name (default: llama-4-scout-17b-16e-instruct)",
    "together_model": "Together AI model name (default: meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8)",
    "openrouter_model": "OpenRouter model name (default: openai/gpt-5.4)",
    "deepseek_model": "DeepSeek model name (default: deepseek-v4-flash)",
    "xai_model": "xAI/Grok model name (default: grok-4.3)",
    "mistral_model": "Mistral AI model name (default: mistral-large-3)",
    "perplexity_model": "Perplexity model name (default: sonar)",
    "azure_model": "Azure OpenAI model name (default: gpt-5.4)",
    "azure_endpoint": "Azure OpenAI endpoint URL (default: https://YOUR_RESOURCE.openai.azure.com)",
    "ollama_url": "Ollama server URL (default: http://localhost:11434)",
    "ollama_model": "Ollama model name (default: llama3.1)",
    "lmstudio_url": "LM Studio server URL (default: http://localhost:1234)",
    "lmstudio_model": "LM Studio model name (default: empty for auto-detect)",
    "llamacpp_url": "llama.cpp server URL (default: http://localhost:8080)",
    "llamacpp_model": "llama.cpp model name (default: empty for server default)",
    "vllm_url": "vLLM server URL (default: http://localhost:8000)",
    "vllm_model": "vLLM model name (default: empty for server default)",
    "localai_url": "LocalAI server URL (default: http://localhost:8080)",
    "localai_model": "LocalAI model name (default: empty for server default)",
    "agent_timeout": "Max seconds for agent execution (default: 1740 / 29 min)",
    "notifications_enabled": "Show Rich panel notifications for key events",
    "stealth_mode": "Enable advanced stealth and command argument evasion",
    "persona": "Active persona name (default: auto)",
    "command_review": "Prompt before executing raw shell commands (default: true)",
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
                import tomli  # pyright: ignore[reportMissingImports]  # third-party

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
        "# Siyarix Settings\n# Edit directly or use: siyarix config set <key> <value>\n"
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
    """TOML-backed settings manager for the Siyarix CLI.

    All reads fall back to DEFAULTS when a key is not set.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _SETTINGS_FILE
        self._data: dict[str, Any] = {**DEFAULTS, **_try_load_toml(self._path)}
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        for env_key, config_key in _ENV_TO_CONFIG.items():
            val = os.getenv(env_key)
            if val is not None:
                if config_key in ("_no_telemetry", "_safe_mode"):
                    self._data[config_key] = val.lower() in ("1", "true", "yes")
                elif config_key == "log_level":
                    self._data[config_key] = val.lower()
                elif config_key == "scan_timeout":
                    try:
                        self._data[config_key] = int(val)
                    except ValueError:
                        pass
                elif config_key in ("model_provider", "persona"):
                    self._data[config_key] = val
                elif config_key == "_config_path":
                    self._data[config_key] = str(Path(val).expanduser().resolve())
                elif config_key == "_home_dir":
                    self._data[config_key] = str(Path(val).expanduser().resolve())

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Return value for *key* or *default* if set, else DEFAULTS[key]."""
        if key in self._data:
            return self._data[key]
        if default is not None:
            return default
        if key not in DEFAULTS:
            raise KeyError(
                f"Unknown setting: '{key}'. Run 'config list' to see valid keys."
            )
        return DEFAULTS[key]

    def set(self, key: str, value: Any) -> Any:
        """Set *key* to *value* (string input is coerced to the correct type)."""
        if key not in DEFAULTS:
            raise KeyError(
                f"Unknown setting: '{key}'. Run 'config list' to see valid keys."
            )
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
        import shlex

        default_editor = (
            "notepad.exe" if _platform.system().lower() == "windows" else "nano"
        )
        editor = os.getenv("EDITOR", default_editor)
        editor_cmd = shlex.split(editor) if _platform.system().lower() == "windows" else [editor]
        try:
            safe_run_sync(editor_cmd + [str(self._path)], timeout=0)
        except Exception:
            logger.exception(
                "Opening editor failed with safe_run_sync for editor=%s path=%s",
                editor,
                self._path,
            )
            try:
                import subprocess
                subprocess.run(  # nosec B603
                    editor_cmd + [str(self._path)],
                    capture_output=False,
                    timeout=30,
                )
            except Exception as inner:
                logger.error("Fallback editor launch failed: %s", inner)
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

    def backup(self) -> Path | None:
        """Backup current config to timestamped file. Returns backup path or None."""
        if not self._path.exists():
            return None
        from datetime import datetime
        backup_dir = self._path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"settings_{ts}.toml"
        try:
            import shutil
            shutil.copy2(self._path, backup_path)
            logger.info("Config backed up to %s", backup_path)
            return backup_path
        except OSError as exc:
            logger.warning("Config backup failed: %s", exc)
            return None

    def _save(self) -> None:
        # Backup previous config (keep last 5)
        if self._path.exists():
            self.backup()
        _write_toml(self._path, self._data)
        self._cleanup_old_backups(5)

    def _cleanup_old_backups(self, keep: int = 5) -> None:
        """Remove oldest backups beyond keep count."""
        backup_dir = self._path.parent / "backups"
        if not backup_dir.exists():
            return
        backups = sorted(backup_dir.glob("settings_*.toml"))
        for old in backups[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass

    @classmethod
    def restore_latest(cls) -> Path | None:
        """Restore from latest backup. Returns restored path or None."""
        backup_dir = _CONFIG_DIR / "backups"
        if not backup_dir.exists():
            return None
        backups = sorted(backup_dir.glob("settings_*.toml"))
        if not backups:
            return None
        latest = backups[-1]
        try:
            import shutil
            shutil.copy2(latest, _SETTINGS_FILE)
            logger.info("Config restored from %s", latest)
            return _SETTINGS_FILE
        except OSError as exc:
            logger.warning("Config restore failed: %s", exc)
            return None
