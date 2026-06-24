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


def get_config_dir() -> Path:
    """Return the canonical config directory (~/.siyarix or $SIYARIX_CONFIG_DIR)."""
    p_str = os.getenv("SIYARIX_CONFIG_DIR") or os.getenv("SIYARIX_HOME")
    if p_str:
        p = Path(p_str).expanduser().resolve()
    else:
        p = Path.home() / ".siyarix"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_settings_file() -> Path:
    """Return the canonical settings.toml file path."""
    return get_config_dir() / "settings.toml"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, Any] = {
    "default_output_format": "table",
    "default_parallel": 3,
    "scan_timeout": 300,
    "auto_sync": True,
    "color_theme": "default",
    "syntax_theme": "monokai",
    "log_level": "warning",
    "tls_verify": True,
    "onboarding_complete": False,
    "model_provider": "auto",
    # Cloud provider models
    "openai_model": "gpt-4o",
    "anthropic_model": "claude-sonnet-4-20250514",
    "gemini_model": "gemini-2.5-flash",
    "groq_model": "llama-3.3-70b-versatile",
    "together_model": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
    "openrouter_model": "openai/gpt-4o",
    # New providers
    "deepseek_model": "deepseek-chat",
    "xai_model": "grok-2-1212",
    "mistral_model": "mistral-large-2407",
    "perplexity_model": "sonar-pro",
    "azure_model": "gpt-4o",
    # New cloud providers
    "cerebras_model": "llama3.1-70b",
    "fireworks_model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "zai_model": "glm-4",
    "minimax_model": "MiniMax-Text-01",
    "moonshot_model": "moonshot-v1-8k",
    "nvidia_model": "nvidia/llama-3.1-nv-70b",
    "opencode_zen_model": "deepseek-chat",
    "huggingface_model": "",
    # Local provider config
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.1",
    "lmstudio_url": "http://localhost:1234",
    "lmstudio_model": "",
    "llamacpp_url": "http://localhost:18080",
    "llamacpp_model": "",
    "vllm_url": "http://localhost:8000",
    "vllm_model": "",
    "localai_url": "http://localhost:8080",
    "localai_model": "",
    "registry_model": "",
    "_start_ollama_on_launch": False,
    # Shell & PATH
    "shell_completion_installed": False,
    "path_setup_done": False,
    # Update
    "auto_update_check": True,
    # Agent settings
    "agent_timeout": 1740,
    "default_mode": "integrated",
    "stealth_mode": False,
    "persona": "auto",
    "command_review": False,
    "additional_system_message": "",
    "max_waves": 25,
    "notifications_enabled": True,
    "history_retention_days": 90,
    "multiline": False,
    "auto_save_session": False,
}

# Human-readable descriptions
DESCRIPTIONS: dict[str, str] = {
    "default_output_format": "Default output format: table | json | yaml | csv",
    "default_parallel": "Max tools to run in parallel during --all scans",
    "scan_timeout": "Seconds before a running tool is killed",
    "auto_sync": "Automatically sync findings to server when connected",
    "color_theme": "Terminal color theme: system | default | dark | light | minimal | neon",
    "syntax_theme": "Code syntax highlighting theme (monokai, dracula, etc.)",
    "log_level": "Logging verbosity: debug | info | warning | error",
    "tls_verify": "Verify TLS certificates on HTTPS requests",
    "model_provider": "Preferred model provider: auto | openai | gemini | anthropic | groq | together | openrouter | deepseek | xai | mistral | perplexity | cerebras | fireworks | zai | minimax | moonshot | nvidia | opencode-zen | huggingface | azure | ollama | lmstudio | llamacpp | vllm | localai",
    "openai_model": "OpenAI model name (default: gpt-4o)",
    "anthropic_model": "Anthropic/Claude model name (default: claude-sonnet-4-20250514)",
    "gemini_model": "Gemini model name (default: gemini-2.5-flash)",
    "groq_model": "Groq model name (default: llama-3.3-70b-versatile)",
    "together_model": "Together AI model name (default: meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo)",
    "openrouter_model": "OpenRouter model name (default: openai/gpt-4o)",
    "deepseek_model": "DeepSeek model name (default: deepseek-chat)",
    "xai_model": "xAI/Grok model name (default: grok-2-1212)",
    "mistral_model": "Mistral AI model name (default: mistral-large-2407)",
    "perplexity_model": "Perplexity model name (default: sonar-pro)",
    "azure_model": "Azure OpenAI model name (default: gpt-4o)",
    "cerebras_model": "Cerebras model name (default: llama3.1-70b)",
    "fireworks_model": "Fireworks AI model name (default: accounts/fireworks/models/llama-v3p1-70b-instruct)",
    "zai_model": "Z.AI model name (default: glm-4)",
    "minimax_model": "MiniMax model name (default: MiniMax-Text-01)",
    "moonshot_model": "Moonshot/Kimi model name (default: moonshot-v1-8k)",
    "nvidia_model": "NVIDIA model name (default: nvidia/llama-3.1-nv-70b)",
    "opencode_zen_model": "OpenCode Zen model name (default: deepseek-chat)",
    "huggingface_model": "Hugging Face model name (default: empty for server default)",
    "ollama_url": "Ollama server URL (default: http://localhost:11434)",
    "ollama_model": "Ollama model name (default: llama3.1)",
    "lmstudio_url": "LM Studio server URL (default: http://localhost:1234)",
    "lmstudio_model": "LM Studio model name (default: empty for auto-detect)",
    "llamacpp_url": "llama.cpp server URL (default: http://localhost:18080)",
    "llamacpp_model": "llama.cpp model name (default: empty for server default)",
    "vllm_url": "vLLM server URL (default: http://localhost:8000)",
    "vllm_model": "vLLM model name (default: empty for server default)",
    "localai_url": "LocalAI server URL (default: http://localhost:8080)",
    "localai_model": "LocalAI model name (default: empty for server default)",
    "registry_model": "Offline/registry mode model name (unused — present for key consistency)",
    "max_waves": "Max plan-execute-measure cycles per goal (reduce for faster responses)",
    "agent_timeout": "Max seconds for agent execution (default: 1740 / 29 min)",
    "stealth_mode": "Enable advanced stealth and command argument evasion",
    "persona": "Active persona name (default: auto)",
    "command_review": "Prompt before executing raw shell commands (default: false)",
    "notifications_enabled": "Enable Slack/Discord notifications for key events (default: true)",
    "history_retention_days": "Days to retain command history (0 = forever, default: 90)",
    "multiline": "Enable multiline input mode (Enter=newline, Alt+Enter=submit)",
    "auto_save_session": "Auto-save session logs on exit (default: false — no footprint)",
}


def _try_load_toml(path: Path) -> dict[str, Any]:
    """Load TOML file; returns empty dict on any error."""
    if not path.exists():
        return {}
    try:
        import tomllib  # Python 3.11+

        with path.open("rb") as f:
            return tomllib.load(f)
    except ImportError:
        try:
            import tomli  # type: ignore

            with path.open("rb") as f:
                return tomli.load(f)
        except ImportError:
            # Fallback naive parser
            data: dict[str, Any] = {}
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    if val == "true":
                        data[key] = True
                    elif val == "false":
                        data[key] = False
                    elif val.startswith('"') and val.endswith('"'):
                        data[key] = val[1:-1]
                    else:
                        try:
                            if "." in val:
                                data[key] = float(val)
                            else:
                                data[key] = int(val)
                        except ValueError:
                            data[key] = val
                return data
            except Exception as e:
                logger.exception("Failed to parse TOML file %s: %s", path, e)
                return {}
    except Exception as exc:
        logger.exception("Failed to parse TOML file %s: %s", path, exc)
        return {}


def _write_toml(path: Path, data: dict[str, Any]) -> None:
    """Write dict as TOML (simple key = value format)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Siyarix Settings\n# Edit directly or use: siyarix config set <key> <value>\n"]
    for key, value in sorted(data.items()):
        desc = DESCRIPTIONS.get(key, "")
        if desc:
            lines.append(f"# {desc}")
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
        else:
            lines.append(f"{key} = {value}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


class SettingsStore:
    """TOML-backed settings manager for the Siyarix CLI.

    All reads fall back to DEFAULTS when a key is not set.

    Uses singleton pattern to prevent divergent in-memory state.
    Pass an explicit *path* to bypass the singleton (useful for tests).
    """

    _instance: SettingsStore | None = None

    def __new__(cls, path: Path | None = None) -> SettingsStore:
        if path is not None:
            # Explicit path bypasses singleton (for testing)
            instance = super().__new__(cls)
            return instance
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, path: Path | None = None) -> None:
        if hasattr(self, "_initialized") and self._initialized and path is None:
            return  # Already initialized singleton
        self._path = path or get_settings_file()
        self._data: dict[str, Any] = {**DEFAULTS, **_try_load_toml(self._path)}
        self._apply_env_overrides()
        self._initialized = True

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
            raise KeyError(f"Unknown setting: '{key}'. Run 'config list' to see valid keys.")
        return DEFAULTS[key]

    def set(self, key: str, value: Any) -> Any:
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
        from ._platform import is_windows, get_platform_id, get_termux_prefix

        is_win = is_windows()
        pid = get_platform_id()
        if is_win:
            default_editor = "notepad.exe"
        elif pid == "android":
            default_editor = f"{get_termux_prefix()}/bin/nano"
        elif pid == "ios":
            default_editor = "vi"
        else:
            default_editor = "nano"
        editor = os.getenv("EDITOR", default_editor)
        if is_win:
            editor_cmd = [editor]
        else:
            import shlex
            editor_cmd = shlex.split(editor)
        try:
            safe_run_sync(editor_cmd + [str(self._path)], timeout=3600)
        except Exception:
            logger.exception(
                "Opening editor failed with safe_run_sync for editor=%s path=%s",
                editor,
                self._path,
            )
        # Reload after editing
        self._data = {**DEFAULTS, **_try_load_toml(self._path)}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _coerce(self, key: str, value: str) -> Any:
        """Coerce string input to the expected type for *key*."""
        default = DEFAULTS[key]
        if isinstance(default, bool):
            if isinstance(value, bool):
                return value
            return value.lower() in ("true", "1", "yes", "on")
        if isinstance(default, int):
            if isinstance(value, int):
                return value
            try:
                return int(value)
            except ValueError as exc:
                raise ValueError(f"'{key}' expects an integer, got '{value}'.") from exc
        if isinstance(default, float):
            if isinstance(value, float):
                return value
            try:
                return float(value)
            except ValueError as exc:
                raise ValueError(f"'{key}' expects a number, got '{value}'.") from exc
        return value  # string

    def backup(self) -> Path | None:
        """Backup current config to timestamped file. Returns backup path or None."""
        if not self._path.exists():
            return None
        from datetime import datetime, timezone

        backup_dir = self._path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
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
            try:
                old_data = _try_load_toml(self._path)
                if old_data != self._data:
                    self.backup()
            except Exception:
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
        backup_dir = get_config_dir() / "backups"
        if not backup_dir.exists():
            return None
        backups = sorted(backup_dir.glob("settings_*.toml"))
        if not backups:
            return None
        latest = backups[-1]
        try:
            import shutil

            settings_file = get_settings_file()
            shutil.copy2(latest, settings_file)
            logger.info("Config restored from %s", latest)
            return settings_file
        except OSError as exc:
            logger.warning("Config restore failed: %s", exc)
            return None


__all__ = [
    "get_config_dir",
    "get_settings_file",
    "SettingsStore",
]
