# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix CLI — CA-2.4 Configuration Management.

Settings stored in ~/.siyarix/settings.toml — human-editable TOML format.
Provides a type-safe settings store with get/set/reset/list/edit support.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import threading
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
    "SIYARIX_EXECUTION_TIMEOUT": "scan_timeout",
    "SIYARIX_LOG_LEVEL": "log_level",
    "SIYARIX_NO_TELEMETRY": "_no_telemetry",
    "SIYARIX_SAFE_MODE": "_safe_mode",
    "SIYARIX_STEALTH": "stealth_mode",
    "SIYARIX_MODE": "default_mode",
    "SIYARIX_THEME": "color_theme",
    "SIYARIX_OUTPUT_FORMAT": "default_output_format",
    "SIYARIX_PARALLEL": "default_parallel",
    "SIYARIX_AGENT_TIMEOUT": "agent_timeout",
    "SIYARIX_TLS_VERIFY": "tls_verify",
    "SIYARIX_COMMAND_REVIEW": "command_review",
}


@dataclass
class ValidationIssue:
    """A configuration validation issue (error or warning)."""

    key: str
    message: str
    severity: str = "error"  # "error" or "warning"
    current_value: Any = None
    expected: str = ""


@dataclass
class ConfigDiffEntry:
    """Represents a difference between two configuration states."""

    key: str
    current_value: Any
    target_value: Any
    status: str  # "modified", "added", "removed", "unchanged"


@dataclass
class BackupInfo:
    """Metadata for a configuration backup."""

    name: str
    path: Path
    timestamp: str
    size_bytes: int
    key_count: int


@dataclass
class ProfileInfo:
    """Metadata for a configuration profile."""

    name: str
    path: Path
    is_active: bool
    description: str = ""


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
    "registry_url": "",
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
    "token_saver": False,
}

# Human-readable descriptions
DESCRIPTIONS: dict[str, str] = {
    "default_output_format": "Default output format: table | json | yaml | csv",
    "default_parallel": "Max tools to run in parallel during --all scans",
    "scan_timeout": "Seconds before a running tool is killed",
    "auto_sync": "Automatically sync findings to server when connected",
    "color_theme": "Terminal color theme: system | default | dark | light | minimal | neon | enterprise",
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
    "token_saver": "Optimize token usage by sending compact system prompts after the first call (default: false)",
}

CATEGORIES: dict[str, list[str]] = {
    "General": [
        "default_output_format",
        "default_parallel",
        "scan_timeout",
        "agent_timeout",
        "max_waves",
        "auto_sync",
        "notifications_enabled",
        "history_retention_days",
        "auto_update_check",
        "token_saver",
    ],
    "Appearance": [
        "color_theme",
        "syntax_theme",
        "log_level",
    ],
    "Security": [
        "stealth_mode",
        "command_review",
        "tls_verify",
    ],
    "Mode & Persona": [
        "default_mode",
        "model_provider",
        "persona",
        "additional_system_message",
    ],
    "Cloud Providers": [
        "openai_model",
        "anthropic_model",
        "gemini_model",
        "groq_model",
        "together_model",
        "openrouter_model",
        "deepseek_model",
        "xai_model",
        "mistral_model",
        "perplexity_model",
        "azure_model",
        "cerebras_model",
        "fireworks_model",
        "zai_model",
        "minimax_model",
        "moonshot_model",
        "nvidia_model",
        "opencode_zen_model",
        "huggingface_model",
    ],
    "Local Providers": [
        "ollama_url",
        "ollama_model",
        "lmstudio_url",
        "lmstudio_model",
        "llamacpp_url",
        "llamacpp_model",
        "vllm_url",
        "vllm_model",
        "localai_url",
        "localai_model",
        "_start_ollama_on_launch",
        "registry_model",
        "registry_url",
    ],
    "Terminal & System": [
        "multiline",
        "auto_save_session",
        "shell_completion_installed",
        "path_setup_done",
        "onboarding_complete",
    ],
}

# ---------------------------------------------------------------------------
# Dot Notation Resolution
# ---------------------------------------------------------------------------

SPECIAL_DOT_MAP: dict[str, str] = {
    "providers.openai.model": "openai_model",
    "providers.anthropic.model": "anthropic_model",
    "providers.gemini.model": "gemini_model",
    "providers.groq.model": "groq_model",
    "providers.together.model": "together_model",
    "providers.openrouter.model": "openrouter_model",
    "providers.deepseek.model": "deepseek_model",
    "providers.xai.model": "xai_model",
    "providers.mistral.model": "mistral_model",
    "providers.perplexity.model": "perplexity_model",
    "providers.azure.model": "azure_model",
    "providers.cerebras.model": "cerebras_model",
    "providers.fireworks.model": "fireworks_model",
    "providers.zai.model": "zai_model",
    "providers.minimax.model": "minimax_model",
    "providers.moonshot.model": "moonshot_model",
    "providers.nvidia.model": "nvidia_model",
    "providers.opencode_zen.model": "opencode_zen_model",
    "providers.huggingface.model": "huggingface_model",
    "providers.ollama.url": "ollama_url",
    "providers.ollama.model": "ollama_model",
    "providers.lmstudio.url": "lmstudio_url",
    "providers.lmstudio.model": "lmstudio_model",
    "providers.llamacpp.url": "llamacpp_url",
    "providers.llamacpp.model": "llamacpp_model",
    "providers.vllm.url": "vllm_url",
    "providers.vllm.model": "vllm_model",
    "providers.localai.url": "localai_url",
    "providers.localai.model": "localai_model",
}


def canonicalize_key(key: str) -> str:
    """Normalize a setting key, supporting dot-notation aliases.

    Examples:
        - "providers.gemini.model" -> "gemini_model"
        - "appearance.color_theme" -> "color_theme"
        - "security.stealth_mode"  -> "stealth_mode"
        - "custom.plugin.api_key"  -> "custom.plugin.api_key"
    """
    raw = key.strip()
    norm = raw.lower()
    if norm in SPECIAL_DOT_MAP:
        return SPECIAL_DOT_MAP[norm]
    if raw in DEFAULTS:
        return raw
    if norm in DEFAULTS:
        return norm

    prefixes = (
        "general.",
        "appearance.",
        "ui.",
        "security.",
        "providers.",
        "provider.",
        "ai.",
        "agent.",
        "terminal.",
    )
    for pfx in prefixes:
        if norm.startswith(pfx):
            sub = norm[len(pfx) :]
            if sub in DEFAULTS:
                return sub
    return raw


# ---------------------------------------------------------------------------
# Secret & Sensitive Value Masking
# ---------------------------------------------------------------------------

SENSITIVE_KEY_PATTERNS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "credential",
    "private",
    "webhook",
)


NON_SENSITIVE_KEYS = {"token_saver", "max_tokens", "keyboard", "key_bindings", "hotkey"}


def is_sensitive_key(key: str) -> bool:
    """Return True if the key is likely sensitive (contains token, secret, key, etc.)."""
    k = key.lower()
    if k in NON_SENSITIVE_KEYS or k.endswith("_tokens"):
        return False
    return any(p in k for p in SENSITIVE_KEY_PATTERNS)


def mask_value(key: str, value: Any, reveal: bool = False) -> Any:
    """Mask secret value unless reveal is True."""
    if not is_sensitive_key(key) or reveal or value is None:
        return value
    val_str = str(value)
    if not val_str:
        return val_str
    if len(val_str) <= 6:
        return "******"
    return f"{val_str[:3]}***...***{val_str[-3:]}"


# ---------------------------------------------------------------------------
# Validation Enums & Profile Presets
# ---------------------------------------------------------------------------

VALID_LOG_LEVELS = ("debug", "info", "warning", "error", "critical")
VALID_OUTPUT_FORMATS = ("table", "json", "yaml", "csv")
VALID_COLOR_THEMES = (
    "default",
    "dark",
    "light",
    "minimal",
    "neon",
    "system",
    "enterprise",
    "cyber-noir",
    "matrix",
    "bloodmoon",
    "arctic",
    "synthwave",
    "goldenrod",
    "eclipse",
)
VALID_MODES = (
    "interactive",
    "autonomous",
    "integrated",
    "offline",
    "hybrid",
    "stealth",
)
VALID_PERSONAS = (
    "auto",
    "pentester",
    "red_team",
    "blue_team",
    "bug_hunter",
    "ctf_player",
    "compliance_auditor",
    "malware_analyst",
    "forensics_investigator",
    "devsecops_engineer",
)

PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "default": {},
    "ctf": {
        "scan_timeout": 60,
        "agent_timeout": 600,
        "default_parallel": 6,
        "stealth_mode": False,
        "command_review": False,
        "log_level": "debug",
    },
    "stealth": {
        "stealth_mode": True,
        "command_review": True,
        "default_parallel": 1,
        "scan_timeout": 600,
        "log_level": "warning",
    },
    "offline": {
        "model_provider": "ollama",
        "tls_verify": False,
        "auto_sync": False,
        "notifications_enabled": False,
    },
    "cloud": {
        "model_provider": "gemini",
        "auto_sync": True,
    },
}


def _flatten_dict(d: dict[str, Any], parent_key: str = "") -> dict[str, Any]:
    """Flatten nested dicts into dot-separated keys, normalizing aliases."""
    items: dict[str, Any] = {}
    for k, v in d.items():
        new_key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten_dict(v, new_key))
        else:
            items[canonicalize_key(new_key)] = v
    return items


def _try_load_toml(path: Path) -> dict[str, Any]:
    """Load TOML file; returns empty dict on any error."""
    if not path.exists():
        return {}
    try:
        import tomllib  # Python 3.11+

        with path.open("rb") as f:
            raw = tomllib.load(f)
            return _flatten_dict(raw)
    except ImportError:
        try:
            import tomli

            with path.open("rb") as f:
                raw = tomli.load(f)
                return _flatten_dict(raw)
        except ImportError:
            # Fallback naive parser
            data: dict[str, Any] = {}
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip().strip("\"'")
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


def _format_toml_val(val: Any) -> str:
    """Format Python value into valid TOML representation."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(val, (list, tuple)):
        items = [_format_toml_val(item) for item in val]
        return "[" + ", ".join(items) + "]"
    if isinstance(val, dict):
        items = [f"{k} = {_format_toml_val(v)}" for k, v in sorted(val.items())]
        return "{" + ", ".join(items) + "}"
    escaped = str(val).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _write_toml(path: Path, data: dict[str, Any]) -> None:
    """Write dict as standard TOML."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Siyarix Configuration Settings",
        "# Edit directly or use: siyarix config set <key> <value>",
        "",
    ]
    for key, value in sorted(data.items()):
        desc = DESCRIPTIONS.get(key, "")
        if desc:
            lines.append(f"# {desc}")
        formatted_key = f'"{key}"' if "." in key else key
        lines.append(f"{formatted_key} = {_format_toml_val(value)}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


class SettingsStore:
    """Professional TOML-backed settings manager for Siyarix.

    Features:
    - Thread-safe RLock protection
    - Fallback to DEFAULTS when a key is not explicitly set
    - Dynamic addition, modification, and unsetting of custom keys
    - Hierarchical dot-notation aliases
    - Schema validation & secret masking
    - Environment profiles (ctf, stealth, offline, cloud, default)
    - Full backup, restore, export, and import suite

    Uses singleton pattern when initialized without arguments to prevent divergent state.
    Pass an explicit *path* to bypass singleton (ideal for unit testing).
    """

    _instance: SettingsStore | None = None
    _initialized: bool = False

    def __new__(cls, path: Path | None = None) -> SettingsStore:
        if path is not None:
            instance = super().__new__(cls)
            return instance
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, path: Path | None = None) -> None:
        if hasattr(self, "_initialized") and self._initialized and path is None:
            return  # Already initialized singleton
        self._lock = threading.RLock()
        with self._lock:
            self._path = path or get_settings_file()
            self._data: dict[str, Any] = {**DEFAULTS, **_try_load_toml(self._path)}
            self._apply_env_overrides()
            self._initialized = True

    def _apply_env_overrides(self) -> None:
        for env_key, config_key in _ENV_TO_CONFIG.items():
            val = os.getenv(env_key)
            if val is not None:
                if config_key in (
                    "_no_telemetry",
                    "_safe_mode",
                    "stealth_mode",
                    "tls_verify",
                    "command_review",
                ):
                    self._data[config_key] = val.lower() in ("1", "true", "yes", "on")
                elif config_key == "log_level":
                    self._data[config_key] = val.lower()
                elif config_key in ("scan_timeout", "agent_timeout", "default_parallel"):
                    try:
                        self._data[config_key] = int(val)
                    except ValueError:
                        pass
                elif config_key in (
                    "model_provider",
                    "persona",
                    "default_mode",
                    "color_theme",
                    "default_output_format",
                ):
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
        with self._lock:
            canonical = canonicalize_key(key)
            if canonical in self._data:
                return self._data[canonical]
            if default is not None:
                return default
            if canonical not in DEFAULTS:
                raise KeyError(f"Unknown setting: '{key}'. Run 'config list' to see valid keys.")
            return DEFAULTS[canonical]

    def has(self, key: str) -> bool:
        """Return True if *key* exists in settings or default schema."""
        with self._lock:
            canonical = canonicalize_key(key)
            return canonical in self._data or canonical in DEFAULTS

    def set(
        self,
        key: str,
        value: Any,
        allow_custom: bool = False,
        target_type: str | None = None,
    ) -> Any:
        """Set *key* to *value*.

        If *allow_custom* is False and *key* is not in DEFAULTS, raises KeyError.
        String input is coerced to the appropriate type and validated.
        """
        with self._lock:
            canonical = canonicalize_key(key)
            if canonical not in DEFAULTS and not allow_custom:
                raise KeyError(
                    f"Unknown setting: '{key}'. Use 'siyarix config add {key} <value>' to define a custom setting."
                )

            coerced = self._coerce(canonical, value, target_type=target_type)
            self._validate_single_value(canonical, coerced)
            self._data[canonical] = coerced
            self._save()
            return coerced

    def add(
        self,
        key: str,
        value: Any,
        value_type: str | None = None,
        description: str = "",
    ) -> Any:
        """Add or update a custom or existing configuration setting."""
        with self._lock:
            canonical = canonicalize_key(key)
            if description:
                DESCRIPTIONS[canonical] = description
            return self.set(canonical, value, allow_custom=True, target_type=value_type)

    def unset(self, key: str) -> bool:
        """Remove a custom setting or revert an existing default setting back to its factory default."""
        with self._lock:
            canonical = canonicalize_key(key)
            if canonical in self._data:
                if canonical in DEFAULTS:
                    self._data[canonical] = DEFAULTS[canonical]
                else:
                    del self._data[canonical]
                self._save()
                return True
            return False

    def reset(self, key: str | None = None) -> None:
        """Reset *key* (or all settings) to defaults."""
        with self._lock:
            if key:
                canonical = canonicalize_key(key)
                if canonical not in DEFAULTS and canonical not in self._data:
                    raise KeyError(f"Unknown setting: '{key}'.")
                if canonical in DEFAULTS:
                    self._data[canonical] = DEFAULTS[canonical]
                elif canonical in self._data:
                    del self._data[canonical]
            else:
                self._data = {**DEFAULTS}
            self._save()

    def list_all(
        self,
        category: str | None = None,
        reveal_secrets: bool = False,
        modified_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return settings as a list of dicts for display or inspection."""
        with self._lock:
            rows: list[dict[str, Any]] = []

            key_to_cat: dict[str, str] = {}
            for cat_name, keys in CATEGORIES.items():
                for k in keys:
                    key_to_cat[k] = cat_name

            all_keys = sorted(set(list(DEFAULTS.keys()) + list(self._data.keys())))

            for key in all_keys:
                if key.startswith("_") and key not in ("_start_ollama_on_launch",):
                    continue

                current = self._data.get(key, DEFAULTS.get(key, ""))
                default = DEFAULTS.get(key, "")
                is_custom = key not in DEFAULTS
                cat = key_to_cat.get(key, "Custom" if is_custom else "General")

                if category and category.lower() != cat.lower():
                    continue

                is_modified = current != default
                if modified_only and not is_modified:
                    continue

                display_val = mask_value(key, current, reveal=reveal_secrets)
                display_def = mask_value(key, default, reveal=reveal_secrets)

                rows.append(
                    {
                        "key": key,
                        "value": str(display_val),
                        "raw_value": current,
                        "default": str(display_def),
                        "description": DESCRIPTIONS.get(key, "Custom setting" if is_custom else ""),
                        "category": cat,
                        "modified": is_modified,
                        "is_custom": is_custom,
                        "is_sensitive": is_sensitive_key(key),
                    }
                )
            return rows

    # ------------------------------------------------------------------
    # Coercion & Validation
    # ------------------------------------------------------------------

    def _coerce(self, key: str, value: Any, target_type: str | None = None) -> Any:
        """Coerce input value to the expected or specified type."""
        if target_type:
            tt = target_type.lower()
            if tt in ("bool", "boolean"):
                if isinstance(value, bool):
                    return value
                return str(value).lower() in ("true", "1", "yes", "on")
            if tt in ("int", "integer"):
                if isinstance(value, int):
                    return value
                return int(value)
            if tt in ("float", "number"):
                if isinstance(value, float):
                    return value
                return float(value)
            if tt in ("list", "array"):
                if isinstance(value, (list, tuple)):
                    return list(value)
                val_str = str(value).strip()
                if val_str.startswith("[") and val_str.endswith("]"):
                    try:
                        return json.loads(val_str)
                    except json.JSONDecodeError:
                        pass
                return [x.strip() for x in val_str.split(",") if x.strip()]
            if tt in ("dict", "json"):
                if isinstance(value, dict):
                    return value
                val_str = str(value).strip()
                return json.loads(val_str)
            return str(value)

        # Infer from defaults if known
        if key in DEFAULTS:
            default = DEFAULTS[key]
            if isinstance(default, bool):
                if isinstance(value, bool):
                    return value
                return str(value).lower() in ("true", "1", "yes", "on")
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

            # Map numeric menu selections (1..N) to choice strings if provided
            if key == "color_theme" and isinstance(value, (str, int)):
                val_s = str(value).strip()
                if val_s.isdigit():
                    idx = int(val_s) - 1
                    if 0 <= idx < len(VALID_COLOR_THEMES):
                        return VALID_COLOR_THEMES[idx]
            if key == "default_output_format" and isinstance(value, (str, int)):
                val_s = str(value).strip()
                if val_s.isdigit():
                    idx = int(val_s) - 1
                    if 0 <= idx < len(VALID_OUTPUT_FORMATS):
                        return VALID_OUTPUT_FORMATS[idx]
            if key == "log_level" and isinstance(value, (str, int)):
                val_s = str(value).strip()
                if val_s.isdigit():
                    idx = int(val_s) - 1
                    if 0 <= idx < len(VALID_LOG_LEVELS):
                        return VALID_LOG_LEVELS[idx]
            if key == "default_mode" and isinstance(value, (str, int)):
                val_s = str(value).strip()
                if val_s.isdigit():
                    idx = int(val_s) - 1
                    if 0 <= idx < len(VALID_MODES):
                        return VALID_MODES[idx]

            return str(value)

        # Automatic inference for custom keys
        if isinstance(value, (bool, int, float, list, dict)):
            return value
        val_str = str(value).strip()
        if val_str.lower() in ("true", "false", "yes", "no"):
            return val_str.lower() in ("true", "yes")
        if (val_str.startswith("[") and val_str.endswith("]")) or (
            val_str.startswith("{") and val_str.endswith("}")
        ):
            try:
                return json.loads(val_str)
            except json.JSONDecodeError:
                pass
        if val_str.lstrip("-").isdigit():
            try:
                return int(val_str)
            except ValueError:
                pass
        try:
            return float(val_str)
        except ValueError:
            pass
        return val_str

    def _validate_single_value(self, key: str, value: Any) -> None:
        """Validate a single setting value against rules."""
        if key == "log_level":
            val = str(value).lower()
            if val not in VALID_LOG_LEVELS:
                raise ValueError(
                    f"Invalid log_level '{value}'. Must be one of: {', '.join(VALID_LOG_LEVELS)}"
                )
        elif key == "default_output_format":
            val = str(value).lower()
            if val not in VALID_OUTPUT_FORMATS:
                raise ValueError(
                    f"Invalid output format '{value}'. Must be one of: {', '.join(VALID_OUTPUT_FORMATS)}"
                )
        elif key == "color_theme":
            val = str(value).strip().lower()
            if not val:
                raise ValueError("Color theme cannot be empty.")
        elif key == "default_mode":
            val = str(value).lower()
            if val not in VALID_MODES:
                raise ValueError(
                    f"Invalid default mode '{value}'. Must be one of: {', '.join(VALID_MODES)}"
                )
        elif key in ("scan_timeout", "agent_timeout"):
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"'{key}' must be a positive integer, got '{value}'.")
        elif key == "default_parallel":
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"'default_parallel' must be a positive integer, got '{value}'.")
        elif key == "max_waves":
            if not isinstance(value, int) or not (1 <= value <= 100):
                raise ValueError(f"'max_waves' must be between 1 and 100, got '{value}'.")
        elif key.endswith("_url") and value:
            val_str = str(value)
            if not (val_str.startswith("http://") or val_str.startswith("https://")):
                raise ValueError(f"'{key}' must be a valid HTTP or HTTPS URL, got '{val_str}'.")

    def validate(self) -> list[ValidationIssue]:
        """Validate all current settings and return detected issues and warnings."""
        with self._lock:
            issues: list[ValidationIssue] = []

            for key, val in self._data.items():
                if key.startswith("_") and key not in ("_start_ollama_on_launch",):
                    continue
                try:
                    self._validate_single_value(key, val)
                except ValueError as err:
                    issues.append(
                        ValidationIssue(
                            key=key,
                            message=str(err),
                            severity="error",
                            current_value=val,
                        )
                    )

                # Heuristic warnings
                if key == "tls_verify" and val is False:
                    issues.append(
                        ValidationIssue(
                            key=key,
                            message="TLS verification is disabled. Network traffic is vulnerable to MITM attacks.",
                            severity="warning",
                            current_value=val,
                        )
                    )
                elif key == "scan_timeout" and isinstance(val, int) and val < 10:
                    issues.append(
                        ValidationIssue(
                            key=key,
                            message="scan_timeout is under 10 seconds. Network scans may prematurely abort.",
                            severity="warning",
                            current_value=val,
                        )
                    )
                elif key == "agent_timeout" and isinstance(val, int) and val < 60:
                    issues.append(
                        ValidationIssue(
                            key=key,
                            message="agent_timeout is under 60 seconds. Complex goals may fail to complete.",
                            severity="warning",
                            current_value=val,
                        )
                    )
                elif key == "default_parallel" and isinstance(val, int) and val > 64:
                    issues.append(
                        ValidationIssue(
                            key=key,
                            message="default_parallel is unusually high (>64). This may exhaust system resources or trigger rate limits.",
                            severity="warning",
                            current_value=val,
                        )
                    )
            return issues

    # ------------------------------------------------------------------
    # Diffing
    # ------------------------------------------------------------------

    def diff(self, against: str = "defaults") -> list[ConfigDiffEntry]:
        """Compare current settings against defaults, a profile, or another source."""
        with self._lock:
            target_data: dict[str, Any] = {}
            if against == "defaults":
                target_data = dict(DEFAULTS)
            elif against.startswith("profile:"):
                pname = against.split(":", 1)[1]
                prof_file = get_config_dir() / "profiles" / f"{pname}.toml"
                if prof_file.exists():
                    target_data = {**DEFAULTS, **_try_load_toml(prof_file)}
                elif pname in PROFILE_PRESETS:
                    target_data = {**DEFAULTS, **PROFILE_PRESETS[pname]}
                else:
                    raise KeyError(f"Profile '{pname}' not found.")
            elif against.startswith("backup:"):
                bname = against.split(":", 1)[1]
                bpath = get_config_dir() / "backups" / bname
                if bpath.exists():
                    target_data = _try_load_toml(bpath)
                else:
                    raise FileNotFoundError(f"Backup '{bname}' not found.")
            else:
                target_data = dict(DEFAULTS)

            entries: list[ConfigDiffEntry] = []
            all_keys = sorted(set(list(self._data.keys()) + list(target_data.keys())))
            for k in all_keys:
                if k.startswith("_") and k not in ("_start_ollama_on_launch",):
                    continue
                cur = self._data.get(k)
                tgt = target_data.get(k)
                if k not in target_data:
                    entries.append(
                        ConfigDiffEntry(
                            key=k,
                            current_value=cur,
                            target_value=None,
                            status="added",
                        )
                    )
                elif k not in self._data:
                    entries.append(
                        ConfigDiffEntry(
                            key=k,
                            current_value=None,
                            target_value=tgt,
                            status="removed",
                        )
                    )
                elif cur != tgt:
                    entries.append(
                        ConfigDiffEntry(
                            key=k,
                            current_value=cur,
                            target_value=tgt,
                            status="modified",
                        )
                    )
            return entries

    # ------------------------------------------------------------------
    # Export & Import
    # ------------------------------------------------------------------

    def export_config(
        self,
        format: str = "toml",
        reveal_secrets: bool = False,
        custom_only: bool = False,
    ) -> str:
        """Export configuration as a serialized string (TOML, JSON, or YAML)."""
        with self._lock:
            export_data: dict[str, Any] = {}
            for k, v in self._data.items():
                if k.startswith("_") and k not in ("_start_ollama_on_launch",):
                    continue
                if custom_only and k in DEFAULTS and v == DEFAULTS[k]:
                    continue
                export_data[k] = v if reveal_secrets else mask_value(k, v)

            fmt = format.lower()
            if fmt == "json":
                return json.dumps(export_data, indent=2)
            if fmt == "yaml":
                try:
                    import yaml  # type: ignore[import-untyped]

                    return str(yaml.dump(export_data, default_flow_style=False, sort_keys=True))
                except ImportError:
                    pass
                lines = []
                for k, v in sorted(export_data.items()):
                    lines.append(f"{k}: {json.dumps(v)}")
                return "\n".join(lines)

            # Default to TOML
            lines = ["# Siyarix Configuration Export"]
            for k, v in sorted(export_data.items()):
                lines.append(f"{k} = {_format_toml_val(v)}")
            return "\n".join(lines)

    def import_config(self, file_or_content: str | Path, merge: bool = True) -> int:
        """Import configuration from a file path or raw string.

        Supports TOML, JSON, or YAML formats.
        Returns the number of imported keys.
        """
        with self._lock:
            raw_data: dict[str, Any] = {}
            content = ""
            p = Path(file_or_content) if isinstance(file_or_content, Path) else None
            if p and p.exists():
                content = p.read_text(encoding="utf-8")
            elif isinstance(file_or_content, str) and Path(file_or_content).exists():
                content = Path(file_or_content).read_text(encoding="utf-8")
            else:
                content = str(file_or_content)

            content = content.strip()
            # Attempt JSON
            if (content.startswith("{") and content.endswith("}")) or (
                content.startswith("[") and content.endswith("]")
            ):
                try:
                    raw_data = json.loads(content)
                except json.JSONDecodeError:
                    pass

            # Attempt YAML
            if not raw_data:
                try:
                    import yaml

                    loaded = yaml.safe_load(content)
                    if isinstance(loaded, dict):
                        raw_data = loaded
                except Exception:
                    pass

            # Attempt TOML
            if not raw_data:
                try:
                    import tomllib

                    raw_data = tomllib.loads(content)
                except Exception:
                    try:
                        import tomli

                        raw_data = tomli.loads(content)
                    except Exception:
                        pass

            if not raw_data:
                raise ValueError("Could not parse configuration content as TOML, JSON, or YAML.")

            count = 0
            if not merge:
                self._data = {**DEFAULTS}

            for k, v in raw_data.items():
                canonical = canonicalize_key(k)
                coerced = self._coerce(canonical, v)
                self._data[canonical] = coerced
                count += 1

            self._save()
            return count

    # ------------------------------------------------------------------
    # Profile Management
    # ------------------------------------------------------------------

    def _get_profiles_dir(self) -> Path:
        p = get_config_dir() / "profiles"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_active_profile(self) -> str:
        """Return the name of the currently active profile."""
        with self._lock:
            pf = get_config_dir() / "active_profile"
            if pf.exists():
                name = pf.read_text(encoding="utf-8").strip()
                if name:
                    return name
            return "default"

    def list_profiles(self) -> list[ProfileInfo]:
        """List all available profiles (presets and user-created)."""
        with self._lock:
            active = self.get_active_profile()
            prof_dir = self._get_profiles_dir()
            names = set(PROFILE_PRESETS.keys())
            for f in prof_dir.glob("*.toml"):
                names.add(f.stem)

            profiles: list[ProfileInfo] = []
            for name in sorted(names):
                fpath = prof_dir / f"{name}.toml"
                desc = ""
                if name == "default":
                    desc = "Standard default configuration"
                elif name == "ctf":
                    desc = "Aggressive, fast scan timeouts, debug logging"
                elif name == "stealth":
                    desc = "High OPSEC evasion, manual command review, quiet parallel"
                elif name == "offline":
                    desc = "Local LLM (Ollama/vLLM), no cloud sync, air-gapped"
                elif name == "cloud":
                    desc = "Cloud AI models (Gemini/Claude/GPT) with server sync"

                profiles.append(
                    ProfileInfo(
                        name=name,
                        path=fpath,
                        is_active=(name == active),
                        description=desc,
                    )
                )
            return profiles

    def switch_profile(self, name: str) -> bool:
        """Switch active profile, saving current state and loading target profile."""
        with self._lock:
            target = name.strip().lower()
            current = self.get_active_profile()
            if target == current:
                return True

            prof_dir = self._get_profiles_dir()

            # Save current state into profiles/<current>.toml
            cur_path = prof_dir / f"{current}.toml"
            _write_toml(cur_path, self._data)

            # Load target profile
            target_path = prof_dir / f"{target}.toml"
            new_data: dict[str, Any] = {**DEFAULTS}
            if target in PROFILE_PRESETS:
                new_data.update(PROFILE_PRESETS[target])
            if target_path.exists():
                new_data.update(_try_load_toml(target_path))

            self._data = new_data
            self._save()

            active_file = get_config_dir() / "active_profile"
            active_file.write_text(target, encoding="utf-8")
            logger.info("Switched configuration profile from '%s' to '%s'", current, target)
            return True

    def create_profile(self, name: str, from_profile: str | None = None) -> bool:
        """Create a new profile based on current settings or an existing profile."""
        with self._lock:
            clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "", name.strip().lower())
            if not clean_name:
                raise ValueError("Invalid profile name.")

            prof_dir = self._get_profiles_dir()
            target_path = prof_dir / f"{clean_name}.toml"

            base_data: dict[str, Any] = {}
            if from_profile:
                src_prof = from_profile.strip().lower()
                src_path = prof_dir / f"{src_prof}.toml"
                if src_path.exists():
                    base_data = _try_load_toml(src_path)
                elif src_prof in PROFILE_PRESETS:
                    base_data = {**DEFAULTS, **PROFILE_PRESETS[src_prof]}
                else:
                    raise KeyError(f"Source profile '{from_profile}' does not exist.")
            else:
                base_data = dict(self._data)

            _write_toml(target_path, base_data)
            return True

    def delete_profile(self, name: str) -> bool:
        """Delete an existing profile (cannot delete active profile or 'default')."""
        with self._lock:
            target = name.strip().lower()
            active = self.get_active_profile()
            if target in ("default", active):
                raise ValueError(f"Cannot delete active or default profile '{target}'.")
            target_path = self._get_profiles_dir() / f"{target}.toml"
            if target_path.exists():
                target_path.unlink()
                return True
            return False

    # ------------------------------------------------------------------
    # Backups & Restoration
    # ------------------------------------------------------------------

    def backup(self) -> Path | None:
        """Backup current config to timestamped file. Returns backup path or None."""
        if not self._path.exists():
            return None
        backup_dir = self._path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"settings_{ts}.toml"
        try:
            shutil.copy2(self._path, backup_path)
            logger.info("Config backed up to %s", backup_path)
            return backup_path
        except OSError as exc:
            logger.warning("Config backup failed: %s", exc)
            return None

    def list_backups(self) -> list[BackupInfo]:
        """List all existing timestamped backups."""
        with self._lock:
            backup_dir = self._path.parent / "backups"
            if not backup_dir.exists():
                return []
            backups: list[BackupInfo] = []
            for bp in sorted(backup_dir.glob("settings_*.toml"), reverse=True):
                stat = bp.stat()
                ts = bp.stem.replace("settings_", "")
                data = _try_load_toml(bp)
                backups.append(
                    BackupInfo(
                        name=bp.name,
                        path=bp,
                        timestamp=ts,
                        size_bytes=stat.st_size,
                        key_count=len(data),
                    )
                )
            return backups

    def restore_backup(self, identifier: str | int = -1) -> Path | None:
        """Restore configuration from a specific backup name or index (-1 for latest)."""
        with self._lock:
            backups = self.list_backups()
            if not backups:
                return None

            selected: BackupInfo | None = None
            if isinstance(identifier, int):
                try:
                    selected = backups[identifier]
                except IndexError:
                    return None
            else:
                for b in backups:
                    if b.name == identifier or b.timestamp == identifier:
                        selected = b
                        break

            if not selected:
                return None

            try:
                shutil.copy2(selected.path, self._path)
                self._data = {**DEFAULTS, **_try_load_toml(self._path)}
                logger.info("Restored configuration from %s", selected.path)
                return self._path
            except OSError as exc:
                logger.warning("Restore from %s failed: %s", selected.path, exc)
                return None

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
            settings_file = get_settings_file()
            shutil.copy2(latest, settings_file)
            logger.info("Config restored from %s", latest)
            return settings_file
        except OSError as exc:
            logger.warning("Config restore failed: %s", exc)
            return None

    def _save(self) -> None:
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
        backup_dir = self._path.parent / "backups"
        if not backup_dir.exists():
            return
        backups = sorted(backup_dir.glob("settings_*.toml"))
        for old in backups[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass

    def edit(self) -> None:
        """Open settings file in $EDITOR."""
        self._save()
        from ._platform import get_platform_id, get_termux_prefix, is_windows

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
        self._data = {**DEFAULTS, **_try_load_toml(self._path)}


__all__ = [
    "DEFAULTS",
    "DESCRIPTIONS",
    "CATEGORIES",
    "PROFILE_PRESETS",
    "ValidationIssue",
    "ConfigDiffEntry",
    "BackupInfo",
    "ProfileInfo",
    "get_config_dir",
    "get_settings_file",
    "canonicalize_key",
    "is_sensitive_key",
    "mask_value",
    "SettingsStore",
]
