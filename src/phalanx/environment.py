"""Helpers for Siyarix environment file management."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE_FILE = PROJECT_ROOT / ".env.example"

PROVIDER_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "cloud": "SIYARIX_API_KEY",
    "siyarix": "SIYARIX_API_KEY",
}

_KEY_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def ensure_env_file(path: Path | None = None) -> Path:
    """Ensure a writable .env file exists in the repo root."""
    target = path or ENV_FILE
    if target.exists():
        return target

    if ENV_EXAMPLE_FILE.exists():
        target.write_text(
            ENV_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8"
        )
    else:
        target.write_text(
            "# Siyarix environment file\n"
            "# Add your API keys here. This file is safe to edit locally.\n\n"
            "OPENAI_API_KEY=REPLACE_ME\n"
            "GEMINI_API_KEY=REPLACE_ME\n"
            "ANTHROPIC_API_KEY=REPLACE_ME\n"
            "SIYARIX_SERVER_URL=\n"
            "SIYARIX_API_KEY=\n",
            encoding="utf-8",
        )
    return target


def load_env_file(
    path: Path | None = None, *, override: bool = False
) -> dict[str, str]:
    """Load key=value pairs from .env into os.environ.

    Existing environment variables are preserved unless override=True.
    """
    target = path or ENV_FILE
    if not target.exists():
        return {}

    loaded: dict[str, str] = {}
    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _KEY_RE.match(raw_line)
        if not match:
            continue
        key, raw_value = match.groups()
        value = _strip_quotes(raw_value.strip())
        loaded[key] = value
        if value.strip().upper() in {
            "REPLACE_ME",
            "CHANGE_ME",
            "PLEASE_SET_ME",
            "TODO",
        }:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded


def upsert_env_vars(values: dict[str, str | None], path: Path | None = None) -> Path:
    """Persist selected environment variables to .env, preserving comments."""
    target = ensure_env_file(path)
    lines = target.read_text(encoding="utf-8").splitlines()

    seen: set[str] = set()
    output: list[str] = []
    for raw_line in lines:
        match = _KEY_RE.match(raw_line)
        if not match:
            output.append(raw_line)
            continue
        key = match.group(1)
        if key not in values:
            output.append(raw_line)
            continue
        seen.add(key)
        value = values[key]
        output.append(f"{key}={'' if value is None else _quote(value)}".rstrip())

    for key, value in values.items():
        if key in seen:
            continue
        output.append(f"{key}={'' if value is None else _quote(value)}".rstrip())

    target.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    return target


def key_value_or_default(values: dict[str, Any], key: str, default: str = "") -> str:
    """Helper to pull a string value from a dict safely."""
    value = values.get(key, default)
    return value if isinstance(value, str) else str(value)


def provider_env_var(provider: str) -> str:
    """Map a provider name to its matching environment variable."""
    normalized = provider.strip().lower()
    return PROVIDER_ENV_VARS.get(normalized, f"{normalized.upper()}_API_KEY")
