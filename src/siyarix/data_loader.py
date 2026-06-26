"""Data loader for Siyarix prompts, personas, rules, and UI messages.

Loads from user directory first (~/.siyarix/data/), falls back to
built-in package data (src/siyarix/data/). This enables users to
customise prompts, add custom personas, and modify rules without
editing package files (which get overwritten on upgrade).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .config import get_config_dir

logger = logging.getLogger(__name__)


def _get_user_data_dir() -> Path:
    """Return the user's Siyarix data directory (~/.siyarix/data/)."""
    return get_config_dir() / "data"


def _get_builtin_data_dir() -> Path:
    """Return the built-in package data directory."""
    return Path(__file__).parent / "data"


def load_text(category: str, filename: str) -> str:
    """Load text content from a data file.

    Tries user directory first (~/.siyarix/data/<category>/<filename>),
    falls back to built-in package data (src/siyarix/data/<category>/<filename>).

    Returns the file content as a string, or raises FileNotFoundError.
    """
    path = _resolve_path(category, filename)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(
            f"Data file not found: {category}/{filename} "
            f"(tried user and built-in paths)"
        ) from exc


def load_json(category: str, filename: str) -> Any:
    """Load and parse JSON from a data file.

    Tries user directory first, falls back to built-in.
    Returns the parsed JSON data.
    """
    content = load_text(category, filename)
    return json.loads(content)


def file_exists(category: str, filename: str) -> bool:
    """Check if a data file exists in either user or built-in directory."""
    try:
        _resolve_path(category, filename)
        return True
    except FileNotFoundError:
        return False


def list_files(category: str, pattern: str = "*") -> list[Path]:
    """List files in a data category, merging user and built-in directories.

    User files take precedence (if a file exists in both, the user version
    is returned and the built-in version is omitted).
    """
    files: list[Path] = []
    seen: set[str] = set()

    for base in (_get_user_data_dir(), _get_builtin_data_dir()):
        target = base / category
        if not target.is_dir():
            continue
        for f in sorted(target.glob(pattern)):
            if f.name not in seen:
                files.append(f)
                seen.add(f.name)

    return files


def list_custom_personas() -> list[dict[str, Any]]:
    """List custom personas from ~/.siyarix/data/personas/custom/.

    Each custom persona is defined by a JSON file with fields:
    name, label, description, prompt.

    Returns a list of persona dicts (empty list if no custom personas).
    """
    custom_dir = _get_user_data_dir() / "personas" / "custom"
    if not custom_dir.is_dir():
        return []

    personas: list[dict[str, Any]] = []
    for f in sorted(custom_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if all(k in data for k in ("name", "label", "prompt")):
                personas.append(data)
            else:
                logger.warning(
                    "Custom persona file %s missing required fields "
                    "(name, label, prompt)", f.name
                )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load custom persona %s: %s", f.name, exc)

    return personas


def _resolve_path(category: str, filename: str) -> Path:
    """Resolve a data file path, checking user dir first, built-in second.

    Returns the first existing Path, or raises FileNotFoundError.
    """
    user_path = _get_user_data_dir() / category / filename
    if user_path.is_file():
        return user_path

    builtin_path = _get_builtin_data_dir() / category / filename
    if builtin_path.is_file():
        return builtin_path

    raise FileNotFoundError(
        f"Data file not found: {category}/{filename} "
        f"(checked {user_path} and {builtin_path})"
    )


__all__ = [
    "load_text",
    "load_json",
    "file_exists",
    "list_files",
    "list_custom_personas",
]
