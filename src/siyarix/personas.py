"""Persona/mindset definitions for Siyarix.

Personas are defined in external files under data/personas/ and
optionally customised by the user via ~/.siyarix/data/personas/custom/.
Each persona is a short paragraph prepended to the system prompt to shape
the LLM's tone, priorities, and analytical lens.
"""

from __future__ import annotations

from typing import Any

from .data_loader import list_custom_personas, load_json, load_text


def _load_personas() -> dict[str, dict[str, Any]]:
    """Load all personas from external data files (built-in + custom)."""
    personas: dict[str, dict[str, Any]] = {}

    # 1. Special modes (always available, never from external files)
    personas["auto"] = {
        "name": "auto",
        "label": "Auto (Smart Select)",
        "description": "Analyse the request and choose the best-fit persona automatically",
        "prompt": "",
    }
    personas["none"] = {
        "name": "none",
        "label": "None",
        "description": "No persona framing — the LLM decides its own voice",
        "prompt": "",
    }

    # 2. Built-in personas from data/personas/index.json + .md files
    try:
        index = load_json("personas", "index.json")
    except FileNotFoundError:
        index = {}

    for name, meta in index.items():
        prompt_file = meta.get("file", "")
        prompt_text = ""
        if prompt_file:
            try:
                prompt_text = load_text("personas", prompt_file).strip()
            except FileNotFoundError:
                prompt_text = ""
        personas[name] = {
            "name": meta.get("name", name),
            "label": meta.get("label", name),
            "description": meta.get("description", ""),
            "prompt": prompt_text,
        }

    # 3. Custom personas from ~/.siyarix/data/personas/custom/
    for cp in list_custom_personas():
        name = cp["name"]
        personas[name] = {
            "name": cp["name"],
            "label": cp.get("label", name),
            "description": cp.get("description", ""),
            "prompt": cp["prompt"],
        }

    return personas


# Cache for loaded personas (cleared on /persona reload if implemented)
_PERSONAS_CACHE: dict[str, dict[str, Any]] | None = None


def _get_personas() -> dict[str, dict[str, Any]]:
    global _PERSONAS_CACHE
    if _PERSONAS_CACHE is None:
        _PERSONAS_CACHE = _load_personas()
    return _PERSONAS_CACHE


def reload_personas() -> None:
    """Force reload of all personas from external files (for live update)."""
    global _PERSONAS_CACHE
    _PERSONAS_CACHE = _load_personas()


def _normalize_persona_key(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", "").replace("_", "")


def get_persona(name: str) -> dict[str, Any] | None:
    """Return the persona dict for *name*, or ``None`` if not found."""
    p = _get_personas().get(name)
    if p:
        return p
    norm = _normalize_persona_key(name)
    for key, val in _get_personas().items():
        if _normalize_persona_key(key) == norm:
            return val
    return None


def list_personas() -> list[dict[str, Any]]:
    """Return all standard named personas (excluding special modes auto/none)."""
    return [p for name, p in _get_personas().items() if name not in ("auto", "none", "universal")]


def list_all_personas() -> list[dict[str, Any]]:
    """Return every persona (including auto, none, universal, and custom)."""
    return list(_get_personas().values())


def get_all_personas() -> dict[str, dict[str, Any]]:
    """Return the full personas dict (keyed by name).

    Returns a copy so callers can safely iterate without affecting the cache.
    """
    return dict(_get_personas())


def build_persona_prompt(persona_name: str) -> str:
    """Return the persona preamble to prepend to the system prompt.

    For ``auto``: include all persona descriptions and instruct the LLM to choose.
    For ``none``: no persona framing — return empty string.
    For named personas: return that persona's prompt paragraph.
    """
    p = get_persona(persona_name)
    if not p or persona_name == "none":
        return ""

    if persona_name == "auto":
        lines = ["<PERSONA>"]
        lines.append("## Active Persona: Auto (Smart Select)")
        lines.append(
            "Analyse the user's request below and automatically adopt the persona "
            "that best fits the task. Available personas:"
        )
        for name, pp in _get_personas().items():
            if name not in ("auto", "none"):
                lines.append(f"  - **{pp['label']}**: {pp['description']}")
        lines.append(
            "\nAfter selecting the persona, respond with the appropriate expertise, "
            "methodology, tooling mindset, and operational cadence for that role."
        )
        lines.append("</PERSONA>")
        return "\n".join(lines)

    return f"<PERSONA>\nName: {p['label']}\n\n{p['prompt']}\n</PERSONA>"


__all__ = [
    "get_persona",
    "get_all_personas",
    "list_personas",
    "list_all_personas",
    "build_persona_prompt",
    "reload_personas",
]
