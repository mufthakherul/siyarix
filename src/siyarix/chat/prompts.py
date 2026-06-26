"""System prompt templates and UI prompt components for Siyarix chat.

Prompts are loaded from external files under data/prompts/ (with user overrides
in ~/.siyarix/data/prompts/) rather than being hardcoded in Python. The UI
rendering functions remain here as they are presentation logic.
"""

from __future__ import annotations

import sys
import platform as _platform

from rich.text import Text
from rich.console import RenderableType

from ..data_loader import load_text, load_json

# ── Mode colour map ───────────────────────────────────────────────────────

_MODE_COLORS_DATA: dict[str, str] | None = None


def _get_mode_colors() -> dict[str, str]:
    global _MODE_COLORS_DATA
    if _MODE_COLORS_DATA is None:
        try:
            ui_data = load_json("messages", "ui.json")
            _MODE_COLORS_DATA = ui_data.get("mode_colors", {})
        except FileNotFoundError:
            _MODE_COLORS_DATA = {}
    return _MODE_COLORS_DATA


def mode_color(mode: str) -> str:
    return _get_mode_colors().get(mode, "bright_cyan")


# ── Prompt template loaders ──────────────────────────────────────────────


def load_system_prompt() -> str:
    """Load the full system prompt from external data files."""
    return load_text("prompts", "system.md")


def load_neutral_prompt() -> str:
    """Load the neutral system prompt (no persona)."""
    return load_text("prompts", "system-neutral.md")


def load_compact_prompt() -> str:
    """Load the compact prompt for follow-up calls."""
    return load_text("prompts", "compact.md")


def load_compact_neutral_prompt() -> str:
    """Load the compact neutral prompt for follow-up calls (no persona)."""
    return load_text("prompts", "compact-neutral.md")


def load_rules() -> str:
    """Load the LLM rules document."""
    return load_text("rules", "RULES.md")


# ── Mode hint data ───────────────────────────────────────────────────────

_MODE_HINTS_DATA: dict[str, str] | None = None


def _get_mode_hints() -> dict[str, str]:
    global _MODE_HINTS_DATA
    if _MODE_HINTS_DATA is None:
        try:
            ui_data = load_json("messages", "ui.json")
            _MODE_HINTS_DATA = ui_data.get("mode_hints", {})
        except FileNotFoundError:
            _MODE_HINTS_DATA = {}
    return _MODE_HINTS_DATA


# ── Platform context helper (runtime-generated, not from files) ──────────


def platform_context() -> str:
    """Return the platform context string for prompt injection.

    Generated at call time because the OS/shell can change between sessions.
    """
    is_win = sys.platform == "win32"
    shell = "cmd /c" if is_win else "sh -c"
    lines = [
        "<PLATFORM_CONTEXT>",
        f"- OS: {_platform.system()} {_platform.release()} ({_platform.machine()})",
        f"- Shell: {shell}",
    ]
    if is_win:
        lines.extend(
            [
                "- WARNING: Windows system detected — commands must use Windows-compatible flags:",
                "  * nmap: use -sT (TCP connect) instead of -sS (SYN scan); omit -O",
                "  * Use forward slashes or escaped backslashes in paths",
                "  * For DNS: use nslookup if dig is unavailable",
                "  * Find binaries with `where` instead of `which`",
            ]
        )
    else:
        lines.extend(
            [
                "- Unix-like system (Linux/macOS) — standard Unix commands apply.",
                "  * nmap -sS (SYN scan) requires root/admin privileges",
            ]
        )
    lines.append("</PLATFORM_CONTEXT>")
    return "\n".join(lines)


# ── Professional Prompt Rendering ─────────────────────────────────────────


def make_prompt_top(
    mode: str,
    provider: str,
    session_id: str,
    msg_count: int,
    uptime_seconds: float,
    theme: str = "cyber-noir",
    persona: str = "",
) -> RenderableType:
    """Render the top line of the professional prompt."""
    mc = mode_color(mode)
    hours, rem = divmod(int(uptime_seconds), 3600)
    minutes, secs = divmod(rem, 60)
    uptime_str = f"{hours:02d}:{minutes:02d}:{secs:02d}"

    persona_part = []
    if persona:
        persona_part = [
            (" ", ""),
            (f"persona:{persona}", "bright_green"),
        ]

    title_parts = [
        ("▌", "dim"),
        ("siyarix", "bold bright_white"),
        ("  ", ""),
        (f"[{mode}]", mc),
        (" ", ""),
        (f"{provider}", "bright_blue"),
        *persona_part,
        (" ", ""),
        (f"msgs:{msg_count}", "dim"),
        (" ", ""),
        (f"up:{uptime_str}", "dim"),
        (" ", ""),
        (f"sid:{session_id[:6]}", "dim italic"),
        ("▐", "dim"),
    ]
    return Text.assemble(*title_parts)


def make_prompt_bottom(show_hint: bool = True) -> RenderableType:
    """Render the input line."""
    parts = [
        ("╰─ ", "dim"),
        ("➜ ", "bold bright_cyan"),
    ]
    if show_hint:
        parts.append(("(Tab: autocomplete, ?: help)", "dim italic"))
    return Text.assemble(*parts)


def mode_prompt_hint(mode: str) -> str:
    """Return a mode-specific one-line hint shown in the prompt area."""
    return _get_mode_hints().get(mode, "")


def make_prompt_bar(
    mode: str,
    provider: str,
    session_id: str,
    msg_count: int,
    uptime_seconds: float,
    theme: str = "cyber-noir",
    persona: str | None = None,
    show_hint: bool = True,
) -> RenderableType:
    """Combined professional prompt with top bar and input line."""
    top = make_prompt_top(mode, provider, session_id, msg_count, uptime_seconds, theme, persona)
    bottom = make_prompt_bottom(show_hint)
    return Text.assemble(top, "\n", bottom)


__all__ = [
    "mode_color",
    "load_system_prompt",
    "load_neutral_prompt",
    "load_compact_prompt",
    "load_compact_neutral_prompt",
    "load_rules",
    "platform_context",
    "make_prompt_top",
    "make_prompt_bottom",
    "make_prompt_bar",
    "mode_prompt_hint",
]
