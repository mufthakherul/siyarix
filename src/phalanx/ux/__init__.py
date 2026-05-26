"""Siyarix Premium UX & Interactive Layout System.

Exposes next-generation terminal interfaces, split-pane timelines,
tiered autocompletion, and fuzzy command palettes.
"""

from .autocomplete import SmartAutocomplete
from .command_palette import CommandPalette
from .split_pane import SplitPane

__all__ = [
    "SmartAutocomplete",
    "CommandPalette",
    "SplitPane",
]
