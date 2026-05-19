"""NexSec Premium UX & Interactive Layout System.

Exposes next-generation terminal interfaces, split-pane timelines,
tiered autocompletion, fuzzy command palettes, and setup wizards.
"""

from .autocomplete import SmartAutocomplete
from .command_palette import CommandPalette
from .split_pane import SplitPane
from .wizard import OnboardingWizard

__all__ = [
    "SmartAutocomplete",
    "CommandPalette",
    "SplitPane",
    "OnboardingWizard",
]
