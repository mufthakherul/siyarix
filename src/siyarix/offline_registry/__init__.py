# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline registry utilities for registry/offline execution mode.

Provides helpers used by the registry planner and executor when running
without an AI provider connection.
"""

from __future__ import annotations


def offline_instruction_hint(instruction: str) -> str:
    """Return a brief hint about what will happen with this instruction in offline mode."""
    return (
        f"[dim]Offline mode: planning '{instruction[:60]}' "
        "using heuristic tool registry (no LLM)[/dim]"
    )


def no_provider_message() -> str:
    """Return a user-facing message when no AI provider is configured for online mode."""
    return (
        "No AI provider configured. Use 'siyarix auth set-key <provider> <key>' "
        "to enable LLM-powered execution, or run in offline/registry mode."
    )


__all__ = [
    "offline_instruction_hint",
    "no_provider_message",
]
