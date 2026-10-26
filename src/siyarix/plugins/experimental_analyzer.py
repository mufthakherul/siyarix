# SPDX-License-Identifier: AGPL-3.0-or-later

"""Experimental Threat Analyzer Plugin for Siyarix.

This plugin registers a heuristic threat analysis tool into the ToolRegistry.
"""

from __future__ import annotations

import logging
from typing import Any

from siyarix.registry import ToolRegistry
from siyarix.tool_models import RiskLevel, ToolCapability, ToolCategory

logger = logging.getLogger(__name__)


async def _experimental_analyzer_handler(**kwargs: Any) -> dict[str, Any]:
    target = kwargs.get("target", "unknown")
    logger.info("Running Experimental Analyzer (canned heuristic) on %s", target)
    return {
        "output": (
            f"[EXPERIMENTAL / CANNED HEURISTIC] Stub analysis for target '{target}'. "
            "No real model inference ran; this is a placeholder plugin. "
            "Any confidence figure would be illustrative only — not a calibrated score. "
            "Do not treat this output as a security assessment."
        )
    }


def register_tools(registry: ToolRegistry) -> None:
    """Register the experimental tools with the Siyarix registry."""
    capability = ToolCapability(
        name="experimental_analyzer",
        description=(
            "Experimental canned heuristic stub — returns placeholder text only; "
            "not real threat analysis or calibrated confidence."
        ),
        category=ToolCategory.RECON,
        risk_level=RiskLevel.LOW,
        tags=["experimental", "heuristic", "canned", "threat-analysis"],
    )
    registry.register(capability, _experimental_analyzer_handler)
    logger.info("Registered experimental_analyzer tool in Siyarix.")
