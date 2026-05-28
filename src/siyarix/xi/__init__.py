# SPDX-License-Identifier: AGPL-3.0-or-later

"""Experience Intelligence (XI) services.

Modules:
  • service — Core XI recommendation engine
  • context_tracker — Real-time operation/target awareness
  • predictor — Predictive next-action suggestions
  • skill_profiler — User skill level detection and UX adaptation
"""

from .context_tracker import ContextTracker, OperationPhase, TrackedTarget
from .predictor import Prediction, Predictor
from .service import XICoreService, XIRecommendation
from .skill_profiler import SkillLevel, SkillProfile, SkillProfiler

__all__ = [
    "XICoreService",
    "XIRecommendation",
    "ContextTracker",
    "OperationPhase",
    "TrackedTarget",
    "Predictor",
    "Prediction",
    "SkillProfiler",
    "SkillProfile",
    "SkillLevel",
]
