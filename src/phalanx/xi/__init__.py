"""Experience Intelligence (XI) services.

Modules:
  • service — Core XI recommendation engine
  • context_tracker — Real-time operation/target awareness
  • predictor — Predictive next-action suggestions
  • skill_profiler — User skill level detection and UX adaptation
"""

from .service import XICoreService, XIRecommendation
from .context_tracker import ContextTracker, OperationPhase, TrackedTarget
from .predictor import Predictor, Prediction
from .skill_profiler import SkillProfiler, SkillProfile, SkillLevel

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
