# SPDX-License-Identifier: AGPL-3.0-or-later
"""Siyarix — AI-native cybersecurity operations platform.

Next-generation agent platform with registry-based execution,
intelligent tool selection, autonomous workflows, and advanced security tooling.
"""

__version__ = "3.0.0"
__author__ = "MD MUFTHAKHERUL ISLAM MIRAZ"
__license__ = "AGPL-3.0-or-later"

from .events import Event, EventType, EventBus, get_event_bus
from .registry import ToolCapability, ToolCategory, RiskLevel, ToolCapabilityGraph, ToolRegistry
from .memory import MemoryManager, MemoryStore, MemoryEntry, MemoryLayer
from .providers import (
    ProviderManager,
    ProviderProfile,
    ProviderCredential,
    FailoverReason,
    ClassifiedError,
)
from .planner import Planner, ExecutionPlan, PlanStep, PlanType, PlanStatus, StepStatus
from .planner_registry import RegistryPlanner, TOOL_ALTERNATIVES
from .response import ResponseGenerator
from .planner_autonomous import AutonomousPlanner
from .executor import BaseExecutor, ExecutionBudget, GuardrailConfig, ToolCallTracker
from .executor_registry import RegistryExecutor
from .executor_autonomous import AutonomousExecutor
from .validators import Validator, ValidationResult, RecoveryAction, RecoveryPlan
from .context import ContextManager, ContextChunk, ContextWindow
from .workflow import WorkflowEngine, Workflow, WorkflowNode, WorkflowStatus
from .core import AgentCore, AgentMode, AgentStatus, AgentGoal, AgentResult

# Backward compatibility alias
Executor = RegistryExecutor

__all__ = [
    "Event",
    "EventType",
    "EventBus",
    "get_event_bus",
    "ToolCapability",
    "ToolCategory",
    "RiskLevel",
    "ToolCapabilityGraph",
    "ToolRegistry",
    "MemoryManager",
    "MemoryStore",
    "MemoryEntry",
    "MemoryLayer",
    "ProviderManager",
    "ProviderProfile",
    "ProviderCredential",
    "FailoverReason",
    "ClassifiedError",
    "Planner",
    "RegistryPlanner",
    "AutonomousPlanner",
    "ExecutionPlan",
    "PlanStep",
    "PlanType",
    "PlanStatus",
    "StepStatus",
    "Executor",
    "BaseExecutor",
    "RegistryExecutor",
    "AutonomousExecutor",
    "ExecutionBudget",
    "GuardrailConfig",
    "ToolCallTracker",
    "TOOL_ALTERNATIVES",
    "Validator",
    "ValidationResult",
    "RecoveryAction",
    "RecoveryPlan",
    "ContextManager",
    "ContextChunk",
    "ContextWindow",
    "WorkflowEngine",
    "Workflow",
    "WorkflowNode",
    "WorkflowStatus",
    "AgentCore",
    "AgentMode",
    "AgentStatus",
    "AgentGoal",
    "AgentResult",
    "ResponseGenerator",
]
