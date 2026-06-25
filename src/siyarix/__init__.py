# SPDX-License-Identifier: AGPL-3.0-or-later
"""Siyarix — AI-native cybersecurity operations platform.

Next-generation agent platform with registry-based execution,
intelligent tool selection, autonomous workflows, and advanced security tooling.
"""

__app_name__ = "siyarix"
__version__ = "1.0.0"
__author__ = "MD MUFTHAKHERUL ISLAM MIRAZ"
__license__ = "AGPL-3.0-or-later"

import importlib
import typing as _typing

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
    "ExecutionPlan",
    "PlanStep",
    "PlanType",
    "PlanStatus",
    "StepStatus",
    "RegistryPlanner",
    "TOOL_ALTERNATIVES",
    "ResponseGenerator",
    "AutonomousPlanner",
    "Executor",
    "BaseExecutor",
    "RegistryExecutor",
    "AutonomousExecutor",
    "ExecutionBudget",
    "GuardrailConfig",
    "ToolCallTracker",
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
]

_SYMBOL_MODULE: dict[str, str] = {
    "Event": ".events",
    "EventType": ".events",
    "EventBus": ".events",
    "get_event_bus": ".events",
    "ToolCapability": ".registry",
    "ToolCategory": ".registry",
    "RiskLevel": ".registry",
    "ToolCapabilityGraph": ".registry",
    "ToolRegistry": ".registry",
    "MemoryManager": ".memory",
    "MemoryStore": ".memory",
    "MemoryEntry": ".memory",
    "MemoryLayer": ".memory",
    "ProviderManager": ".providers",
    "ProviderProfile": ".providers",
    "ProviderCredential": ".providers",
    "FailoverReason": ".providers",
    "ClassifiedError": ".providers",
    "Planner": ".planner",
    "ExecutionPlan": ".planner",
    "PlanStep": ".planner",
    "PlanType": ".planner",
    "PlanStatus": ".planner",
    "StepStatus": ".planner",
    "RegistryPlanner": ".planner_registry",
    "TOOL_ALTERNATIVES": ".planner_registry",
    "ResponseGenerator": ".response",
    "AutonomousPlanner": ".planner_autonomous",
    "Executor": ".executor_registry",
    "BaseExecutor": ".executor",
    "ExecutionBudget": ".executor",
    "GuardrailConfig": ".executor",
    "ToolCallTracker": ".executor",
    "RegistryExecutor": ".executor_registry",
    "AutonomousExecutor": ".executor_autonomous",
    "Validator": ".validators",
    "ValidationResult": ".validators",
    "RecoveryAction": ".validators",
    "RecoveryPlan": ".validators",
    "ContextManager": ".context",
    "ContextChunk": ".context",
    "ContextWindow": ".context",
    "WorkflowEngine": ".workflow",
    "Workflow": ".workflow",
    "WorkflowNode": ".workflow",
    "WorkflowStatus": ".workflow",
    "AgentCore": ".core",
    "AgentMode": ".core",
    "AgentStatus": ".core",
    "AgentGoal": ".core",
    "AgentResult": ".core",
}


def __getattr__(name: str) -> _typing.Any:
    if name in _SYMBOL_MODULE:
        mod = importlib.import_module(_SYMBOL_MODULE[name], __package__)
        obj = getattr(mod, name)
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
