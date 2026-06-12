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
from .executor import Executor, ExecutionBudget, GuardrailConfig, ToolCallTracker
from .validators import Validator, ValidationResult, RecoveryAction, RecoveryPlan
from .context import ContextManager, ContextChunk, ContextWindow
from .workflow import WorkflowEngine, Workflow, WorkflowNode, WorkflowStatus
from .mcp import MCPManager, MCPClient, MCPServerConfig
from .core import AgentCore, AgentMode, AgentStatus, AgentGoal, AgentResult

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
    "Executor",
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
    "MCPManager",
    "MCPClient",
    "MCPServerConfig",
    "AgentCore",
    "AgentMode",
    "AgentStatus",
    "AgentGoal",
    "AgentResult",
]
