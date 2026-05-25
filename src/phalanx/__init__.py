"""Phalanx — AI-native cybersecurity operations platform.

Provides autonomous execution, multi-agent framework, intelligent workflow
orchestration, and advanced security tooling for offensive and defensive
cybersecurity operations.
"""

__version__ = "2.0.0"
__author__ = "MD MUFTHAKHERUL ISLAM MIRAZ"
__license__ = "MIT"

from .engine import ExecutionEngine, ExecutionMode, EngineResult
from .planner import TaskPlanner, ExecutionPlan, ExecutionStep, StepType
from .engine_types import StepResult, StepStatus
from .providers import Provider, ProviderRegistry, NoopProvider, registry as provider_registry
from .masking import MaskingEngine
from .response_sensor import ResponseSensor
from .security_hardening import InputValidator, SecretRedactor, DangerAnalyzer
from .knowledge_graph import KnowledgeGraph, Node, Edge, NodeType, EdgeType
from .tool_registry import ToolRegistry, ToolInfo
from .multi_agent import Agent, AgentTeam, AgentMessage, AgentRole, AgentStatus
from .worker_pool import AsyncWorkerPool
from .tool_executor import ToolExecutor
from .dynamic_resolver import DynamicResolver
from .metrics import get_metrics
from .notifications import notification_center
from .audit_log import audit, AuditEventType, AuditSeverity
from .config import SettingsStore
from .credential_store import CredentialStore
from .offline_store import OfflineStore
from .interpreter import RuleInterpreter, InterpretedTask
from .output import output, OutputEngine
from .health import get_health
from .exceptions import ValidationError
from .validators import validate_target
from .plugins import PluginManager
from .logging_config import configure_logging
from .core import IntentRouter, SessionKernel, AgenticLoop, InMemoryEventBus as EventBus
from .xi import XICoreService, ContextTracker, Predictor
from .orchestration import WorkflowRuntime
from .agents import CoordinatorAgent, SOCAgent, DFIRAgent
from .exploitation import ExploitChainBuilder, ExploitChainExecutor, ExploitChain, ExploitPhase
from .ml_anomaly import AnomalyDetector
from .deception import HoneypotDetector, FakeBannerGenerator, TrapdoorCredentialManager
from .threat_intel import ThreatIntelFeed, MITREAttackDB
from .telemetry.opentelemetry import OpenTelemetryCollector, OpenTelemetryMiddleware, get_collector
from .dashboard import DashboardService, DashboardSnapshot, DashboardConfig
from .distributed import DistributedOrchestrator, TaskQueueBackend, DistributedTask
from .bootstrap import BootstrapEngine, BootstrapResult, PlatformInfo
from .tool_installer import ToolInstaller, ToolInstallResult
from .terminal_detection import TerminalDetector, TerminalInfo, ShellType, TerminalType
from .cvss_scorer import CVSSScorer, CVSSResult, CVSSVector, Severity
from .report_engine import ReportEngine, Report, ReportConfig, ReportSection, ReportFormat
from .playbook_engine import PlaybookEngine, Playbook, PlaybookStep, PlaybookStepType
from .stealth import StealthEngine, StealthConfig
from .canary import CanaryTokenManager, CanaryToken, CanaryDeployment, CanaryTokenType
from .cloud_scanner import CloudScanner, CloudScanResult, CloudProvider
from .compliance_runner import (
    ComplianceRunner,
    ComplianceResult,
    ComplianceControl,
    ComplianceFramework,
)
from .multi_model_ensemble import MultiModelEnsemble, EnsembleResult, ModelResponse, VotingStrategy
from .adversarial_tester import AdversarialTester, AdversarialFinding, AdversarialSeverity
from .persona_engine import PersonaEngine, Persona, PersonaName, ToolACL, WorkflowTemplate, LearningBias, REVIEW, BUILTIN_PERSONAS
from .permission_gate import PermissionGate, GateResult
from .kill_switch import KillSwitch, KillSwitchState
from .shell_review import ReviewResult, review_command, review_and_confirm, ReviewDecision
from .agent_lifecycle import AgentLifecycle, AgentInstance
from .collaboration import CollaborationManager, CollabSession, CollabMember
from .coder_bridge import CoderBridge, CodeReview
from .mcp_integration import MCPClient, MCPTool
from .learning_memory import LearningMemory, ToolPattern, SessionContext
from .user_learning import UserLearning, UserProfile, SessionRecord, ExperienceLevel

__all__ = [
    "ExecutionEngine",
    "ExecutionMode",
    "EngineResult",
    "TaskPlanner",
    "ExecutionPlan",
    "ExecutionStep",
    "StepType",
    "StepResult",
    "StepStatus",
    "Provider",
    "ProviderRegistry",
    "NoopProvider",
    "provider_registry",
    "MaskingEngine",
    "ResponseSensor",
    "InputValidator",
    "SecretRedactor",
    "DangerAnalyzer",
    "KnowledgeGraph",
    "Node",
    "Edge",
    "NodeType",
    "EdgeType",
    "ToolRegistry",
    "ToolInfo",
    "Agent",
    "AgentTeam",
    "AgentMessage",
    "AgentRole",
    "AgentStatus",
    "AsyncWorkerPool",
    "ToolExecutor",
    "DynamicResolver",
    "get_metrics",
    "notification_center",
    "audit",
    "AuditEventType",
    "AuditSeverity",
    "SettingsStore",
    "CredentialStore",
    "OfflineStore",
    "RuleInterpreter",
    "InterpretedTask",
    "output",
    "OutputEngine",
    "get_health",
    "ValidationError",
    "validate_target",
    "PluginManager",
    "configure_logging",
    "IntentRouter",
    "SessionKernel",
    "AgenticLoop",
    "EventBus",
    "XICoreService",
    "ContextTracker",
    "Predictor",
    "WorkflowRuntime",
    "CoordinatorAgent",
    "SOCAgent",
    "DFIRAgent",
    "ExploitChainBuilder",
    "ExploitChainExecutor",
    "ExploitChain",
    "ExploitPhase",
    "AnomalyDetector",
    "HoneypotDetector",
    "FakeBannerGenerator",
    "TrapdoorCredentialManager",
    "ThreatIntelFeed",
    "MITREAttackDB",
    "OpenTelemetryCollector",
    "OpenTelemetryMiddleware",
    "get_collector",
    "DashboardService",
    "DashboardSnapshot",
    "DashboardConfig",
    "DistributedOrchestrator",
    "TaskQueueBackend",
    "DistributedTask",
    "BootstrapEngine",
    "BootstrapResult",
    "PlatformInfo",
    "ToolInstaller",
    "ToolInstallResult",
    "TerminalDetector",
    "TerminalInfo",
    "ShellType",
    "TerminalType",
    "CVSSScorer",
    "CVSSResult",
    "CVSSVector",
    "Severity",
    "ReportEngine",
    "Report",
    "ReportConfig",
    "ReportSection",
    "ReportFormat",
    "PlaybookEngine",
    "Playbook",
    "PlaybookStep",
    "PlaybookStepType",
    "StealthEngine",
    "StealthConfig",
    "CanaryTokenManager",
    "CanaryToken",
    "CanaryDeployment",
    "CanaryTokenType",
    "CloudScanner",
    "CloudScanResult",
    "CloudProvider",
    "ComplianceRunner",
    "ComplianceResult",
    "ComplianceControl",
    "ComplianceFramework",
    "MultiModelEnsemble",
    "EnsembleResult",
    "ModelResponse",
    "VotingStrategy",
    "AdversarialTester",
    "AdversarialFinding",
    "AdversarialSeverity",
    "PersonaEngine",
    "Persona",
    "PersonaName",
    "ToolACL",
    "WorkflowTemplate",
    "LearningBias",
    "REVIEW",
    "BUILTIN_PERSONAS",
    "PermissionGate",
    "GateResult",
    "KillSwitch",
    "KillSwitchState",
    "ReviewResult",
    "review_command",
    "review_and_confirm",
    "ReviewDecision",
    "AgentLifecycle",
    "AgentInstance",
    "CollaborationManager",
    "CollabSession",
    "CollabMember",
    "CoderBridge",
    "CodeReview",
    "MCPClient",
    "MCPTool",
    "LearningMemory",
    "ToolPattern",
    "SessionContext",
    "UserLearning",
    "UserProfile",
    "SessionRecord",
    "ExperienceLevel",
]
