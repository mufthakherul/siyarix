# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix — AI-native cybersecurity operations platform.

Provides autonomous execution, multi-agent framework, intelligent workflow
orchestration, and advanced security tooling for offensive and defensive
cybersecurity operations.
"""

__version__ = "0.1.3"
__author__ = "MD MUFTHAKHERUL ISLAM MIRAZ"
__license__ = "AGPL-3.0-or-later"

from .adversarial_tester import (AdversarialFinding, AdversarialSeverity,
                                 AdversarialTester)
from .agent_lifecycle import AgentInstance, AgentLifecycle
from .agents import CoordinatorAgent
from .audit_log import AuditEventType, AuditSeverity, audit
from .bootstrap import BootstrapEngine, BootstrapResult, PlatformInfo
from .canary import (CanaryDeployment, CanaryToken, CanaryTokenManager,
                     CanaryTokenType)
from .cloud_scanner import CloudProvider, CloudScanner, CloudScanResult
from .coder_bridge import CoderBridge, CodeReview
from .compliance_runner import (ComplianceControl, ComplianceFramework,
                                 ComplianceResult, ComplianceRunner)
from .config import SettingsStore
from .core import AgenticLoop
from .core import InMemoryEventBus as EventBus
from .core import IntentRouter, SessionKernel
from .core.session_kernel import SessionContext
from .credential_store import CredentialStore
from .cvss_scorer import CVSSResult, CVSSScorer, CVSSVector, Severity
from .dashboard import DashboardConfig, DashboardService, DashboardSnapshot
from .deception import (FakeBannerGenerator, HoneypotDetector,
                        TrapdoorCredentialManager)
from .distributed import (DistributedOrchestrator, DistributedTask,
                          TaskQueueBackend)
from .dynamic_resolver import DynamicResolver
from .engine import EngineResult, ExecutionEngine, ExecutionMode
from .engine_types import StepResult, StepStatus
from .exceptions import ValidationError
from .exploitation import (ExploitChain, ExploitChainBuilder,
                           ExploitChainExecutor, ExploitPhase)
from .health import get_health
from .interpreter import InterpretedTask, RuleInterpreter
from .kill_switch import KillSwitch, KillSwitchState
from .knowledge_graph import Edge, EdgeType, KnowledgeGraph, Node, NodeType
from .learning_memory import LearningEvent, LearningMemory, ToolPattern
from .logging_config import configure_logging
from .masking import MaskingEngine
from .mcp_integration import MCPClient, MCPTool
from .metrics import get_metrics
from .ml_anomaly import AnomalyDetector
from .multi_agent import Agent, AgentMessage, AgentRole, AgentStatus, AgentTeam
from .multi_model_ensemble import (EnsembleResult, ModelResponse,
                                   MultiModelEnsemble, VotingStrategy)
from .notifications import notification_center
from .offline_store import OfflineStore
from .orchestration import WorkflowRuntime
from .output import OutputEngine, output
from .permission_gate import GateResult, PermissionGate
from .persona_engine import (BUILTIN_PERSONAS, REVIEW, LearningBias, Persona,
                             PersonaEngine, PersonaName, ToolACL,
                             WorkflowTemplate)
from .planner import ExecutionPlan, ExecutionStep, StepType, TaskPlanner
from .playbook_engine import (Playbook, PlaybookEngine, PlaybookStep,
                              PlaybookStepType)
from .providers import (AnthropicAdapter, CloudAdapter, CustomAdapter,
                         GeminiAdapter, GroqAdapter, LMStudioAdapter,
                         NoopProvider, OllamaAdapter, OpenAIAdapter,
                         OpenCodeAdapter, Provider,
                         ProviderRegistry, TogetherAdapter)
from .providers import registry as provider_registry
from .report_engine import (Report, ReportConfig, ReportEngine, ReportFormat,
                            ReportSection)
from .response_sensor import ResponseSensor
from .security_hardening import DangerAnalyzer, SecretRedactor
from .session_log import (CommandEntry, SafetyEvent, SessionLog, SessionLogger,
                          session_logger)
from .shell_review import (ReviewDecision, ReviewResult, review_and_confirm,
                           review_command)
from .stealth import StealthConfig, StealthEngine
from .telemetry.opentelemetry import (OpenTelemetryCollector,
                                      OpenTelemetryMiddleware, get_collector)
from .terminal_detection import (ShellType, TerminalDetector, TerminalInfo,
                                 TerminalType)
from .threat_intel import MITREAttackDB, ThreatIntelFeed
from .tool_executor import ToolExecutor
from .tool_installer import ToolInstaller, ToolInstallResult
from .tool_registry import ToolInfo, ToolRegistry
from .user_learning import (ExperienceLevel, PedagogicalEngine,
                            PedagogicalStep, SessionRecord, UserLearning,
                            UserProfile)
from .achievement import Achievement, AchievementSystem, achievement_system
from .cache_manager import CacheEntry, CacheManager, cache_manager

from .hsm_manager import HSMError, HSMKeyInfo, HSMNotAvailable, HSMService, HSMStatus
from .iac_scanner import IaCFinding, IaCScanResult, IaCScanner
from .importer import ImportResult, ImportedFinding, SecurityImporter, security_importer
from .iot_scanner import IoTFinding, IoTScanResult, IoTScanner
from .mobile_scanner import MobileFinding, MobileScanResult, MobileScanner
from .opsec import OPSECActionResult, OPSECManager, OPSECStatus, opsec_manager
from .performance import PerformanceConfig, PerformanceOptimizer, SystemResources, performance_optimizer
from .platform_integration import (BOUNTY_PLATFORMS, COMMS_PLATFORMS, SIEM_PLATFORMS,
                                   NotificationChannel, PlatformConnection,
                                   PlatformIntegrationService, SubmissionResult,
                                   platform_integration)
from . import progress
from .scheduler import SiyarixScheduler, ScheduledJob
from .validators import validate_target
from .worker_pool import AsyncWorkerPool
from .xi import ContextTracker, Predictor, XICoreService

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
    "OpenAIAdapter",
    "GeminiAdapter",
    "OllamaAdapter",
    "CloudAdapter",
    "GroqAdapter",
    "TogetherAdapter",
    "LMStudioAdapter",
    "CustomAdapter",
    "AnthropicAdapter",
    "OpenCodeAdapter",
    "MaskingEngine",
    "ResponseSensor",
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

    "SiyarixScheduler",
    "ScheduledJob",
    "DashboardSnapshot",
    "DashboardConfig",
    "DashboardService",
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
    "CoderBridge",
    "CodeReview",
    "MCPClient",
    "MCPTool",
    "LearningMemory",
    "ToolPattern",
    "SessionContext",
    "LearningEvent",
    "UserLearning",
    "UserProfile",
    "SessionRecord",
    "ExperienceLevel",
    "PedagogicalEngine",
    "PedagogicalStep",
    "SessionLog",
    "CommandEntry",
    "SafetyEvent",
    "SessionLogger",
    "session_logger",
    "AchievementSystem",
    "Achievement",
    "achievement_system",
    "CacheManager",
    "CacheEntry",
    "cache_manager",
    "HSMService",
    "HSMStatus",
    "HSMKeyInfo",
    "HSMError",
    "HSMNotAvailable",
    "IaCScanner",
    "IaCFinding",
    "IaCScanResult",
    "SecurityImporter",
    "ImportedFinding",
    "ImportResult",
    "security_importer",
    "IoTScanner",
    "IoTFinding",
    "IoTScanResult",
    "MobileScanner",
    "MobileFinding",
    "MobileScanResult",
    "OPSECManager",
    "OPSECStatus",
    "OPSECActionResult",
    "opsec_manager",
    "PerformanceOptimizer",
    "PerformanceConfig",
    "SystemResources",
    "performance_optimizer",
    "PlatformIntegrationService",
    "PlatformConnection",
    "SubmissionResult",
    "NotificationChannel",
    "platform_integration",
    "BOUNTY_PLATFORMS",
    "SIEM_PLATFORMS",
    "COMMS_PLATFORMS",
    "progress",
]
