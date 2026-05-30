# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix — AI-native cybersecurity operations platform.

Provides autonomous execution, intelligent workflow
orchestration, and advanced security tooling for offensive and defensive
cybersecurity operations.
"""

__version__ = "1.0.0"
__author__ = "MD MUFTHAKHERUL ISLAM MIRAZ"
__license__ = "AGPL-3.0-or-later"

from .audit_log import AuditEventType, AuditSeverity, audit
from .bootstrap import BootstrapEngine, BootstrapResult, PlatformInfo
from .branding import available_themes, print_banner
from .cache_manager import CacheEntry, CacheManager, cache_manager
from .config import SettingsStore
from .core import AgenticLoop
from .core import InMemoryEventBus as EventBus
from .core import IntentRouter, SessionKernel
from .core.session_kernel import SessionContext
from .credential_store import CredentialStore
from .cvss_scorer import CVSSResult, CVSSScorer, CVSSVector, Severity
from .dynamic_resolver import DynamicResolver
from .engine import EngineResult, ExecutionEngine, ExecutionMode
from .engine_types import StepResult, StepStatus
from .exceptions import ValidationError
from .health import get_health
from .interpreter import InterpretedTask, RuleInterpreter
from .kill_switch import KillSwitch, KillSwitchState
from .logging_config import configure_logging
from .metrics import get_metrics
from .output import OutputEngine, output
from .permission_gate import GateResult, PermissionGate
from .planner import ExecutionPlan, ExecutionStep, StepType, TaskPlanner
from .providers import (AnthropicAdapter, CloudAdapter, CustomAdapter,
                         GeminiAdapter, GroqAdapter, LMStudioAdapter,
                         NoopProvider, OllamaAdapter, OpenAIAdapter,
                         OpenCodeAdapter, Provider,
                         ProviderRegistry, TogetherAdapter)
from .providers import registry as provider_registry
from .report_engine import (Report, ReportConfig, ReportEngine, ReportFormat,
                            ReportSection)
from .security_hardening import DangerAnalyzer, SecretRedactor
from .session_log import (CommandEntry, SafetyEvent, SessionLog, SessionLogger,
                          session_logger)
from .shell_review import (ReviewDecision, ReviewResult, review_and_confirm,
                           review_command)
from .stealth import StealthConfig, StealthEngine
from .opsec import OPSECActionResult, OPSECManager, OPSECStatus, opsec_manager
from .tool_executor import ToolExecutor
from .tool_installer import ToolInstaller, ToolInstallResult
from .tool_registry import ToolInfo, ToolRegistry
from .validators import validate_target
from .worker_pool import AsyncWorkerPool

__all__ = [
    "available_themes",
    "print_banner",
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
    "SecretRedactor",
    "DangerAnalyzer",
    "ToolRegistry",
    "ToolInfo",
    "AsyncWorkerPool",
    "ToolExecutor",
    "DynamicResolver",
    "get_metrics",
    "audit",
    "AuditEventType",
    "AuditSeverity",
    "SettingsStore",
    "CredentialStore",
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
    "StealthEngine",
    "StealthConfig",
    "PermissionGate",
    "GateResult",
    "KillSwitch",
    "KillSwitchState",
    "ReviewResult",
    "review_command",
    "review_and_confirm",
    "ReviewDecision",
    "SessionLog",
    "CommandEntry",
    "SafetyEvent",
    "SessionLogger",
    "session_logger",
    "CacheManager",
    "CacheEntry",
    "cache_manager",
    "OPSECManager",
    "OPSECStatus",
    "OPSECActionResult",
    "opsec_manager",
    "SessionContext",
]
