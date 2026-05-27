# Architecture & Internals

Siyarix follows a **7-layer Clean Architecture** with modular, event-driven design. Each layer has distinct responsibilities, enabling independent evolution, testing, and deployment.

---

## 🏛️ Seven-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 7: USER INTERFACE                                                     │
│ CLI (Typer) │ Interactive REPL │ Dashboard │ VS Code │ Collaborative SSH    │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 6: CORE KERNEL                                                        │
│ SessionKernel │ IntentRouter │ ModeDispatcher │ EventBus │ Pipeline         │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 5: EXECUTION ENGINE                                                   │
│ ExecutionEngine │ TaskPlanner │ ToolExecutor │ AgentTeam │ WorkflowRuntime   │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 4: AI & INTELLIGENCE                                                  │
│ Provider Adapters │ Multi-Model Ensemble │ XI │ ML Anomaly │ Adversarial     │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 3: SECURITY & COMPLIANCE                                              │
│ MaskingEngine │ InputValidator │ RBAC │ Compliance │ Stealth │ Canary        │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 2: INFRASTRUCTURE                                                     │
│ KnowledgeGraph │ CredentialStore │ OfflineStore │ Audit │ Metrics │ OTel     │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 1: INTEGRATION                                                        │
│ Tool Registry │ Parsers (17) │ SIEM │ Cloud Scanner │ Threat Intel │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Module Deep Dive

### Layer 7: User Interface
| Module | Purpose |
|--------|---------|
| `main.py` | Typer CLI entry point — 30+ commands, 9 interaction modes |
| `chat.py` | Interactive REPL — streaming, multi-turn, slash commands |
| `ux/` | Premium terminal UI — wizard, split pane, palette, autocomplete |
| `dashboard.py` | Web dashboard — REST API, WebSocket live updates, metrics snapshots |

### Layer 6: Core Kernel
| Module | Purpose |
|--------|---------|
| `core/session_kernel.py` | Session context, operation cards, persistence levels |
| `core/intent_router.py` | 4-stage routing: exact → heuristic → keyword → LLM |
| `core/event_bus.py` | In-process pub/sub for operation-level signaling |
| `core/mode_dispatcher.py` | 9 interaction modes (shell, chat, autonomous, dashboard, etc.) |
| `core/pipeline.py` | Sequential step execution with context propagation |
| `core/agentic_loop.py` | Observe → Reflect → Reason → Act → Evaluate cycle |

### Layer 5: Execution Engine
| Module | Purpose |
|--------|---------|
| `engine.py` | Central orchestrator — 3 modes, dynamic mutation, feedback loop |
| `planner.py` | LLM-first + heuristic fallback, circuit breaker, retry logic |
| `tool_executor.py` | Tool execution with dependency resolution, chaining |
| `multi_agent.py` | Agent framework — AgentTeam, AgentRole, messaging |
| `agents/coordinator.py` | Objective decomposition → phase-based multi-agent dispatch |
| `agents/soc_agent.py` | 8 detection rules, triage tickets, MITRE ATT&CK mapping |
| `agents/dfir_agent.py` | Memory/disk/network forensics, IOC extraction, chain of custody |
| `playbook_engine.py` | Playbook save/load/execute with variables and conditionals |
| `workflow_runtime.py` | YAML workflow automation runtime |

### Layer 4: AI & Intelligence
| Module | Purpose |
|--------|---------|
| `providers.py` | Provider abstraction + adapter classes — OpenAI, Gemini, Ollama, Claude, NoopProvider |
| `provider_adapters.py` | Re-exports from providers.py for backward compatibility |
| `multi_model_ensemble.py` | Multi-provider voting, consensus, hallucination detection |
| `xi/context_tracker.py` | Real-time operation awareness (phase, targets, executions) |
| `xi/predictor.py` | Predictive next-action engine with pattern learning |
| `xi/skill_profiler.py` | User skill assessment (beginner→expert), adaptive UX |
| `ml_anomaly.py` | Statistical baseline, z-score, frequency analysis, alerts |
| `adversarial_tester.py` | IDS trigger detect, rate-limit, safety, dependency checks |

### Layer 3: Security & Compliance
| Module | Purpose |
|--------|---------|
| `masking.py` | Session-scoped deterministic masking with exportable mapping |
| `response_sensor.py` | Pre-model masking + post-model redaction pipeline |
| `security_hardening.py` | Input validation, secret redaction, danger pattern analysis |
| `security/rbac.py` | 5 roles × 5 permissions for team environments |
| `security/attack_path.py` | Graph traversal for multi-step exploit paths |
| `security/compliance.py` | Compliance report generation (SOC 2, ISO 27001, NIST-CSF) |
| `compliance_runner.py` | Automated assessment: PCI-DSS, ISO 27001, NIST, SOC 2, GDPR, HIPAA |
| `stealth.py` | Evasion: 5 levels, UA rotation, proxy chaining, decoy traffic |
| `canary.py` | 7 token types, deployment, trigger detection, alert handlers |
| `deception.py` | Honeypot detection (7 signatures), canary tokens (5 patterns) |

### Layer 2: Infrastructure
| Module | Purpose |
|--------|---------|
| `knowledge_graph.py` | Graph DB — 15 node types, 20 edge types, BFS/DFS/shortest path |
| `credential_store.py` | Encrypted vault — Fernet AES-128, keyring, RBAC |
| `offline_store.py` | SQLite offline storage — schema, sync, CRUD |
| `audit_log.py` | Enterprise audit — tamper-evident SHA-256 chain, SIEM forward |
| `metrics.py` | Prometheus-format metrics — execution, tool, planner |
| `notifications.py` | In-terminal alerts, severity panels, webhook forwarding |
| `telemetry/opentelemetry.py` | Traces, spans, decorator, middleware, exporter registration |
| `telemetry/siem.py` | Splunk HEC, ElasticSearch, generic webhook connectors |

### Layer 1: Integration
| Module | Purpose |
|--------|---------|
| `tool_registry.py` | Auto-discovers 50+ tools from PATH, capability inference |
| `tool_installer.py` | Auto-install missing tools via apt/brew/choco/pip/go |
| `parsers/` | 17 tool output parsers (nmap, nuclei, gobuster, sqlmap, etc.) |
| `exploitation.py` | Exploit chain builder, msfvenom payload generator |
| `threat_intel.py` | STIX/TAXII, MISP ingestion, MITRE ATT&CK DB (25+ techniques) |
| `cloud_scanner.py` | AWS, Azure, GCP, Kubernetes, Docker security checks |
| `bootstrap.py` | First-run setup, platform detection, directory structure |

---

## 🔄 Execution Flow

```
User Input
  │
  ▼
[Layer 7] CLI / Chat / Dashboard — captures user intent
  │
  ▼
[Layer 6] SessionKernel → IntentRouter — routes to correct handler
  │
  ▼
[Layer 5] ExecutionEngine — orchestrates execution plan
  │
  ├── [Layer 4] TaskPlanner — generates plan via LLM or heuristic
  ├── [Layer 4] AdversarialTester — reviews plan for risks
  ├── [Layer 4] MultiModelEnsemble — votes across providers (optional)
  │
  ▼
[Layer 5] ToolExecutor — executes steps with dependency resolution
  │
  ├── [Layer 3] MaskingEngine — masks sensitive data before LLM calls
  ├── [Layer 1] ToolRegistry — verifies tool availability
  ├── [Layer 3] DangerAnalyzer — validates command safety
  ├── [Layer 3] ResponseSensor — unmask + redact model outputs
  │
  ▼
[Layer 2] KnowledgeGraph — stores findings and relationships
[Layer 2] AuditLog — records tamper-evident execution log
[Layer 2] Metrics — updates execution statistics
```

---

## 🧪 Testing Architecture

```
tests/
├── conftest.py          # 15 shared fixtures (providers, masking, tools, mock outputs)
├── pytest.ini           # Markers: slow, network, parser, agent, xi, integration, e2e
├── __init__.py          # Test package marker
│
├── test_engine*.py      # Execution engine tests
├── test_planner*.py     # Planner tests
├── test_xi_*.py         # XI module tests (17+13+11+6 tests)
├── test_agents_*.py     # Agent tests (12+14+13 tests)
├── test_parsers_all.py  # All 17 parsers (28 tests)
├── test_*.py            # 58 total test files
```

---

## 🔐 Security Architecture

```
Input
  │
  ▼
[Layer 3] MaskingEngine — replaces real targets with placeholders
  │
  ▼
[Layer 4] LLM Provider — never sees real targets
  │
  ▼
[Layer 3] DangerAnalyzer — blocks dangerous command patterns
  │
  ▼
[Layer 3] ResponseSensor — detects forbidden commands, permission gates
  │
  ▼
[Layer 3] Unmasking — restores real targets from placeholders
  │
  ▼
[Layer 5] Execution — executes in sandboxed subprocess
  │
  ▼
[Layer 2] Audit — records tamper-evident chain
```
