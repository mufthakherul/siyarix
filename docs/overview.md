# Phalanx — Platform Overview

Phalanx is an **enterprise-grade, AI-native cybersecurity operations platform** that orchestrates security tools through autonomous AI planning, multi-agent coordination, and intelligent workflow execution. It transforms your terminal into a powerful security operations center.

---

## 🎯 Core Mission

Bridge the gap between AI-driven planning and deterministic tool execution. Phalanx doesn't just chat — it acts. It discovers your environment, plans attack/defense strategies, executes security tools, parses results, learns from outcomes, and generates professional reports.

### Key Principles
- **Autonomous Execution**: From natural language to executed commands in one step
- **Safety First**: Bidirectional data masking, command sandboxing, permission gates
- **Cross-Platform**: Native support for Linux, macOS, Windows, WSL, cloud shells
- **Extensible**: 17 parsers, custom provider adapters
- **Observable**: OpenTelemetry, audit trails, SIEM forwarding

---

## 🛠️ Capability Matrix

### Planning & Intelligence
| Capability | Description | Module |
|------------|-------------|--------|
| AI Task Planning | LLM-powered execution plan generation | `planner.py` |
| Heuristic Fallback | Rule-based planning without LLM | `interpreter.py` |
| Multi-Model Ensemble | Vote across providers for optimal plan | `multi_model_ensemble.py` |
| Adversarial Review | Auto-detect IDS triggers, rate issues, safety risks | `adversarial_tester.py` |
| ML Anomaly Detection | Statistical baseline deviation analysis | `ml_anomaly.py` |
| Experience Intelligence | Context tracking, next-action prediction, skill profiling | `xi/` |

### Execution & Orchestration
| Capability | Description | Module |
|------------|-------------|--------|
| 7-Agent Team | Recon, Scanner, Enumeration, Exploit, SOC, DFIR, Report | `agents/` |
| Tool Registry | Auto-discovers 50+ security tools from PATH | `tool_registry.py` |
| Exploit Chains | Parameterized campaign workflows with dependency linking | `exploitation.py` |
| Distributed Queue | Redis-backed multi-worker task execution | `distributed.py` |
| Playbook Engine | Save/load/replay multi-step workflows | `playbook_engine.py` |
| Scheduled Scans | Cron-based recurring automated assessments | `scheduler.py` |

### Security & Hardening
| Capability | Description | Module |
|------------|-------------|--------|
| Data Masking | Bidirectional OPSEC masking for cloud LLMs | `masking.py` |
| Input Validation | 8 injection patterns, 35+ dangerous command patterns | `security_hardening.py` |
| Deception | Honeypot detection, canary tokens, fake banners | `deception.py`, `canary.py` |
| Stealth Evasion | 5 levels: jitter, UA rotation, proxy chain, decoy traffic | `stealth.py` |
| RBAC | 5 roles × 5 permissions for team environments | `security/rbac.py` |
| Compliance | PCI-DSS, ISO 27001, NIST 800-53, SOC 2, GDPR, HIPAA | `compliance_runner.py` |

### Intelligence & Integration
| Capability | Description | Module |
|------------|-------------|--------|
| Threat Intel | STIX/TAXII, MISP ingestion, MITRE ATT&CK mapping | `threat_intel.py` |
| Cloud Scanning | AWS, Azure, GCP, Kubernetes, Docker security checks | `cloud_scanner.py` |
| SIEM Forwarding | Splunk HEC, ElasticSearch, generic webhooks | `telemetry/siem.py` |
| OpenTelemetry | Traces, spans, metrics, exporter registration | `telemetry/opentelemetry.py` |
| Web Dashboard | REST API, WebSocket live updates, metrics snapshots | `dashboard.py` |

### Reporting & Output
| Capability | Description | Module |
|------------|-------------|--------|
| Report Engine | Markdown, HTML, JSON, SARIF with CVSS 3.1 scoring | `report_engine.py` |
| CVSS Scoring | Full 3.1 vector calculation, auto-inference from findings | `cvss_scorer.py` |
| Audit Trails | Tamper-evident SHA-256 chain, SIEM-compatible | `audit_log.py` |
| Output Formats | Rich tables, JSON, YAML, CSV, HTML, XML | `output.py` |

---

## 📊 Project Scale

- **118** Python source modules
- **58** test files with shared fixtures
- **50+** security tool integrations
- **17** tool output parsers
- **14** GitHub Actions CI/CD workflows
- **6** compliance frameworks
- **7** specialized AI agents
- **25+** MITRE ATT&CK technique mappings
- **12** advanced feature modules

---

## 🌐 Ecosystem Integration

Phalanx integrates into existing security stacks:

- **SIEM**: Splunk, ElasticSearch via `siem.py`
- **Ticketing**: JIRA, GitHub Issues (coming soon)
- **Communication**: Slack, Discord, Teams (coming soon)
- **Cloud**: AWS, Azure, GCP scanning
- **Container**: Docker, Kubernetes security checks
- **Threat Intel**: MISP, STIX/TAXII feeds
- **IaC**: Terraform, CloudFormation scanning

---

## 🔒 Security & Compliance

- **OPSEC**: Bidirectional data masking prevents target leakage to cloud LLMs
- **Encryption**: AES-256-GCM for API keys, SHA-256 for audit integrity
- **Access Control**: RBAC with 5 permission levels for tools
- **Compliance**: Automated assessment against 6 major frameworks
- **Evidence**: Chain of custody tracking, cryptographic evidence hashing
- **Audit**: Tamper-evident log chains, non-repudiation support
