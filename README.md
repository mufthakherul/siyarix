# Phalanx Security Agent

<div align="center">
  <p><strong>AI-native cybersecurity operations platform — autonomous execution, multi-agent framework, intelligent orchestration</strong></p>
  <p>
    <a href="https://github.com/mufthakherul/phalanx/actions/workflows/ci.yml"><img src="https://github.com/mufthakherul/phalanx/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
    <a href="https://github.com/mufthakherul/phalanx/blob/main/LICENSE"><img src="https://img.shields.io/github/license/mufthakherul/phalanx" alt="License"></a>
    <a href="https://pypi.org/project/phalanx/"><img src="https://img.shields.io/pypi/v/phalanx" alt="PyPI"></a>
    <a href="https://github.com/mufthakherul/phalanx"><img src="https://img.shields.io/github/stars/mufthakherul/phalanx" alt="Stars"></a>
    <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs Welcome">
    <img src="https://img.shields.io/badge/coverage-%3E80%25-success" alt="Coverage">
  </p>
</div>

---

Phalanx is an **enterprise-grade, AI-native cybersecurity operations platform** that combines autonomous AI planning with classic security tools. It orchestrates tool execution, analyzes findings, generates reports, and adapts in real time — all from your terminal.

### 🌱 Our Story
Phalanx started as a college project to experiment with AI and security automation. As the codebase grew into a production-grade platform, we open-sourced it. Today it powers 118 modules, 58 test files, and supports 30+ security tools across 6 compliance frameworks.

---

## ✨ Enterprise Features

### Core Platform
- **AI Task Planner**: LLM-driven execution planning (OpenAI, Gemini, Ollama, local models)
- **Multi-Agent Orchestration**: 7 specialized agents (Recon, Scanner, Enumeration, Exploit, SOC, DFIR, Report)
- **Autonomous Execution**: Adaptive re-planning, fallback routing, self-correction on failures
- **Cross-Platform Shell**: Native command translation across Bash, Zsh, PowerShell, CMD
- **Secure Credential Vault**: AES-256-GCM encrypted, OS keyring integration

### Advanced Security Modules
- **Exploit Chain Automation**: Parameterized campaign workflows with dependency-linked phases
- **ML Anomaly Detection**: Statistical baseline, z-score analysis, temporal pattern deviation
- **Threat Intelligence**: STIX/TAXII, MISP ingestion, MITRE ATT&CK DB (25+ techniques)
- **Deception Tactics**: Honeypot detection, canary tokens, fake banners, trapdoor credentials
- **Adversarial Testing**: IDS trigger detection, rate-limit analysis, plan safety validation
- **Stealth Evasion**: 5 evasion levels, User-Agent rotation, proxy chaining, decoy traffic

### Enterprise Infrastructure
- **Distributed Deployment**: Redis-backed task queue, multi-worker orchestration
- **OpenTelemetry**: Full traces, spans, metrics, exporter registration
- **Web Dashboard**: REST API, WebSocket live updates, snapshot system
- **CI/CD Integration**: 14 GitHub Actions workflows, pre-commit hooks
- **Docker Support**: Multi-service compose (phalanx, worker, dashboard, redis, otel)
- **Compliance Assessment**: PCI-DSS, ISO 27001, NIST 800-53, SOC 2, GDPR, HIPAA

### Reporting & Automation
- **Report Engine**: Markdown, HTML, JSON, SARIF output with CVSS 3.1 scoring
- **Playbook System**: Save/load/execute reusable workflows with variables
- **Scheduled Scans**: Cron-based recurring assessments
- **Evidence Preservation**: SHA-256 chain, chain of custody tracking

---

## 🚀 Quick Start

### Installation
```bash
# Production
pip install phalanx

# Full experience (AI planners, CLI, SIEM)
pip install "phalanx[all,cli,siem]"

# Development
git clone https://github.com/mufthakherul/phalanx.git
cd phalanx
pip install -e ".[all,cli,siem]"
```

### Docker
```bash
docker compose up -d
```

### Verify
```bash
make test        # Run 58 test files
make lint        # Ruff linting
make typecheck   # Mypy strict mode
```

### Basic Usage
```bash
# Interactive chat
phalanx

# Quick scan
phalanx scan 192.168.1.1

# Natural language task
phalanx run "scan example.com with nmap and nuclei"

# Generate report
phalanx report generate --findings results.json --format html
```

---

## 📖 Comprehensive Documentation

| Document | Description |
|----------|-------------|
| [Overview](docs/overview.md) | Full platform capabilities, principles, ecosystem |
| [Architecture](docs/architecture.md) | 7-layer architecture, module deep dive, execution flows |
| [Installation](docs/installation.md) | Setup guides, Docker, CI/CD, configuration profiles |
| [Usage Guide](docs/usage.md) | Examples for all modules, playbooks, reports, dashboards |
| [CLI Reference](docs/cli-reference.md) | Complete command reference with 40+ commands |
| [Models](docs/models.md) | AI provider setup, multi-model ensemble, local models |
| [Security](docs/security.md) | Stealth, canary tokens, compliance, OPSEC, data masking |
| [Development](docs/development.md) | Setup, testing, Makefile, CI/CD, code quality |
| [Contributing](docs/contributing.md) | PR process, code of conduct, getting involved |
| [Troubleshooting](docs/troubleshooting.md) | Common issues, diagnostics, debugging |
| [FAQ](docs/faq.md) | Frequently asked questions |

---

## 🏗️ Architecture at a Glance

```
User → CLI Layer → Session Kernel → Intent Router → Mode Dispatcher → Execution Engine
    ├── AI Planner (LLM + Heuristic)
    ├── Tool Registry + Executor
    ├── Multi-Agent Coordinator
    ├── Knowledge Graph
    └── Security Pipeline (Mask → Sensor → Execute → Audit)
```

Plus 12 advanced modules: Exploitation, ML Anomaly, Threat Intel, Deception,
Distributed, OTel, Dashboard, Bootstrap, Stealth, Canary, Cloud Scanner, Compliance.

---

## 🤝 Contributing

We welcome contributions of all kinds! See [CONTRIBUTING.md](docs/contributing.md) to get started.

- **Report bugs**: Open a GitHub issue
- **Suggest features**: Start a discussion
- **Write code**: Look for `good first issue` tags
- **Improve docs**: PRs for documentation are always appreciated

---

## 📜 License

MIT — Use responsibly. Only scan systems you own or have explicit permission to test.
