<p align="center">
  <img src="assets/logo.png" alt="Siyarix" width="120"/>
</p>

<h1 align="center">Siyarix</h1>

<p align="center">
  <b>CLI-based AI-Native Cybersecurity Orchestration Agent</b><br/>
  Transform natural language security objectives into deterministic, tool-driven execution workflows<br/>
  across 24 AI providers, 114+ tool parsers, and 50+ CLI commands.
</p>

<p align="center">
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Stars-See%20GitHub-blue?style=flat-square&logo=github" alt="Stars"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/releases">
    <img src="https://img.shields.io/badge/Release-v3.0.0-blue?style=flat-square&logo=github" alt="Release"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0--or--later-blue?style=flat-square&logo=gnu" alt="License"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml">
    <img src="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/pyproject.toml">
    <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python" alt="Python"/>
  </a>
  <a href="https://pypi.org/project/siyarix/">
    <img src="https://img.shields.io/badge/PyPI-v3.0.0-blue?style=flat-square&logo=pypi" alt="PyPI"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/SPDX-AGPL--3.0--or--later-blue?style=flat-square" alt="SPDX"/>
  </a>
  <a href="https://www.codefactor.io/repository/github/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Quality-A%2B-brightgreen?style=flat-square" alt="Quality"/>
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#license">License</a>
</p>

---

## Overview

**Siyarix** is an AI-native cybersecurity operations platform that acts as your personal AI orchestration agent. It bridges the gap between natural language security objectives and deterministic tool execution — taking requests like *"scan this subnet for open ports"*, routing them through a multi-provider AI abstraction layer, generating structured execution plans, and running local security tools to deliver precise results.

```mermaid
graph LR
    A[Natural Language] --> B[Intent Router]
    B --> C[AI Planner]
    C --> D[Permission Gate]
    D --> E[Execution Engine]
    E --> F[114+ Parsers]
    F --> G[Structured Results]
```

---

## CLI Banner

```
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██║╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║ ╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║  ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║   ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝

                             S I Y A R I X
```

---

## Features

### AI Orchestration

| Capability | Detail |
|------------|--------|
| **24 AI Providers** | OpenAI, Gemini, Anthropic, Groq, Together, OpenRouter, DeepSeek, xAI, Mistral, Perplexity, Cerebras, Fireworks, Z.AI, MiniMax, Moonshot, NVIDIA, Hugging Face, Azure, OpenCode Go, Ollama, LM Studio, llama.cpp, vLLM, LocalAI |
| **Multi-Provider Routing** | Automatic failover, circuit breakers, session-disabled provider tracking, preference chains |
| **Multi-Model Ensemble** | Parallel LLM voting with configurable strategies (majority, consensus, weighted, best-score) |
| **Persona System** | 10 security mindsets — red team, blue team, DFIR, cloud sec, app sec, network sec, threat intel, governance, purple team, security explorer |
| **Multi-Wave Execution** | Iterative LLM-driven workflows with up to 5 waves, real-time streaming, and Live Rich display |
| **Offline Fallback** | Heuristic rule-based planner when no AI provider is available |

### Security Tooling

| Capability | Detail |
|------------|--------|
| **50+ CLI Commands** | Scan, recon, exploit, discover, agent, profile, audit, report, health, metrics, and more |
| **114+ Tool Parsers** | Structured output extraction from nmap, nuclei, masscan, metasploit, burpsuite, hydra, ffuf, gobuster, nikto, sqlmap, shodan, subfinder, amass, impacket, bettercap, and 100+ more |
| **100+ Tool Registry** | Automatic discovery of tools on PATH with capability tagging, platform detection, version checking |
| **Interactive Chat REPL** | Slash commands, multi-turn context, tab completion, SQLite-backed session persistence, Rich terminal UI |
| **Command Review** | Interactive edit/run/step/cancel prompt before executing any shell command |

### Security & Compliance

| Capability | Detail |
|------------|--------|
| **Credential Vault** | AES-256-GCM encrypted storage, OS keyring integration, key rotation |
| **Permission Gate** | Two-stage syntax check + danger analysis, 38 dangerous-command patterns |
| **Tamper-Evident Audit** | SHA-256 chained audit trail, SIEM forwarding (Splunk/ELK) |
| **Safe Mode** | Restrict to reconnaissance-only operations |
| **Knowledge Graph** | In-memory entity relationship model with BFS traversal for attack path discovery |
| **Compliance Frameworks** | SOC2, ISO27001, NIST, PCI-DSS, GDPR, HIPAA automated assessments |
| **Threat Intelligence** | MITRE ATT&CK mapping (13 tactics, 24+ techniques), MISP/STIX feed ingestion |
| **Deception** | Honeypot detection (9 signatures), canary tokens (7 types), trapdoor credentials |

### Scanning & Analysis

| Capability | Detail |
|------------|--------|
| **Cloud Scanning** | AWS (5 checks), Azure (3 checks), GCP (3 checks), Kubernetes, Docker |
| **IaC Scanning** | Terraform (15 checks), CloudFormation, Helm (7 checks), Dockerfile, secret detection |
| **Mobile Scanning** | Android APK analysis — dangerous permissions, insecure flags, hardcoded secrets |
| **IoT Scanning** | Firmware analysis (16 indicators), serial port enumeration, device type detection |
| **Import Engine** | Nessus, Burp Suite, Metasploit, STIX 2.x, OpenIOC format auto-detection and normalization |

### Automation & Workflows

| Capability | Detail |
|------------|--------|
| **Playbook Engine** | Reusable workflows with conditionals, loops, error handling, variables |
| **Workflow Files** | YAML/JSON DAG-based multi-step pipelines with dependency resolution |
| **Goal-Driven Agent** | Autonomous objective decomposition with Observe-Reason-Act loop |
| **9 Interaction Modes** | Interactive shell, conversational AI, direct command, autonomous agent, workflow automation, TUI dashboard, guided wizard, team collaboration, headless API |

---

## Architecture

```
User Input (CLI / Chat / Pipeline / API / Workflow)
        |
        ▼
┌───────────────────────────────┐
│       Intent Router           │
│  (Exact → Heuristic →        │
│   Keyword → LLM Fallback)    │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│      Task Planner             │
│  (24 AI Providers with        │
│   automatic failover,         │
│   circuit breakers)           │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│     Permission Gate           │
│  (Syntax Check → Danger       │
│   Analysis → User Review)     │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│     Execution Engine          │
│  (Parallel step execution,    │
│   DAG dependency resolution,  │
│   tool output parsing)        │
└───────────┬───────────────────┘
            │
            ▼
┌───────────────────────────────┐
│    Output & Reporting         │
│  (Table / JSON / YAML / CSV,  │
│   Audit Log, Session Log,     │
│   HTML/Markdown/PDF Reports)  │
└───────────────────────────────┘
```

Key architectural decisions:

- **Provider abstraction**: 24 provider adapters registered through a `ProviderManager` singleton with preference-ordered fallback chains and no hard SDK dependencies
- **Offline fallback**: Heuristic `RegistryPlanner` when no AI provider is available; local models via Ollama, LM Studio, llama.cpp, vLLM, LocalAI
- **Safety-first**: Two-stage permission gate (syntax + danger), 38 dangerous-command patterns, safe mode, tamper-evident SHA-256 chained audit trail
- **Plugin architecture**: Dynamic Python plugin loader from `~/.siyarix/plugins/`
- **Event-driven**: Internal event bus for component communication and OpenTelemetry-powered observability
- **Extreme parsing**: 114+ tool output parsers covering the most comprehensive set of security tools in the open-source ecosystem

---

## Installation

```bash
pip install siyarix
```

With optional AI provider SDKs and extras:

```bash
pip install "siyarix[openai,gemini,anthropic,cli,siem]"
# or install everything: pip install "siyarix[all]"
```

Requires Python 3.11+. See the [installation guide](docs/getting-started/installation.md) for platform-specific instructions (Homebrew, Winget, npm, Docker, source).

---

## Quick Start

```bash
# Interactive session (chat REPL)
siyarix

# Run a quick scan
siyarix scan quick example.com

# Natural language command
siyarix run "enumerate services on 10.0.0.1"

# Goal-driven autonomous agent
siyarix agent "find all vulnerabilities on our web server"

# System health check
siyarix health

# Setup with first-run wizard
siyarix init
```

Set at least one AI provider API key (`OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`) or run local models via Ollama/LM Studio. See the [setup guide](docs/getting-started/setup.md) for details.

---

## Documentation

The full documentation lives in [`docs/`](docs/DOCS_MAP.md) and is built with MkDocs Material.

| Section | Contents |
|---------|----------|
| `getting-started/` | Installation, setup, configuration, troubleshooting |
| `user/` | CLI reference, interactive chat, security workflows, AI workflows, reporting, cloud/IaC/mobile/IoT scanning, compliance, playbooks, threat intel, deception, importing |
| `developer/` | Codebase overview, contribution guide, module architecture, testing, building & packaging |
| `architecture/` | System overview, AI agent pipeline, provider abstraction, execution engine, memory/state, security model, experience intelligence, interaction modes, intent routing |
| `ai/` | Multi-provider routing, persona system, multi-wave execution, prompt architecture, agent reasoning, tool execution, safety/hallucination handling, multi-model ensemble |
| `security/` | Ethical hacking policy, abuse prevention, threat model, vulnerability reporting, OPSEC, HSM integration |
| `legal/` | AGPL-3.0 license guide, NOTICE explanation, disclaimer, trademark policy, responsible AI usage |

Additional resources outside `docs/`:

| Resource | Description |
|----------|-------------|
| [AI_PROVIDER_POLICY.md](AI_PROVIDER_POLICY.md) | Provider governance, failover, security boundaries |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guide and development workflow |
| [ETHICAL_USE.md](ETHICAL_USE.md) | Permitted and prohibited use |
| [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md) | AI governance and transparency |
| [NOTICE](NOTICE) | Copyright notice, third-party attributions, provider architecture |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance and decision-making |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community guidelines |

---

## Safety & Ethical Use

Siyarix is designed for **authorized security testing, research, and defensive operations only**. It must not be used against systems without explicit permission.

- Unauthorized access, exploitation without consent, and any illegal activity are strictly prohibited
- Safe mode (`SIYARIX_SAFE_MODE=1`) restricts operations to reconnaissance only
- The permission gate blocks 38 dangerous command patterns
- All actions are logged to a tamper-evident SHA-256 chained audit trail
- Bidirectional masking engine redacts sensitive data before sending to cloud AI providers

See [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md).

---

## Performance

- **102+ test files** with coverage targeting 75%+
- **47 CI/CD workflows** across GitHub Actions — lint, test (3 OS x 3 Python), security audit, Docker, packaging, SBOM, code quality
- **Cross-platform**: Windows, macOS, Linux, WSL2 — tested in CI
- **Distribution channels**: PyPI, npm, Homebrew, Winget, Chocolatey, Debian/APT, Docker, HarmonyOS

---

## License

**GNU Affero General Public License v3.0 or later** — SPDX: `AGPL-3.0-or-later`.

This is free software: you can redistribute and/or modify it under the terms of the AGPL-3.0 or any later version published by the Free Software Foundation. There is no warranty — see the [LICENSE](LICENSE) file for details.

---

## Author

**MD MUFTHAKHERUL ISLAM MIRAZ**

[github.com/mufthakherul/siyarix](https://github.com/mufthakherul/siyarix) | [siyarix.dev](https://siyarix.dev)

---

## Disclaimer

Siyarix is provided "as is", without warranty of any kind. It is a research and learning tool. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before testing any system. The authors assume no liability for misuse or damages.

---

## Vision

The project explores how declarative AI orchestration can simplify multi-tool security workflows — reducing overhead while maintaining human oversight. Future directions include richer multi-agent coordination with shared reasoning, improved offline planning through heuristic learning, expanded plugin ecosystem, and deeper integration with enterprise security stacks.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
