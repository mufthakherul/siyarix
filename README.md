<p align="center">
  <img src="assets/logo.png" alt="Siyarix" width="160"/>
</p>

<h1 align="center">Siyarix</h1>

<p align="center">
  <strong>AI Cybersecurity Orchestration Agent</strong><br/>
  CLI-native, multi-provider AI orchestration platform for modern security operations.<br/>
  Translate natural language objectives into precise, multi-tool security workflows.
</p>

<p align="center">
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Stars-See%20GitHub-blue?style=for-the-badge&logo=github" alt="Stars"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/releases">
    <img src="https://img.shields.io/badge/Release-v3.0.0-blue?style=for-the-badge&logo=github" alt="Release"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0--or--later-blue?style=for-the-badge&logo=gnu" alt="License"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml">
    <img src="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"/>
  </a>
  <a href="https://pypi.org/project/siyarix/">
    <img src="https://img.shields.io/badge/PyPI-v3.0.0-blue?style=for-the-badge&logo=pypi" alt="PyPI"/>
  </a>
  <a href="https://www.codefactor.io/repository/github/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Quality-A%2B-brightgreen?style=for-the-badge" alt="Quality"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/mufthakherul/siyarix/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/mufthakherul/siyarix?style=for-the-badge&logo=github&color=blue" alt="Contributors"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/commits/main">
    <img src="https://img.shields.io/github/last-commit/mufthakherul/siyarix?style=for-the-badge&logo=github&color=blue" alt="Last Commit"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/github/repo-size/mufthakherul/siyarix?style=for-the-badge&logo=github&color=blue" alt="Repo Size"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/issues">
    <img src="https://img.shields.io/github/issues/mufthakherul/siyarix?style=for-the-badge&logo=github&color=blue" alt="Open Issues"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/pulls?q=is%3Apr+is%3Aclosed">
    <img src="https://img.shields.io/github/issues-pr-closed/mufthakherul/siyarix?style=for-the-badge&logo=github&color=blue" alt="Closed PRs"/>
  </a>
  <a href="https://pypi.org/project/siyarix/">
    <img src="https://img.shields.io/pypi/dm/siyarix?style=for-the-badge&logo=pypi&color=blue" alt="Downloads"/>
  </a>
</p>

<p align="center">
  <a href="#overview">Overview</a> |
  <a href="#features">Features</a> |
  <a href="#architecture">Architecture</a> |
  <a href="#quick-start">Quick Start</a> |
  <a href="#installation">Installation</a> |
  <a href="docs/DOCS_MAP.md">Documentation</a>
</p>

---

## Overview

Siyarix is a production-grade **AI Cybersecurity Orchestration Agent** that bridges natural language security objectives with deterministic multi-tool execution. Describe your goal in plain English -- "scan this subnet for open ports" or "enumerate services on the web server" -- and Siyarix plans, executes, analyzes, and reports using an extensible multi-provider AI core and a comprehensive security tool registry.

Built on **Python 3.11+** with **Typer CLI**, **Rich** terminal output, and **Pydantic** data models, Siyarix delivers a modern, type-safe security operations experience.

### Agent Modes

Siyarix v3.0.0 operates in four distinct modes:

| Mode | Description |
|------|-------------|
| **REGISTRY** | Tool-driven mode -- direct command execution with AI-assisted planning |
| **AUTONOMOUS** | Goal-driven autonomous agent with Observe-Reason-Act loop |
| **HYBRID** | Mixed initiative -- AI proposes, human approves |
| **INTERACTIVE** | Full REPL session with 40+ slash commands and real-time feedback |

### Request Lifecycle

```
User Intent
    |
    v
Intent Router --> Context Manager --> AI Planner --> Permission Gate
                                                         |
                                            +------------+------------+
                                            |                         |
                                        Approved                  High Risk
                                            |                     Manual Review
                                            v                         |
                                    Execution Engine <---------------+
                                            |
                                    Tool Registry
                                            |
                                     80+ Tools --> 80+ Parsers
                                            |
                            +---------------+---------------+
                            |               |               |
                     Knowledge Graph    Rich Reports    Audit Log
                            |
                     Self-Correction Loop
```

---

## Features

### AI Orchestration

- **24+ AI Providers**: OpenAI, Anthropic (Claude), Google Gemini, Groq, Mistral AI, Together AI, OpenRouter, DeepSeek, xAI (Grok), Perplexity, Cerebras, Fireworks AI, HuggingFace Inference, Azure OpenAI, NVIDIA Nemotron, MiniMax, Moonshot (Kimi), vLLM, Ollama, LM Studio, llama.cpp, LocalAI, OpenCodeGo, ZAI, plus offline heuristic registry
- **Multi-Provider Failover**: Automatic circuit breaker pattern with exponential backoff across configured providers
- **Multi-Model Ensemble**: Parallel LLM voting (MAJORITY, CONSENSUS, WEIGHTED, BEST_SCORE) for critical decisions
- **Swarm Multi-Agent Orchestration**: Decompose complex objectives across specialized sub-agents
- **Continuous Learning**: Semantic memory via vector embeddings with cosine similarity search and experience recording
- **Semantic Memory**: Persistent knowledge graph for cross-session infrastructure modeling
- **Agent Core**: LLM-first planning, parallel tool execution, and LLM synthesis in a closed feedback loop

### Security Tool Integration

- **80+ Tool Parsers**: Structured output extraction for nmap, nuclei, masscan, gobuster, ffuf, hydra, nikto, metasploit, burpsuite, zaproxy, sqlmap, wpscan, trivy, grype, semgrep, gitleaks, trufflehog, theHarvester, Amass, Subfinder, Sublist3r, assetfinder, findomain, dnsrecon, dnsenum, massdns, shuffledns, dnsx, httpx, katana, hakrawler, gospider, waybackurls, gau, wfuzz, dirb, dirsearch, feroxbuster, kiterunner, arjun, paramspider, corsy, dalfox, kxss, xsstrike, commix, jwt_tool, wafw00f, whatweb, aquatone, gowitness, bettercap, responder, crackmapexec, impacket, mimikatz, pypykatz, bloodhound, sharphound, certipy, kerbrute, ldapsearch, enum4linux, smbclient, smbmap, evil-winrm, ssh_audit, sslscan, sslyze, testssl, dig, whois, shodan, searchsploit, lynis, scoutsuite, prowler, checkov, kubectl, aws, volatility, yara, tcpdump, dmitry, finger, ike_scan, netcat, smtp_user_enum, hashcat, hash_identifier, john, exiftool, s3scanner, zmap, zgrab, rustscan, naabu, interactsh, recon-ng, aircrack-ng, ettercap, and more
- **Command Pipeline**: Chain tool executions with `|` / `then` / `and then` operators
- **Plugin System**: Dynamic discovery and loading from `~/.siyarix/plugins/`

### CLI & Interface

- **50+ CLI Commands** across 12 command groups: `scan`, `recon`, `exploit`, `report`, `config`, `security`, `incidents`, `vulns`, `hunt`, `mitre`, `playbooks`, `dashboard`
- **Interactive REPL** with 40+ slash commands (`/model`, `/persona`, `/review`, `/key`, etc.)
- **12 Color Themes**: CYBER_NOIR, MATRIX, BLOODMOON, ARCTIC, GOLDENROD, ECLIPSE, SYNTHWAVE, DARK, LIGHT, NEON, MINIMAL, DEFAULT
- **REST API (FastAPI)** + WebSocket at `/v1/*` endpoints with JWT authentication
- **8 Output Formats**: TABLE, JSON, YAML, CSV, HTML, XML, RAW, QUIET
- **4 Report Engine Formats**: MARKDOWN, HTML, JSON, SARIF
- **Shell Completions**: bash, zsh, fish, PowerShell
- **Session Branching**: Fork and explore alternate execution paths concurrently

### Security & Safety

- **Permission Gate**: Two-stage AI-driven danger analysis before command execution
- **Credential Store**: AES-256-GCM encrypted vault for API keys and secrets
- **Stealth Engine**: TOR routing support and honeypot detection
- **DLP Engine**: Data loss prevention with pattern-based sensitive data detection
- **OPSEC Manager**: Operational security controls and countermeasures
- **Tamper-Evident Audit Log**: SHA-256 chained cryptographic audit trail with verify command
- **Health Checker**: System diagnostics with `siyarix health` command
- **Event Bus**: Asynchronous event-driven architecture for internal communication
- **Metrics**: Performance and usage metrics collection

### Compliance & Intelligence

- **Compliance Engine**: Framework-based compliance checking (PCI-DSS, HIPAA, ISO 27001, SOC 2)
- **Threat Intel**: Structured threat intelligence consumption and correlation
- **Knowledge Graph**: In-memory relationship model of scanned infrastructure
- **Report Engine**: Multi-format report generation (MARKDOWN, HTML, JSON, SARIF)
- **Output Engine**: Structured output in 8 formats with customizable verbosity

### Deployment

- **Package Distribution**: PyPI (pip), Homebrew, Chocolatey, Winget, .deb, Docker
- **Docker Compose**: Multi-service orchestration with worker, dashboard, Redis, OpenTelemetry collector
- **CI/CD**: 47 GitHub Actions workflows including CI, Docker publish, release, CodeQL, SBOM, secrets scan, docs deploy, smoke tests, chaos testing, benchmarks, Dependabot

---

## Quick Start

On first run, Siyarix launches an interactive **Onboarding Wizard** to configure AI providers and security tools.

```bash
# Install via pip
pip install siyarix

# Launch the interactive REPL (triggers onboarding on first run)
siyarix

# Quick scan
siyarix scan quick example.com

# Natural language command
siyarix run "enumerate services on 10.0.0.1"

# Goal-driven autonomous agent
siyarix agent "find all vulnerabilities on our web server"

# System health check
siyarix health
```

---

## Installation

```bash
pip install siyarix
```

For alternative package managers (Homebrew, Chocolatey, Winget, .deb, Docker) and optional extras for specific AI providers, see the [Installation Guide](docs/getting-started/installation.md).

---

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started/installation.md) | Installation, setup, onboarding, troubleshooting |
| [User Guide](docs/user/cli-commands.md) | CLI reference, workflows, scanning methodology |
| [AI Internals](docs/ai/agent-reasoning.md) | Provider routing, personas, reasoning architecture |
| [Architecture](docs/architecture/overview.md) | System design, execution engine, security model |
| [Security & Ethics](docs/security/ethical-hacking-policy.md) | Ethical use policy, threat models, OPSEC |

---

## Safety & Ethical Use

Siyarix is designed exclusively for **authorized security testing, research, and defensive operations**. It must not be used against systems without explicit, documented permission. Every action is logged to a tamper-evident audit trail ensuring full accountability.

See [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md) for detailed policies.

---

## Author

**MD MUFTHAKHERUL ISLAM MIRAZ**

[github.com/mufthakherul/siyarix](https://github.com/mufthakherul/siyarix) | [siyarix.dev](https://siyarix.dev)

---

## License

Siyarix is released under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). See the [LICENSE](LICENSE) file for the full legal text.

---

*Transforming how the world performs security operations, one command at a time.*
