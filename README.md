<p align="center">
  <img src="assets/logo.png" alt="Siyarix" width="120"/>
</p>

<h1 align="center">Siyarix</h1>

<p align="center">
  <b>CLI-based AI cybersecurity orchestration agent</b><br/>
  Routes natural-language security tasks through a multi-provider AI abstraction layer<br/>
  to plan and execute tool-based workflows.
</p>

<p align="center">
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/github/stars/mufthakherul/siyarix?style=flat-square&label=Stars&logo=github" alt="Stars"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/releases">
    <img src="https://img.shields.io/badge/Release-v2.0.0-blue?style=flat-square&logo=github" alt="Release"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/mufthakherul/siyarix?style=flat-square&label=License&logo=gnu" alt="License"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/mufthakherul/siyarix/ci.yml?style=flat-square&label=CI&logo=githubactions" alt="CI"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/pyproject.toml">
    <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python" alt="Python"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/releases">
    <img src="https://img.shields.io/badge/PyPI-pending-lightgrey?style=flat-square&logo=pypi" alt="PyPI"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/SPDX-AGPL--3.0--or--later-blue?style=flat-square" alt="SPDX"/>
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#license">License</a>
</p>

---

## Project Status

**Early-stage / under active development.**

Siyarix is an experimental project exploring how multi-provider AI orchestration can assist with security research, automated reconnaissance, and controlled assessment workflows. Expect breaking changes, incomplete features, and rough edges. Contributions and feedback welcome.

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

## Overview

Siyarix takes natural-language objectives (e.g., *"scan this subnet for open ports"*) and routes them through a pluggable AI provider layer to generate structured execution plans. Those plans are then executed using locally available security tools (nmap, nuclei, metasploit, etc.), with results parsed, analyzed, and logged.

The project is organized around three intersecting concerns:

| Area | Focus |
|------|-------|
| **AI orchestration** | Provider-agnostic task planning, failover routing, multi-model voting |
| **Security tooling** | Unified CLI interface over 100+ open-source security tools |

---

## Architecture

```
User input (CLI / chat / pipeline)
        |
Intent Router (4-stage: exact match, heuristic, keyword, LLM fallback)
        |
Task Planner (provider registry with automatic failover, circuit breakers)
        |
Permission Gate (syntax check / danger analysis)
        |
Execution Engine (parallel step execution, tool parsing, result aggregation)
```

Key architectural decisions:

- **Provider abstraction**: 10 provider adapters registered, preference-ordered fallback chains, no hard SDK dependency
- **Offline fallback**: Heuristic planner when no AI provider is available; local models via Ollama/LM Studio
- **Safety**: Two-stage permission gate, 38 dangerous-command patterns, emergency stop

---

## Capabilities

- CLI with 50+ commands across scan, recon, exploit, report, config, and security groups
- Interactive chat REPL with slash commands, multi-turn context, and SQLite-backed session persistence
- Multi-provider AI routing with automatic failover, circuit breakers, and session-disabled provider tracking
- Persona system — 10 security mindsets (red team, blue team, DFIR, cloud, appsec, etc.) plus auto and universal modes
- Multi-wave execution — LLM-driven iterative workflows with up to 5 waves and real-time streaming output
- Command review — interactive edit/run/step/cancel prompt before executing any shell command
- Security tool integration — 100+ tools discovered on PATH, 18+ output parsers
- Credential management — encrypted vault (AES-256-GCM), keyring integration, key rotation
- Knowledge graph — in-memory entity relationship modeling with BFS traversal
- Cloud/IoT/IaC/mobile scanning — built-in checks for AWS, Azure, GCP, firmware, APKs, Terraform
- Compliance frameworks — SOC2, ISO27001, NIST, PCI-DSS, GDPR, HIPAA automated assessments
- Playbook engine — reusable workflows with variables, conditionals, loops, and error handling
- Threat intelligence — MITRE ATT&CK mapping, MISP/STIX feed ingestion
- Deception — honeypot detection (9 signatures), canary tokens (7 types), trapdoor credentials

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
# Run a command
siyarix scan quick example.com

# Interactive session
siyarix

# Natural language
siyarix run "enumerate services on 10.0.0.1"
```

Set at least one AI provider API key (`OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`) or run local models via Ollama/LM Studio. See the [setup guide](docs/getting-started/setup.md) for details.

## Documentation

The full documentation lives in [`docs/`](docs/DOCS_MAP.md).

| Section | Contents |
|---------|----------|
| `getting-started/` | Installation, setup, configuration, troubleshooting |
| `user/` | CLI reference, security workflows, AI workflows, reporting, cloud/IaC/mobile/IoT scanning, compliance, playbooks, threat intel, deception, importing |
| `developer/` | Codebase overview, contribution guide, module architecture, testing, building |
| `architecture/` | System overview, AI agent pipeline, provider abstraction, execution engine, memory/state, security model, experience intelligence, interaction modes, intent routing |
| `ai/` | Multi-provider routing, prompt architecture, agent reasoning, tool execution, safety/hallucination handling, multi-model ensemble, MCP integration |
| `security/` | Ethical hacking policy, abuse prevention, threat model, vulnerability reporting, OPSEC, HSM integration |
| `legal/` | AGPL-3.0 license guide, NOTICE explanation, disclaimer, trademark policy, responsible AI usage |

Start with the [installation guide](docs/getting-started/installation.md).

Additional resources outside `docs/`:

| Resource | Description |
|----------|-------------|
| [AI_PROVIDER_POLICY.md](AI_PROVIDER_POLICY.md) | Provider governance, failover, security boundaries |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guide and development workflow |
| [ETHICAL_USE.md](ETHICAL_USE.md) | Permitted and prohibited use |
| [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md) | AI governance and transparency |
| [NOTICE](NOTICE) | Copyright notice, third-party attributions, provider architecture |
| [REBRANDING_AUDIT_REPORT.md](REBRANDING_AUDIT_REPORT.md) | License and branding compliance audit |
| [LEGAL_AUDIT_REPORT.md](LEGAL_AUDIT_REPORT.md) | Complete legal framework audit |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance and decision-making |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community guidelines |

---

## Safety & Ethical Use

Siyarix is designed for **authorized security testing, research, and defensive operations only**. It must not be used against systems without explicit permission.

- Unauthorized access, exploitation without consent, and any illegal activity are strictly prohibited
- Safe mode (`SIYARIX_SAFE_MODE=1`) restricts operations to reconnaissance only
- The permission gate blocks 38 dangerous command patterns
- All actions are logged to a tamper-evident SHA-256 chained audit trail

See [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md).

---

## License

**GNU Affero General Public License v3.0 or later** — SPDX: `AGPL-3.0-or-later`.

This is free software: you can redistribute and/or modify it under the terms of the AGPL-3.0 or any later version published by the Free Software Foundation. There is no warranty — see the [LICENSE](LICENSE) file for details.

---

## Author

**MD MUFTHAKHERUL ISLAM MIRAZ**

[github.com/mufthakherul/siyarix](https://github.com/mufthakherul/siyarix)

---

## Disclaimer

Siyarix is provided "as is", without warranty of any kind. It is a research and learning tool. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before testing any system. The authors assume no liability for misuse or damages.

---

## Vision

The project explores how declarative AI orchestration can simplify multi-tool security workflows — reducing overhead while maintaining human oversight. Future directions include richer multi-agent coordination with shared reasoning, improved offline planning through heuristic learning, and a plugin system for community-contributed tools and providers.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
