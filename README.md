# Siyarix

A CLI-based AI cybersecurity orchestration agent. Routes natural-language security tasks through a multi-provider AI abstraction layer to plan and execute tool-based workflows.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.txt)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![CI](https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml/badge.svg)](https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.3-orange)]()

---

## Project Status

**Early-stage / under active development.** Siyarix is an experimental project exploring how multi-provider AI orchestration can assist with security research, automated reconnaissance, and controlled red-team workflows. Expect breaking changes, incomplete features, and rough edges.

---

## About

Siyarix takes natural-language objectives (e.g., "scan this subnet for open ports") and routes them through a pluggable AI provider layer — currently supporting Gemini, OpenAI, Anthropic, Groq, Together, Ollama, LM Studio, and others — to generate structured execution plans. Those plans are then executed using locally available security tools (nmap, nuclei, metasploit, etc.), with results parsed, analyzed, and logged.

The project sits at the intersection of:

- **AI orchestration** — experimenting with provider-agnostic task planning, failover routing, and multi-model voting
- **Security tooling** — integrating 100+ open-source security tools through a unified CLI interface
- **Learning** — understanding how LLMs perform at cybersecurity task decomposition and tool selection

---

## Architecture (high-level)

```
User input (CLI / chat / pipeline)
        |
Intent Router (4-stage: exact match, heuristic, keyword, LLM fallback)
        |
Task Planner (provider registry with automatic failover, circuit breakers)
        |
Permission Gate (syntax check/danger analysis/persona ACL)
        |
Execution Engine (parallel step execution, tool parsing, result aggregation)
```

- **Provider abstraction**: 10 provider adapters registered, preference-ordered fallback chains, no hard SDK dependency
- **Offline fallback**: Heuristic planner when no AI provider is available; local models via Ollama/LM Studio
- **Safety**: Three-stage permission gate, 38 dangerous-command patterns, persona-based tool ACLs, kill switch

---

## Realistic capabilities

- CLI with 50+ commands across scan, recon, exploit, report, config, and security groups
- Interactive chat REPL with slash commands, multi-turn context, and session persistence
- Multi-provider AI routing with automatic failover and circuit breakers
- Security tool integration (100+ tools discovered on PATH; 18+ output parsers)
- Session management: SQLite-backed history, tamper-evident audit logging, session export
- Multi-agent framework: role-based agents (recon, scanner, exploiter, reporter) with message-passing coordination
- Credential management: encrypted vault (AES-256-GCM), keyring integration, key rotation
- Knowledge graph: in-memory entity relationship modeling with BFS traversal
- Cloud/IoT/IaC/mobile scanning: built-in security checks for AWS/Azure/GCP, firmware, APKs, Terraform
- Compliance frameworks: SOC2, ISO27001, NIST, PCI-DSS, GDPR, HIPAA automated assessments
- Playbook engine: reusable workflows with variables, conditionals, loops, and error handling
- Scheduled scans: cron-based recurring job scheduler
- Threat intelligence: MITRE ATT&CK mapping, MISP/STIX feed ingestion
- Deception: honeypot detection (9 signatures), canary tokens (7 types), trapdoor credentials
- Distributed task queue: Redis/RQ-backed for multi-node operation (experimental)

---

## Quick start

```bash
# Install
pip install siyarix

# Run a command
siyarix scan quick example.com

# Interactive session
siyarix

# Natural language
siyarix run "enumerate services on 10.0.0.1"
```

Requires Python 3.11+. Set at least one AI provider API key (`OPENAI_API_KEY`, `GEMINI_API_KEY`, or `ANTHROPIC_API_KEY`) or use local models via Ollama/LM Studio.

---

## Documentation

The full documentation is in `/docs`:

| Section | Contents |
|---------|----------|
| `getting-started/` | Installation, setup, configuration, troubleshooting |
| `user/` | CLI reference, security workflows, AI workflows, reporting, cloud/ IaC/ mobile/ IoT scanning, compliance, playbooks, scheduled scans, threat intel, deception, importing |
| `developer/` | Codebase overview, contributing, module architecture, testing, building |
| `architecture/` | System overview, AI agent pipeline, provider abstraction, execution engine, memory, security model, multi-agent, XI, intent routing, interaction modes |
| `ai/` | Multi-provider routing, prompts, agent reasoning, tool execution, safety, multi-model ensemble, MCP |
| `security/` | Ethical hacking policy, abuse prevention, threat model, vulnerability reporting, OPSEC, HSM |
| `legal/` | AGPL-3.0 guide, NOTICE explanation, disclaimer, trademark policy, responsible AI |
| `deployment/` | Distributed mode (Redis/RQ) |

Start with [getting-started/installation.md](docs/getting-started/installation.md).

---

## Safety & ethical use

Siyarix is designed for **authorized security testing, research, and defensive operations only**. It must not be used against systems without explicit permission.

- Unauthorized access, exploitation without consent, and any illegal activity are strictly prohibited
- Safe mode (`SIYARIX_SAFE_MODE=1`) restricts operations to reconnaissance only
- The permission gate blocks dangerous command patterns (38 signatures)
- All actions are logged to a tamper-evident audit trail

See [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md).

---

## License

**GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`).

This is free software: you can redistribute and/or modify it under the terms of the AGPL-3.0 or any later version published by the Free Software Foundation. There is no warranty — see the [LICENSE](LICENSE) file for details.

---

## Author

MD MUFTHAKHERUL ISLAM MIRAZ

[https://github.com/mufthakherul/siyarix](https://github.com/mufthakherul/siyarix)

---

## Disclaimer

Siyarix is provided "as is", without warranty of any kind. It is a research and learning tool. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before testing any system. The authors assume no liability for misuse or damages.

---

## Vision (short)

The project aims to explore how declarative AI orchestration can simplify security workflows — reducing the overhead of running multi-tool assessments while maintaining human oversight. Long-term directions include richer multi-agent coordination, improved offline planning, and a plugin system for community-contributed tools and providers.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
