# Siyarix v1.0.0 Documentation

**Siyarix** is an AI-native cybersecurity operations platform that translates natural language into deterministic security workflows. It lives in your terminal, routes tasks across 24 AI providers, and orchestrates 80+ security tools with automatic output parsing. Built for penetration testers, security engineers, SOC analysts, and cloud architects.

## Quick Start

```bash
pip install siyarix
siyarix                          # Launch the onboarding wizard
siyarix scan quick example.com   # Run a quick port scan
siyarix scan deep example.com    # Run a deep reconnaissance scan
siyarix run "enumerate services on 10.0.0.1"  # Natural language
siyarix --mode offline run "scan example.com"  # Offline mode (no AI needed)
siyarix                          # Interactive REPL (default)
```

## Documentation Sections

| Section | Description |
|---------|-------------|
| [Getting Started](getting-started/installation.md) | Install, onboard, configure, first run |
| [User Guide](user/cli-commands.md) | CLI reference, workflows, playbooks |
| [Developer Guide](developer/codebase-overview.md) | Code structure, contribution guide, building |
| [Architecture](architecture/overview.md) | System design, data flow, internals |
| [AI System](ai/multi-provider-routing.md) | Providers, agent reasoning, multi-model |
| [Security](security/threat-model.md) | Threat model, OPSEC, abuse prevention |
| [Legal](legal/agpl-license-guide.md) | License, trademark, responsible AI |

## Who Is This For?

| Role | How Siyarix helps |
|------|-------------------|
| **Penetration Testers** | Automate recon, chain tools, generate structured reports |
| **Security Engineers** | Build playbooks, integrate into CI/CD, automate compliance |
| **SOC Analysts** | Streamline incident response, accelerate threat hunting, map to MITRE ATT&CK |
| **Cloud Architects** | Validate IaC, perform multi-cloud posture scanning |
| **Researchers** | Leverage AI-assisted analysis, build on the parser framework |

## Project Status

**Stable release** — v1.0.0 is production-ready. Breaking changes follow semantic versioning and are documented in the project Changelog.

> **Ethics & safety**: Siyarix is designed for authorized security testing only. Review the [Ethical Hacking Policy](security/ethical-hacking-policy.md) before use.
