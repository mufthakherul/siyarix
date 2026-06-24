# Documentation Map

Guide to navigating the Siyarix documentation.

## Documentation Tree

```
docs/
├── getting-started/       # Installation, onboarding, configuration
│   ├── installation.md    # Multi-platform install (pip, brew, winget, docker)
│   ├── onboarding.md      # Interactive 11-step wizard
│   ├── setup.md           # API keys, credentials, settings
│   ├── first-run.md       # First session walkthrough
│   ├── configuration.md   # Settings deep-dive
│   └── troubleshooting.md # Common fixes
│
├── user/                  # Daily operations
│   ├── cli-commands.md    # 50+ CLI commands, 12 command groups
│   ├── interactive-chat.md# AI REPL with 54+ slash commands
│   ├── security-workflows.md  # Recon, vuln assessment, incident response
│   ├── cloud-scanning.md  # Multi-cloud security (under development)
│   ├── compliance-frameworks.md # SOC 2, NIST, GDPR, PCI-DSS, HIPAA, ISO 27001
│   ├── threat-intelligence.md  # OTX, NVD, MITRE ATT&CK integrations
│   ├── playbooks.md       # YAML-based IR playbook engine
│   ├── workflow-files.md  # DAG workflow reference (programmatic API)
│   ├── reporting.md       # Multi-format report generation
│   ├── offline-registry.md # Offline/registry execution mode
│   ├── ai-workflows.md    # AI-driven autonomous operations
│   ├── importing-findings.md # Finding import pipeline (coming soon)
│   ├── iac-scanning.md    # IaC security scanning (under development)
│   ├── mobile-scanning.md # Mobile app security (under development)
│   ├── iot-scanning.md    # IoT firmware security (under development)
│   └── deception-and-canary-tokens.md # Deception tech (under development)
│
├── developer/             # Building & extending Siyarix
│   ├── codebase-overview.md   # Full module structure (82 entries)
│   ├── contribution-guide.md  # Workflow & standards
│   ├── module-architecture.md # Component design & responsibilities
│   ├── testing.md             # pytest, coverage, CI/CD
│   └── building.md            # Packaging & distribution
│
├── architecture/          # System design & internals
│   ├── overview.md        # High-level data flow (layered orchestration)
│   ├── ai-agent-pipeline.md   # AgentCore reasoning & execution pipeline
│   ├── provider-abstraction.md # 26-provider unified interface
│   ├── execution-engine.md    # Plan-based step orchestration
│   ├── memory-and-state.md    # Knowledge graph, sessions, learning system
│   ├── security-model.md      # Permission gate, DLP, audit, OPSEC
│   ├── interaction-modes.md   # 5 interaction modes (CLI, REPL, batch, pipeline, agent)
│   └── intent-routing.md      # Semantic intent classification & routing
│
├── ai/                    # AI provider & agent systems
│   ├── multi-provider-routing.md # 26 providers, failover, circuit breaker
│   ├── persona-system.md       # 10 security personas + 3 special modes
│   ├── agent-reasoning.md      # ORA loop, planners, tool call repair
│   ├── tool-execution.md       # Tool registry, capability graph, installer
│   ├── multi-model-ensemble.md # Parallel LLM voting strategies
│   ├── multi-wave-execution.md # Iterative goal execution with context carry-over
│   ├── prompt-architecture.md  # System prompt design & management
│   └── safety-and-hallucination.md # 8-layer safety & hallucination mitigation
│
├── security/              # Safety, ethics & threat models
│   ├── vulnerability-reporting.md  # How to report vulnerabilities
│   ├── threat-model.md         # System threat model & mitigations
│   ├── operational-security.md # TOR, stealth, OPSEC controls
│   ├── hsm-integration.md      # HSM integration (under development)
│   ├── ethical-hacking-policy.md    # Rules of engagement
│   └── abuse-prevention.md     # 8-layer safety system
│
└── legal/                 # Licensing & governance
    ├── agpl-license-guide.md   # AGPL-3.0-or-later overview
    ├── why-agpl.md             # License rationale & philosophy
    ├── trademark-policy.md     # Branding guidelines
    ├── responsible-ai-usage.md # AI ethics framework
    ├── disclaimer.md           # Legal disclaimer
    ├── notice-file-explained.md  # NOTICE file explained
    └── plugin-exception.md     # Plugin license exception
```

## Quick Navigation

### New Users
1. [Installation](getting-started/installation.md)
2. [Onboarding Wizard](getting-started/onboarding.md)
3. [Setup & Configuration](getting-started/setup.md)
4. [First Run](getting-started/first-run.md)

### Security Operators
- [Interactive Chat](user/interactive-chat.md)
- [Security Workflows](user/security-workflows.md)
- [Cloud & IaC Scanning](user/cloud-scanning.md)
- [Compliance Frameworks](user/compliance-frameworks.md)

### Developers
- [Contribution Guide](developer/contribution-guide.md)
- [Codebase Overview](developer/codebase-overview.md)
- [Testing](developer/testing.md)
- [Module Architecture](developer/module-architecture.md)

## Conventions

| Term | Definition |
|------|------------|
| **Provider** | An AI backend (e.g., OpenAI, Ollama) |
| **Tool** | A security executable on PATH (e.g., nmap) |
| **Plan** | An AI-generated sequence of commands |
| **Workflow** | A predefined YAML/JSON DAG execution |
| **Persona** | A specialized behavioral framing for the AI |
