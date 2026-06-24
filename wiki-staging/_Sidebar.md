> [!NOTE]
> 👋 **Welcome to Siyarix!** This is a personal passion project built by a single developer. It's currently under active development and growing fast. Expect rough edges, but lots of love! ❤️

# 🗺️ Siyarix Documentation Map

Welcome to the **Siyarix Documentation Map**! This page serves as your master compass for navigating the extensive documentation we have built for the platform.

Whether you are a brand new user, a seasoned security operator, or a developer looking to contribute to the core engine, you can find exactly what you need here.

---

## 🧭 Quick Navigation

Not sure where to start? Pick the path that best describes you:

### 🌱 For New Users
Just getting started? We highly recommend following these guides in order:
1. **[Installation Guide](getting-started-installation)** — Get Siyarix running on your machine.
2. **[Onboarding Wizard](getting-started-onboarding)** — Let our interactive wizard help you set up your API keys and environment.
3. **[Setup & Configuration](getting-started-setup)** — A deeper dive into customizing your setup.
4. **[Your First Run](getting-started-first-run)** — A gentle walkthrough of your very first Siyarix command.

### 🛡️ For Security Operators
Ready to put Siyarix to work? Dive into our operational guides:
- **[Interactive Chat (REPL)](user-interactive-chat)** — Learn how to use the powerful interactive terminal.
- **[Security Workflows](user-security-workflows)** — Best practices for recon, vulnerability assessment, and incident response.
- **[Cloud & IaC Scanning](user-cloud-scanning)** — How to secure your cloud environments and infrastructure code.
- **[Compliance Frameworks](user-compliance-frameworks)** — Map your scans to SOC 2, HIPAA, ISO 27001, and more.

### 💻 For Developers & Contributors
Looking under the hood or wanting to write some code? Start here:
- **[Contribution Guide](developer-contribution-guide)** — Our workflow, standards, and how you can help!
- **[Codebase Overview](developer-codebase-overview)** — A comprehensive map of our 82+ source modules.
- **[Testing Standards](developer-testing)** — How we ensure reliability with pytest and CI/CD.
- **[Module Architecture](developer-module-architecture)** — Component design and responsibilities.

---

## 📂 The Complete Documentation Tree

If you prefer to browse the raw structure, here is a complete layout of the `docs/` folder:

```text
docs/
├── 🚀 getting-started/       # Installation, onboarding, and configuration
│   ├── installation.md       # Multi-platform install (pip, brew, winget, docker)
│   ├── onboarding.md         # The interactive 11-step setup wizard
│   ├── setup.md              # Managing API keys, credentials, and settings
│   ├── first-run.md          # A walkthrough of your first session
│   ├── configuration.md      # A deep-dive into advanced settings
│   └── troubleshooting.md    # Common issues and how to fix them instantly
│
├── 📖 user/                  # Daily operations and workflows
│   ├── cli-commands.md       # Reference for 50+ CLI commands across 12 groups
│   ├── interactive-chat.md   # Mastering the AI REPL and 54+ slash commands
│   ├── security-workflows.md # Recon, vulnerability assessment, incident response
│   ├── cloud-scanning.md     # Multi-cloud security scanning (under development)
│   ├── compliance.md         # Framework mapping (SOC 2, NIST, GDPR, PCI-DSS)
│   ├── threat-intelligence.md# Integrations with OTX, NVD, and MITRE ATT&CK
│   ├── playbooks.md          # Building automated YAML-based IR playbooks
│   ├── workflow-files.md     # DAG workflow reference (programmatic API)
│   ├── reporting.md          # Multi-format report generation
│   ├── offline-registry.md   # Running without AI (Offline/Registry execution mode)
│   └── ai-workflows.md       # Advanced AI-driven autonomous operations
│
├── 💻 developer/             # Building, testing, and extending Siyarix
│   ├── codebase-overview.md  # Full module structure mapping
│   ├── contribution-guide.md # How to submit PRs and our coding standards
│   ├── module-architecture.md# Component design and responsibilities
│   ├── testing.md            # Writing tests (pytest), coverage, and CI/CD
│   └── building.md           # Packaging, distribution, and Docker builds
│
├── 🏗️ architecture/          # System design and core internals
│   ├── overview.md           # High-level data flow and layered orchestration
│   ├── ai-agent-pipeline.md  # The AgentCore reasoning and execution pipeline
│   ├── provider-abstraction.md# How we unify 26 different AI providers
│   ├── execution-engine.md   # Plan-based step orchestration
│   ├── memory-and-state.md   # Knowledge graph, session persistence, and learning
│   ├── security-model.md     # The Permission Gate, DLP, audit logging, and OPSEC
│   └── intent-routing.md     # Semantic intent classification and routing
│
├── 🧠 ai/                    # Deep dive into the AI provider & agent systems
│   ├── routing.md            # Managing 26 providers, failovers, and circuit breakers
│   ├── persona-system.md     # Overview of our 10 security personas
│   ├── agent-reasoning.md    # The Observe-Reason-Act loop and tool call repair
│   ├── tool-execution.md     # The tool registry, capability graph, and parsers
│   ├── ensemble.md           # Parallel LLM voting strategies
│   ├── multi-wave.md         # Iterative goal execution with context carry-over
│   ├── prompt-architecture.md# System prompt design and management
│   └── safety.md             # Our rigorous 8-layer hallucination mitigation system
│
├── 🛡️ security/              # Safety, ethics, and threat models
│   ├── reporting.md          # How to safely report vulnerabilities to us
│   ├── threat-model.md       # System threat model and our mitigations
│   ├── operational-security.md# TOR routing, stealth modes, and OPSEC controls
│   ├── ethical-policy.md     # Mandatory rules of engagement for all users
│   └── abuse-prevention.md   # How we prevent misuse of the AI engine
│
└── ⚖️ legal/                 # Licensing and governance
    ├── agpl-guide.md         # A plain-English overview of the AGPL-3.0-or-later license
    ├── why-agpl.md           # The philosophy behind our license choice
    ├── trademark-policy.md   # Branding and trademark guidelines
    ├── responsible-ai.md     # Our framework for ethical AI usage
    ├── disclaimer.md         # Important legal disclaimers
    └── plugin-exception.md   # The license exception for building custom plugins
```

---

## 📖 Key Terminology

As you read through the documentation, you might encounter some specific terms. Here is a quick cheat sheet:

| Term | What It Means |
|------|---------------|
| **Provider** | The backend AI engine powering Siyarix (e.g., OpenAI, Anthropic, Ollama). |
| **Tool** | A traditional security executable installed on your system (e.g., `nmap`, `nuclei`). |
| **Plan** | A step-by-step sequence of tool commands intelligently generated by the AI. |
| **Workflow** | A hardcoded, predefined execution path (usually defined in YAML/JSON) that doesn't require AI generation. |
| **Persona** | A specialized behavioral profile given to the AI (e.g., instructing it to act specifically as a "Network Recon Specialist"). |
| **Knowledge Graph** | Siyarix's internal memory where it stores findings (like IP addresses, open ports) to contextually inform future steps. |

---

*Need help finding something specific? Feel free to use the search bar at the top of the documentation site, or open a discussion on our GitHub!*
