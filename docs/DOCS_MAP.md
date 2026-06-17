# 🗺️ Siyarix Documentation Map

Welcome to the comprehensive guide for Siyarix. Whether you're a first-time user, a seasoned security operator, or a developer looking to contribute, this map will help you navigate our extensive documentation.

---

## 🧭 Navigation Guide

Our documentation is organized into logical pillars to help you find exactly what you need.

```bash
docs/
├── getting-started/     # 🚀 Your first steps: Installation & Setup
├── user/                # 💻 Daily Operations: Commands & Workflows
├── developer/           # 🛠️ Building Siyarix: Codebase & Contributions
├── architecture/        # 🏗️ Under the Hood: System Design & Internals
├── ai/                  # 🧠 The Brain: Providers & Agent Reasoning
├── security/            # 🛡️ Safety First: Ethics, OPSEC & Threat Models
└── legal/               # ⚖️ Governance: Licensing & Policies
```

---

## 👥 Who Should Read What?

### 🌟 New Users (Start Here!)
Get Siyarix running and execute your first AI-powered commands.
1. [**Installation**](getting-started/installation.md) — Get it on your machine.
2. [**Onboarding Wizard**](getting-started/onboarding.md) — The 12-step guided setup.
3. [**Setup & Configuration**](getting-started/setup.md) — Configure keys and settings.
4. [**Your First Run**](getting-started/first-run.md) — Launch your first scan.

### 🛡️ Security Operators
Master the day-to-day security workflows and advanced features.
- [**Interactive Chat**](user/interactive-chat.md) — Using the AI-powered REPL.
- [**Security Workflows**](user/security-workflows.md) — Recon, Vuln Assessment, and IR.
- [**Cloud & IaC Scanning**](user/cloud-scanning.md) — Securing AWS, Azure, GCP, and Kubernetes.
- [**Compliance Frameworks**](user/compliance-frameworks.md) — SOC2, NIST, GDPR, and more.
- [**Threat Intelligence**](user/threat-intelligence.md) — MITRE ATT&CK & MISP integration.

### 🛠️ Developers & Contributors
Deep dive into the code and learn how to extend Siyarix.
- [**Contribution Guide**](developer/contribution-guide.md) — How to get involved.
- [**Codebase Overview**](developer/codebase-overview.md) — Understanding the module structure.
- [**Testing Suite**](developer/testing.md) — Keeping things stable with 100+ tests.
- [**Module Architecture**](developer/module-architecture.md) — Planners, Gates, and Engines.

---

## 📂 Documentation Tree

<details>
<summary><b>Click to expand the full documentation structure</b></summary>

```text
docs/
├── getting-started/
│   ├── installation.md          # Multi-platform install guide
│   ├── onboarding.md            # Interactive wizard walkthrough
│   ├── setup.md                 # Config & Credential management
│   ├── first-run.md             # Your very first session
│   ├── configuration.md         # Settings deep-dive
│   └── troubleshooting.md       # Common fixes
│
├── user/
│   ├── cli-commands.md          # 50+ CLI commands reference
│   ├── interactive-chat.md      # AI Chat & Slash commands
│   ├── security-workflows.md    # Real-world operation guides
│   ├── cloud-scanning.md        # Multi-cloud security
│   ├── compliance-frameworks.md # Automated compliance
│   ├── threat-intelligence.md   # MITRE & STIX feeds
│   ├── playbooks.md             # Reusable IR workflows
│   ├── workflow-files.md        # YAML/JSON DAG reference
│   ├── deception-and-canary-tokens.md # Honeypots & Canaries
│   ├── importing-findings.md    # Burp/Nessus/STIX imports
│   ├── offline-registry.md      # Local response registry
│   ├── iac-scanning.md          # Terraform & Helm security
│   ├── mobile-scanning.md       # APK static analysis
│   └── iot-scanning.md          # Firmware & Serial port analysis
│
├── developer/
│   ├── codebase-overview.md     # The Siyarix ecosystem
│   ├── contribution-guide.md    # Workflow & Standards
│   ├── module-architecture.md   # Component-level design
│   ├── testing.md               # Quality & Coverage
│   └── building.md              # Packaging & Distribution
│
├── architecture/
│   ├── overview.md              # High-level data flow
│   ├── ai-agent-pipeline.md     # Reasoning & Execution
│   ├── provider-abstraction.md  # 24-provider interface
│   ├── execution-engine.md      # Step orchestration
│   ├── memory-and-state.md      # Knowledge graph & caching
│   ├── security-model.md        # Permission gate & audit
│   ├── interaction-modes.md     # 9 interaction ways
│   └── intent-routing.md        # Semantic routing pipeline
│
├── ai/
│   ├── multi-provider-routing.md # Failover & Load balancing
│   ├── persona-system.md         # 10 security mindsets
│   ├── agent-reasoning.md        # Goal decomposition
│   ├── tool-execution.md         # Discovery & Parsing
│   └── multi-model-ensemble.md   # LLM Voting strategies
│
├── security/
│   ├── ethical-hacking-policy.md  # Rules of Engagement
│   ├── abuse-prevention.md        # Danger patterns & Safety
│   ├── operational-security.md    # TOR & Stealth features
│   └── hsm-integration.md         # Hardware security (TPM/YubiKey)
│
└── legal/
    ├── agpl-license-guide.md      # AGPL-3.0 overview
    ├── why-agpl.md                # Why we chose AGPL
    ├── trademark-policy.md        # Branding guidelines
    └── responsible-ai-usage.md    # AI Ethics & Transparency
```
</details>

---

## 🎯 Convention & Terminology

To keep our documentation consistent, we follow these naming conventions:

- **Provider**: An AI backend (e.g., OpenAI, Ollama).
- **Tool**: A security executable on your PATH (e.g., nmap).
- **Plan**: An AI-generated sequence of commands.
- **Workflow**: A predefined YAML/JSON DAG execution.
- **Persona**: A specialized behavioral framing for the AI.

---

*Found a mistake or want to add a page? Check our [Contribution Guide](developer/contribution-guide.md).*
