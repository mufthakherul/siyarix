# Welcome to Siyarix v3

Hey there! 👋 Welcome to **Siyarix** — your intelligent, AI-native cybersecurity operations agent. 

Imagine having a brilliant security analyst sitting right inside your terminal, ready to translate your natural language requests into complex, deterministic security workflows. That's Siyarix. We bridge the gap between what you want to do and the actual command-line tools required to do it.

Just tell Siyarix what you need in plain English — *"scan this subnet for open ports and check for known CVEs"* — and watch as it dynamically routes your request, designs an execution plan, safely runs the required open-source tools, and gives you back structured, actionable insights.

---

## Why Siyarix?

> **Human oversight, machine speed.**

We built Siyarix because we believe AI shouldn't replace security operators. Instead, it should take on the tedious, repetitive tasks — like writing complex tool syntax, parsing messy outputs, and gluing workflows together — so you can focus on the big picture.

Our core design pillars:

- 💻 **CLI-First**: We live in the terminal. No clunky web dashboards, no distractions.
- 🧠 **Provider Agnostic**: Use OpenAI, Anthropic, Gemini, or run entirely offline with local models (Ollama, LM Studio). If one provider hiccups, our smart routing automatically fails over to the next.
- 🛡️ **Safe & Deterministic**: We don't just blindly run AI-generated commands. Every execution passes through a rigorous two-stage permission gate. 38 dangerous patterns are blocked by default.
- 🛠️ **Extreme Parsing**: We have over 114+ built-in parsers that transform raw, messy terminal output from your favorite security tools into structured, readable data.

---

## What Can Siyarix Do?

Siyarix is packed with features designed to make your day-to-day security operations smoother and more powerful.

| What We Do Best | How We Do It |
|-----------------|--------------|
| **AI Orchestration** | Dynamically routes tasks across **24 AI providers** with automatic failover, circuit breakers, and even multi-model ensemble voting. No internet? No problem. Our offline heuristic fallback keeps you moving. |
| **Security Tooling** | Automatically discovers over 100+ tools on your PATH. Siyarix executes them intelligently and parses their outputs into beautifully structured findings. |
| **Workflow Automation** | Build reusable YAML/JSON pipelines, run comprehensive playbooks, or unleash goal-driven autonomous agents with our Observe-Reason-Act loop. |
| **Compliance & Intel** | Maps your findings directly to MITRE ATT&CK, ingests MISP/STIX feeds, and assesses your posture against SOC2, ISO27001, NIST, PCI-DSS, GDPR, and HIPAA. |
| **Cloud & Infrastructure** | Seamlessly scans AWS, Azure, GCP, Kubernetes, Docker, Terraform, CloudFormation, and Helm for misconfigurations. |
| **Mobile & IoT** | Analyze Android APKs statically, inspect IoT firmware, enumerate serial ports, and identify devices on the fly. |
| **Safety & OPSEC** | Your security is our priority. Enjoy a two-stage permission gate, an encrypted credential vault, a tamper-evident audit trail, TOR routing, and a dedicated stealth mode. |

---

## Ready to Dive In?

<div class="grid cards" markdown>

-   :material-rocket-launch: **Get Up and Running**

    ---

    Install Siyarix and configure your workspace in just a few minutes.

    [Installation Guide](getting-started/installation.md)

-   :material-console: **Master the CLI**

    ---

    Explore all available commands, interactive chat features, and specialized workflows.

    [CLI Reference](user/cli-commands.md)

-   :material-brain: **Peek Under the Hood**

    ---

    Curious how it works? Dive into our multi-provider routing and agent reasoning engines.

    [AI Agent Pipeline](architecture/ai-agent-pipeline.md)

-   :material-security: **Our Security Model**

    ---

    Learn exactly how Siyarix keeps your executions safe, secure, and fully auditable.

    [Security Architecture](architecture/security-model.md)

</div>

---

## Quick Start

Want to see it in action? Here are a few commands to get you started immediately:

```bash
# Launch the interactive, context-aware REPL
siyarix

# Run a quick, predefined scan
siyarix scan quick example.com

# Speak its language
siyarix run "enumerate services on 10.0.0.1"

# Unleash an autonomous agent
siyarix agent "find all vulnerabilities on the web server"

# Check your system health
siyarix health
```

---

## Who Is This For?

Whether you're breaking things or defending them, Siyarix has your back:

| Your Role | How Siyarix Helps |
|-----------|-------------------|
| **Penetration Testers** | Automate your recon, intelligently chain tools together, and generate structured reports effortlessly. |
| **Security Engineers** | Build custom playbooks, integrate directly into CI/CD pipelines, and automate compliance checks. |
| **SOC Analysts** | Streamline incident response workflows, accelerate threat hunting, and map everything to MITRE ATT&CK. |
| **Cloud Architects** | Validate infrastructure as code (IaC) and perform multi-cloud posture scanning in seconds. |
| **Researchers & Students** | Leverage AI-assisted analysis, build on our extensible parser framework, or simply learn how security tools interact. |

---

## Project Status

**Stable Release** — You are looking at the documentation for **v3.0.0**, our most robust and feature-rich release yet! It is fully stable and ready for production security assessments. Any breaking changes follow strict semantic versioning and are clearly documented in our [Changelog](../CHANGELOG.md).

---

> **A Quick Note on Ethics & Safety**: Siyarix is a powerful tool designed strictly for authorized security testing, research, and defensive operations. Unauthorized access or exploitation without explicit, documented consent is absolutely prohibited. Please review our [Ethical Hacking Policy](security/ethical-hacking-policy.md) before you begin.
