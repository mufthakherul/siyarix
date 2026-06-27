---
title: Siyarix Documentation - AI-Native Cybersecurity Orchestration Platform

> [!NOTE]
> 👋 **Welcome to Siyarix!** It's currently under active development and growing fast. Expect rough edges, but lots of love! ❤️

# 📚 Siyarix Documentation (v1.0.0)

Welcome to the official documentation for **Siyarix**! 👋 

Whether you are here to run your first automated scan, build an advanced incident response playbook, or contribute to our core AI engine, you are in the right place. 

## 🌟 What is Siyarix?

At its core, Siyarix is an **AI-native cybersecurity orchestration platform**. 

What does that mean? It means we bridge the gap between human intent and machine execution. Instead of memorizing obscure CLI flags or manually parsing text outputs, Siyarix allows you to state your security goals in plain English. It then uses advanced AI to plan the steps, orchestrates over **80+ security tools**, automatically parses their outputs, and generates beautiful, structured reports.

It lives right in your terminal, acting as your tireless, highly-intelligent security co-pilot.

---

## 🚀 Quick Start

Ready to dive right in? Here are a few quick commands to get you rolling. 

*(Note: On your very first run, a friendly Onboarding Wizard will help you set up your AI providers!)*

```bash
# 1. Install via pip
pip install siyarix

# 2. Launch the interactive REPL shell
siyarix

# 3. Run a quick, pre-configured port scan
siyarix scan quick example.com

# 4. Use natural language to get things done!
siyarix run "enumerate services on 10.0.0.1 and output to markdown"

# 5. Working in a secure, air-gapped environment? Use offline mode!
siyarix --mode offline run "scan example.com"
```

---

## 🗺️ Documentation Directory

We have organized our documentation to help you find exactly what you need. Choose your path below:

| Section | What You'll Find Inside |
|---------|-------------------------|
| 🛠️ **[Getting Started](getting-started/installation.md)** | Everything you need to install, set up your credentials, and run your very first scan. |
| 📖 **[User Guide](user/cli-commands.md)** | Your daily manual. Covers all CLI commands, interactive chat, and advanced security workflows. |
| 🧠 **[AI System](ai/multi-provider-routing.md)** | A deep dive into how our AI reasons, routes requests across 24+ providers, and keeps operations safe. |
| 🏗️ **[Architecture](architecture/overview.md)** | For the curious minds: how the execution engine, Knowledge Graph, and data flows actually work. |
| 🛡️ **[Security & Ethics](security/threat-model.md)** | Critical reading on our OPSEC controls, threat models, and mandatory ethical hacking policies. |
| 💻 **[Developer Guide](developer/codebase-overview.md)** | Want to contribute? Learn about our codebase structure, testing standards, and how to build Siyarix. |
| ⚖️ **[Legal & Governance](legal/agpl-license-guide.md)** | Licensing details (AGPL-3.0), trademark policies, and our Responsible AI framework. |

---

## 🎯 Who Is Siyarix Built For?

Siyarix is designed to empower a wide variety of security professionals:

| If you are a... | Siyarix helps you by... |
|-----------------|-------------------------|
| **Penetration Tester** | Automating tedious recon phases, intelligently chaining tools together, and generating perfectly structured reports for your clients. |
| **Security Engineer** | Allowing you to build repeatable, YAML-based playbooks, integrate security into CI/CD pipelines, and automate routine compliance checks. |
| **SOC Analyst** | Streamlining incident response, accelerating your threat hunting, and automatically mapping findings to the MITRE ATT&CK framework. |
| **Cloud Architect** | Validating your Infrastructure as Code (IaC) and performing consistent, multi-cloud posture scanning. |
| **Security Researcher** | Providing a robust parser framework and AI-assisted analysis so you can focus on finding novel vulnerabilities rather than writing glue code. |

## 🤝 Contributing

Siyarix started as a personal passion project, but it is **now officially public** and growing fast! 

We **warmly welcome** contributors of all skill levels. Whether you want to fix a typo in the documentation, add a new AI provider, or write a parser for a security tool you love, your help is deeply appreciated. 

> 👋 **Heads Up:** To better support our growing community of contributors, Siyarix will soon be moving to its very own dedicated GitHub organization (`siyarix/siyarix`). Don't worry, all links will seamlessly redirect!

Check out our [Contribution Guide](developer/contribution-guide.md) to get started. Let's build the future of AI-assisted security together!

---

## 📢 Project Status

**Stable Release** — Version `1.0.0` is currently production-ready! We strictly follow semantic versioning, and any breaking changes are always thoroughly documented in our project Changelog.

> [!WARNING]
> ## Ethics & Safety Reminder
> Siyarix is an incredibly powerful tool designed **exclusively for authorized security testing and defensive operations**. You must review and agree to our [Ethical Hacking Policy](security/ethical-hacking-policy.md) before using it. Never scan systems without explicit permission.
