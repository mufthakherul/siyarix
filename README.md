<p align="center">
  <img src="assets/logo.png" alt="Siyarix Logo" width="160"/>
</p>

<h1 align="center">Siyarix</h1>

<p align="center">
  <strong>Your AI-Powered Cybersecurity Orchestration Platform</strong><br/>
  <em>Translating your natural language goals into precise, multi-tool security workflows.</em>
</p>

<p align="center">
  <!-- Core Info -->
  <a href="https://github.com/mufthakherul/siyarix/releases">
    <img src="https://img.shields.io/badge/Release-v1.0.0-blue?style=for-the-badge&logo=github" alt="Release"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0--or--later-blue?style=for-the-badge&logo=gnu" alt="License"/>
  </a>

  <!-- Build & Quality -->
  <a href="https://github.com/mufthakherul/siyarix/actions/workflows/ci.yml">
    <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=githubactions" alt="Build Status"/>
  </a>
  <a href="https://www.codefactor.io/repository/github/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Quality-A%2B-brightgreen?style=for-the-badge" alt="Quality"/>
  </a>

  <!-- Package & Ecosystem -->
  <a href="https://pypi.org/project/siyarix/">
    <img src="https://img.shields.io/badge/PyPI-v1.0.0-blue?style=for-the-badge&logo=pypi" alt="PyPI"/>
  </a>
  <a href="https://pypi.org/project/siyarix/">
    <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python" alt="Python Version"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge&logo=linux" alt="Platforms"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker" alt="Docker"/>
  </a>

  <!-- Community (Static replacements for private repo) -->
  <a href="https://github.com/mufthakherul/siyarix">
    <img src="https://img.shields.io/badge/Stars-See%20GitHub-blue?style=for-the-badge&logo=github" alt="Stars"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/graphs/contributors">
    <img src="https://img.shields.io/badge/Contributors-Welcome-blue?style=for-the-badge&logo=github" alt="Contributors"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/issues">
    <img src="https://img.shields.io/badge/Issues-Tracked-blue?style=for-the-badge&logo=github" alt="Open Issues"/>
  </a>
  <a href="https://github.com/mufthakherul/siyarix/commits/main">
    <img src="https://img.shields.io/badge/Last%20Commit-Recent-blue?style=for-the-badge&logo=github" alt="Last Commit"/>
  </a>
</p>

<p align="center">
  <a href="#-welcome-to-siyarix">Overview</a> |
  <a href="#-why-siyarix-the-problem-we-solve">Why Siyarix?</a> |
  <a href="#-key-features-in-detail">Features</a> |
  <a href="#-how-it-works-under-the-hood-the-request-lifecycle">Architecture</a> |
  <a href="#-quick-start">Quick Start</a> |
  <a href="docs/DOCS_MAP.md">Documentation</a>
</p>

---

> 👋 **A Quick Heads-Up: We are moving!**  
> To better support our incredible community, Siyarix will soon be migrating from my personal repository (`mufthakherul/siyarix`) to its very own dedicated GitHub organization: **`siyarix/siyarix`**.  
> Please read our [Migration Announcement](announcement/repo-migration-announcement.md) for all the details.

---

## 👋 Welcome to Siyarix!

Hello there! Welcome to **Siyarix**—a production-grade, AI-driven Cybersecurity Orchestration Platform designed to completely transform how you approach security operations.

Have you ever wished you could just tell your security tools what to do in plain English? With Siyarix, you can! Whether you say *"scan this subnet for open ports"*, *"enumerate services on our main web server,"* or even *"perform a full external reconnaissance on example.com,"* Siyarix takes your natural language objective, intelligently plans the necessary steps, safely executes the right tools, analyzes the complex outputs, and finally generates a clear, comprehensive report for you. 

Under the hood, Siyarix is beautifully crafted in **Python 3.11+**. It features a modern, type-safe operations experience powered by **Typer CLI** for seamless terminal commands, **Rich** for gorgeous, readable terminal output, and **Pydantic** for robust, error-free data modeling. 

## 💡 Why Siyarix? The Problem We Solve

Modern security operations are complex. Security professionals often suffer from "tool fatigue"—juggling dozens of disparate CLI tools, each with its own obscure syntax, parsing messy text outputs, and manually stringing together workflows. 

Siyarix acts as your highly intelligent, tireless co-pilot. It bridges the gap between **human intent** and **deterministic machine execution**. 
- **No more memorizing flags:** Let the AI remember that `-p- -sV -T4` is the right `nmap` flag combination for your current goal.
- **No more manual parsing:** Siyarix automatically reads the raw output of over 80+ tools and turns it into structured, actionable intelligence.
- **Scale your efforts:** What would normally take hours of manual typing and correlation can now be orchestrated with a single plain-English sentence.

---

## 🤖 Agent Modes: Work How You Want to Work

Siyarix doesn't force you into a single workflow. It beautifully adapts to your comfort level and operational needs through four distinct modes:

| Mode | Best Used For | What it does |
|------|--------------|-------------|
| **REGISTRY** | Precise, manual control | Tool-driven mode. You run direct commands (e.g., `siyarix run nmap -sV example.com`), but our AI acts as your assistant, offering syntax help and planning advice on demand. |
| **AUTONOMOUS** | Broad, complex objectives | Goal-driven mode. You set a high-level objective (*"Find all vulnerabilities on this server"*), and the agent takes over. It uses an Observe-Reason-Act loop to independently plan, execute, and adapt until the goal is met. |
| **HYBRID** | Safe, supervised operations | The perfect middle ground! The AI proposes a detailed step-by-step plan, but it pauses and waits for your explicit human approval before running any potentially sensitive commands. |
| **INTERACTIVE** | Deep dive investigations | A full REPL (Read-Eval-Print Loop) session. Think of it as a dedicated chat interface in your terminal, featuring 40+ slash commands (`/model`, `/review`), a split-pane view, and real-time feedback. |

---

## ✨ Key Features in Detail

### 🧠 Advanced AI Orchestration

- **24+ AI Providers Supported:** We integrate with the best in the business. Whether you prefer the raw power of **OpenAI** and **Anthropic (Claude)**, the speed of **Groq**, or the privacy of running **Local models** (like Ollama or LM Studio) completely offline, Siyarix supports it out of the box.
- **Resilient Multi-Provider Failover:** API down? No problem. Siyarix features an automatic "circuit breaker." If your primary AI provider fails or rate-limits you, the system automatically falls back to your secondary providers with exponential backoff, ensuring your scan never dies halfway through.
- **Swarm Intelligence:** For massive tasks, Siyarix doesn't just use one brain. It decomposes complex objectives and spins up specialized sub-agents (e.g., a "Recon Agent", an "Exploit Agent", and a "Reporting Agent") that work together to solve the problem.
- **Semantic Memory & Knowledge Graph:** Siyarix learns as it goes. It builds an in-memory "Knowledge Graph" of your infrastructure across sessions. If it finds an open port in step 1, it naturally remembers to run a vulnerability scan on that specific port in step 5.

### 🛠️ Incredible Security Tool Integration

- **80+ Native Tool Parsers:** Siyarix doesn't just run tools; it *understands* them. We have native integrations for the tools you already love: `nmap`, `nuclei`, `metasploit`, `burpsuite`, `sqlmap`, `trivy`, `semgrep`, `theHarvester`, `subfinder`, and dozens more. It takes their messy text output and turns it into clean JSON data for the AI to reason about.
- **Powerful Command Pipelines:** Easily chain your tools together using intuitive logic operators like `|`, `then`, or `and then`. *(Example: run subfinder `then` run httpx on the results)*.
- **Dynamic Plugins:** Have a custom internal script? You can easily load custom tool integrations from your `~/.siyarix/plugins/` directory.

### 🛡️ Uncompromising Safety & Ethical Operations

We know that combining AI with security tools can be daunting. We take safety incredibly seriously:
- **The Permission Gate:** We never run commands blindly. Siyarix features a two-stage, AI-driven danger analysis that checks every proposed command against 38+ high-risk patterns before execution. If it looks dangerous, it immediately halts and asks for your permission.
- **Encrypted Credential Vault:** Never hardcode API keys or passwords. Store your sensitive credentials securely using our AES-256-GCM encrypted vault, which integrates directly with your operating system's native keyring.
- **Stealth & OPSEC Manager:** Conducting a red team engagement? Our OPSEC manager handles request jitter, pacing, decoy traffic, User-Agent rotation, and session isolation to keep your operations quiet and secure.
- **Tamper-Evident Logs:** Trust, but verify. Every single action, AI prompt, and tool execution is recorded in a cryptographically chained (SHA-256) audit log, ensuring total accountability.

### 💻 A Beautiful CLI Experience

- **Versatile Exports:** Security is only as good as the report. Generate beautiful, structured outputs in 8 different formats including **Markdown, HTML, JSON, SARIF, XML, and CSV**.
- **Express Yourself:** Staring at a terminal all day? Choose from **12 stunning color themes** (like SYNTHWAVE, CYBER_NOIR, ARCTIC, or MINIMAL) to match your workflow vibe.
- **Offline Mode:** Stuck on a plane or working in a highly secure, air-gapped environment? Siyarix's Offline Mode uses robust heuristic planning—meaning you can still run complex automated workflows without needing an external AI provider.

---

## 🔄 How It Works Under the Hood (The Request Lifecycle)

Wondering what exactly happens when you hit enter? Here is a simplified look at the fascinating journey of your request:

```text
1. You ask a question (e.g., "Find vulnerabilities on this web app")
    |
    v
2. Intent Router & Context Manager (Analyzes your request and gathers past data)
    |
    v
3. AI Planner (Drafts a multi-step plan of attack)
    |
    v
4. Permission Gate & Danger Analysis (Safety First!)
         |
    +----+----+
    |         |
 Looks Safe   High Risk (Pauses for your Manual Review!)
    |         |
    v         v
5. Execution Engine (Coordinates the actual work)
    |
    v
6. 80+ Tool Registries (Runs tools like Nmap, Nuclei, etc.)
    |
    v
7. 80+ Smart Parsers (Converts raw terminal text into structured data)
    |
    +-----------------------+-----------------------+
    |                       |                       |
8. Updates Knowledge Graph  Generates Rich Reports  Writes to Secure Audit Log
    |
    v
9. Self-Correction Loop (If a tool fails, the AI reasons why and tries a new approach!)
```

---

## 🚀 Quick Start

Getting started is an absolute breeze! When you run Siyarix for the very first time, a friendly interactive **Onboarding Wizard** will launch to guide you through configuring your favorite AI providers and checking which security tools you have installed.

```bash
# 1. Install easily via pip
pip install siyarix

# 2. Launch the interactive shell (this starts the onboarding wizard!)
siyarix

# 3. Try a quick pre-configured scan
siyarix scan quick example.com

# 4. Or talk to it in natural language!
siyarix run "enumerate services on 10.0.0.1 and output to a markdown file"

# 5. Delegate a massive goal to the autonomous agent
siyarix agent "find all subdomains for example.com, check them for live web servers, and scan for common CVEs"

# 6. Working entirely offline? No problem.
siyarix --mode offline run "scan example.com"

# Check your system health and tool dependencies anytime
siyarix health
```

---

## 📦 Installation

The absolute easiest way to install Siyarix is via Python's package manager:

```bash
pip install siyarix
```

*Prefer a different method?* We completely understand. We also support **Docker, Homebrew (macOS), Winget (Windows), Chocolatey, and `.deb` (Debian/Ubuntu)** packages! 

Check out our incredibly detailed [Installation Guide](docs/getting-started/installation.md) for step-by-step instructions for all platforms and optional extras.

---

## 📚 Comprehensive Documentation

Want to dive much deeper into what makes Siyarix tick? We have written extensive, easy-to-read guides ready for you:

| Explore This Guide | To Learn About... |
|---------|-------------|
| 🚀 [Getting Started](docs/getting-started/installation.md) | Step-by-step installation, initial setup, and troubleshooting common issues. |
| 📖 [User Guide](docs/user/cli-commands.md) | Full CLI reference, daily operational workflows, and advanced scanning methodologies. |
| 🧠 [AI Internals](docs/ai/agent-reasoning.md) | Fascinating details on how the AI thinks, reasons, corrects itself, and routes your requests. |
| 🏗️ [Architecture](docs/architecture/overview.md) | System design, our secure execution engine, and how the Knowledge Graph works. |
| 🛡️ [Security & Ethics](docs/security/ethical-hacking-policy.md) | Our strict ethical use policies, OPSEC configurations, and system safety measures. |

---

## ⚖️ A Note on Safety & Ethical Use

Siyarix is an incredibly powerful tool built **strictly for authorized security testing, legitimate research, and defensive operations**. 

> **🛑 CRITICAL REMINDER:** You must NEVER use Siyarix to scan, test, or interact with systems, applications, or networks without explicit, documented permission from their respective owners. 

We strongly believe in building tools that protect, not harm. To ensure absolute accountability, every single action, command, and AI prompt processed by the platform is permanently recorded in a tamper-evident audit trail. 

Before running your first scan, please take a brief moment to read our full [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md) policies.

---

## ❤️ Meet the Author

**MD MUFTHAKHERUL ISLAM MIRAZ**

I absolutely love connecting with the community, hearing your feedback, and seeing how you use Siyarix! You can find me and the project here:
[GitHub](https://github.com/mufthakherul/siyarix) | [siyarix.dev](https://siyarix.dev)

---

## 📝 License

Siyarix is proudly open-source and released under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). This ensures the project remains free and open for everyone. For the full legal details, please see our [LICENSE](LICENSE) file.

---

<p align="center">
  <em>Transforming how the world performs security operations, one command at a time. 🌍🔒</em>
</p>
