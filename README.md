<p align="center">
  <img src="assets/logo.png" alt="Siyarix Logo" width="160"/>
</p>

<h1 align="center">Siyarix</h1>

<p align="center">
  <strong>Your AI-Powered Cybersecurity Orchestration Assistant</strong><br/>
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

  <!-- Community  -->
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

> ✋ **A Quick Heads-Up: We are moving!**  
> To better support our growing community, Siyarix will soon be migrating from my personal repository (`mufthakherul/siyarix`) to its very own dedicated GitHub organization: **`siyarix/siyarix`**.  
> Please read our [Migration Announcement](announcement/repo-migration-announcement.md) for all the details.

---

## 👋 Welcome to Siyarix!

Hello there! Welcome to **Siyarix**. What started as a personal passion project has steadily grown into a capable AI-driven Cybersecurity Orchestration Platform, built to help streamline security operations.

Have you ever wished you could just tell your security tools what to do in plain English? With Siyarix, you can! Whether you say *"scan this subnet for open ports"*, *"enumerate services on our main web server,"* or even *"perform a full external reconnaissance on example.com,"* Siyarix takes your natural language objective, plans the necessary steps, executes the right tools safely, analyzes the outputs, and generates a clear report for you. 

Under the hood, Siyarix is beautifully crafted in **Python 3.11+**. It features a modern, type-safe operations experience powered by **Typer CLI** for seamless terminal commands, **Rich** for gorgeous, readable terminal output, and **Pydantic** for robust data modeling. 

## 💡 Why Siyarix? The Problem We Solve

Security operations can be complex. Security professionals often juggle dozens of disparate CLI tools, each with its own obscure syntax, parsing messy text outputs, and manually stringing together workflows. 

Siyarix acts as your intelligent, tireless co-pilot. It bridges the gap between **human intent** and **machine execution**. 
- **No more memorizing flags:** Let the AI remember that `-p- -sV -T4` is the right `nmap` flag combination for your current goal.
- **Automated parsing:** Siyarix automatically reads the raw output of dozens of common security tools and turns it into structured, actionable intelligence.
- **Scale your efforts:** What normally takes manual typing and correlation can now be orchestrated with a simple plain-English sentence.

---

## 🤖 Agent Modes: Work How You Want to Work

Siyarix adapts to your comfort level and operational needs through four distinct modes:

| Mode | Best Used For | What it does |
|------|--------------|-------------|
| **REGISTRY** | Precise, manual control | Tool-driven mode. You run direct commands (e.g., `siyarix run nmap -sV example.com`), but our AI acts as your assistant, offering syntax help and planning advice on demand. |
| **AUTONOMOUS** | Broad objectives | Goal-driven mode. You set a high-level objective (*"Find vulnerabilities on this server"*), and the agent takes over. It uses an Observe-Reason-Act loop to independently plan, execute, and adapt until the goal is met. |
| **HYBRID** | Safe, supervised operations | The perfect middle ground! The AI proposes a detailed step-by-step plan, but it pauses and waits for your explicit human approval before running any potentially sensitive commands. |
| **INTERACTIVE** | Deep dive investigations | A full REPL (Read-Eval-Print Loop) session. Think of it as a dedicated chat interface in your terminal, featuring handy slash commands, a split-pane view, and real-time feedback. |

---

## ✨ Key Features in Detail

### 🧠 AI Orchestration

- **Multiple AI Providers Supported:** We integrate with the best in the business. Whether you prefer **OpenAI**, **Anthropic (Claude)**, **Groq**, or running **Local models** (like Ollama or LM Studio) completely offline, Siyarix supports it out of the box.
- **Resilient Failover:** API down? No problem. Siyarix features an automatic "circuit breaker." If your primary AI provider fails, the system automatically falls back to your secondary providers, ensuring your scan continues.
- **Swarm Agents:** For complex tasks, Siyarix decomposes objectives and spins up specialized sub-agents (e.g., a "Recon Agent", an "Exploit Agent", and a "Reporting Agent") that work together.
- **Semantic Memory:** Siyarix learns as it goes, building an in-memory "Knowledge Graph" of your infrastructure across sessions. If it finds an open port early on, it remembers to target it later.

### 🛠️ Security Tool Integration

- **Native Tool Parsers:** Siyarix doesn't just run tools; it *understands* them. We have native integrations for tools like `nmap`, `nuclei`, `metasploit`, `burpsuite`, `sqlmap`, and more. It takes their messy text output and turns it into clean JSON data for the AI to reason about.
- **Command Pipelines:** Chain your tools together using intuitive logic operators like `|`, `then`, or `and then`. *(Example: run subfinder `then` run httpx on the results)*.
- **Dynamic Plugins:** Have a custom script? You can easily load custom tool integrations from your `~/.siyarix/plugins/` directory.

### 🛡️ Safety & Ethical Operations

We know that combining AI with security tools can be daunting. We take safety seriously:
- **The Permission Gate:** We never run commands blindly. Siyarix features a two-stage danger analysis that checks every proposed command against high-risk patterns before execution. If it looks dangerous, it halts and asks for your permission.
- **Encrypted Credential Vault:** Never hardcode API keys or passwords. Store your sensitive credentials securely using our AES-256-GCM encrypted vault, which integrates directly with your operating system's native keyring.
- **Stealth Manager:** Our OPSEC manager handles request jitter, pacing, and User-Agent rotation to keep your operations quiet.
- **Tamper-Evident Logs:** Every single action, AI prompt, and tool execution is recorded in a cryptographically chained (SHA-256) audit log for total accountability.

### 💻 A Clean CLI Experience

- **Versatile Exports:** Generate structured outputs in 8 different formats including **Markdown, HTML, JSON, SARIF, XML, and CSV**.
- **Express Yourself:** Choose from **12 stunning color themes** (like SYNTHWAVE, CYBER_NOIR, ARCTIC, or MINIMAL) to match your terminal vibe.
- **Offline Mode:** Working in a secure, air-gapped environment? Siyarix's Offline Mode uses robust heuristic planning—meaning you can still run automated workflows without an external AI provider.

---

## 🔄 How It Works Under the Hood

Wondering what exactly happens when you hit enter? Here is a simplified look at the journey of your request:

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
6. Tool Registries (Runs tools like Nmap, Nuclei, etc.)
    |
    v
7. Smart Parsers (Converts raw terminal text into structured data)
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

Getting started is a breeze! When you run Siyarix for the very first time, an interactive **Onboarding Wizard** will launch to guide you through configuring your favorite AI providers.

```bash
# 1. Install easily via pip
pip install siyarix

# 2. Launch the interactive shell (this starts the onboarding wizard!)
siyarix

# 3. Try a quick pre-configured scan
siyarix scan quick example.com

# 4. Or talk to it in natural language!
siyarix run "enumerate services on 10.0.0.1 and output to a markdown file"

# 5. Delegate a broad goal to the autonomous agent
siyarix agent "find subdomains for example.com and check them for live web servers"

# 6. Working entirely offline? No problem.
siyarix --mode offline run "scan example.com"

# Check your system health and tool dependencies anytime
siyarix health
```

---

## 📦 Installation

The easiest way to install Siyarix is via Python's package manager:

```bash
pip install siyarix
```

*Prefer a different method?* We also support **Docker, Homebrew (macOS), Winget (Windows), Chocolatey, and `.deb` (Debian/Ubuntu)** packages! 

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

We strongly believe in building tools that protect, not harm. To ensure accountability, every single action, command, and AI prompt processed by the platform is permanently recorded in a tamper-evident audit trail. 

Before running your first scan, please read our full [ETHICAL_USE.md](ETHICAL_USE.md) and [RESPONSIBLE_AI_USE.md](RESPONSIBLE_AI_USE.md) policies.

---

## 🤝 Contributing

Siyarix started as a personal passion project, but it is **now officially public** and growing fast! 

We **warmly welcome** contributors of all skill levels. Whether you want to fix a typo in the documentation, add a new AI provider, or write a parser for a security tool you love, your help is deeply appreciated. 

> 👋 **Heads Up:** To better support our growing community of contributors, Siyarix will soon be moving to its very own dedicated GitHub organization (`siyarix/siyarix`). Don't worry, all links will seamlessly redirect!

Check out our [Contribution Guide](docs/developer/contribution-guide.md) to get started. Let's build the future of AI-assisted security together!

---

## ❤️ Meet the Author

**MD MUFTHAKHERUL ISLAM MIRAZ**

I absolutely love connecting with the community, hearing your feedback, and seeing how you use Siyarix! You can find me and the project here:  
[GitHub](https://github.com/mufthakherul/siyarix) | [siyarix.dev](https://siyarix.github.io)

---

## 📝 License

Siyarix is proudly open-source and released under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). This ensures the project remains free and open for everyone. For the full legal details, please see our [LICENSE](LICENSE) file.

---

<p align="center">
  <em>Helping secure the world, one command at a time. 🌍🔒</em>
</p>
