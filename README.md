# Phalanx Security Agent

<div align="center">
  <img src="assets/logo.png" alt="Phalanx Logo" width="200">
  <p><strong>A humble, open-source security agent by CosmicSec-Lab. Built for learning, research, and community collaboration.</strong></p>
  <p>
    <a href="https://github.com/CosmicSec-Lab/phalanx/actions/workflows/ci.yml"><img src="https://github.com/CosmicSec-Lab/phalanx/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
    <a href="https://github.com/CosmicSec-Lab/phalanx/blob/main/LICENSE"><img src="https://img.shields.io/github/license/CosmicSec-Lab/phalanx?style=flat-square" alt="License"></a>
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome">
  </p>
</div>

---

**Phalanx** is a command-line security agent that explores how we can combine autonomous AI planning with classic security tools right in the terminal. Whether you're scanning a network, hunting for vulnerabilities, or just trying to learn how different security tools work together, Phalanx is here to act as your helpful assistant.

### 🌱 Our Story
Phalanx started out as a humble college project to experiment with AI and security automation. As the codebase grew and became surprisingly useful, we decided to open-source it! Today, it's maintained by the CosmicSec-Lab community. We don't claim to be an "ultra-premium enterprise solution"—rather, Phalanx is a practical, lightweight, and modern tool meant for students, researchers, penetration testers, and anyone curious about AI-driven security.

When you run `phalanx` in your terminal, it opens an interactive chat experience where you can naturally ask the agent to help you scan networks, run security tools, and understand vulnerabilities.

## ✨ Core Features

- **Interactive AI Assistant (Chat Mode)**: A polished, terminal-based REPL where you can chat with large language models (OpenAI, Gemini, local Ollama) to plan and execute security tasks.
- **Autonomous Tool Orchestration**: Phalanx doesn't just talk; it can actually run tools like `nmap`, `ffuf`, and `nuclei` on your machine, parse their output, and summarize the results.
- **Cross-Platform Intelligence**: Whether you are on Linux (Bash/Zsh), macOS, or Windows (PowerShell/CMD), Phalanx understands your environment and translates security intents into commands that actually work.
- **Secure Credential Vault**: Your API keys are encrypted locally and never exposed in plaintext or sent anywhere without your permission.
- **Local Tool Discovery**: The agent automatically scans your system `PATH` to figure out which security tools you have installed, so it only recommends plans you can actually execute.

## 🏗️ How It Works (High-Level Architecture)

Phalanx is built to be simple, modular, and transparent. We want you to look under the hood and learn how it works!

1. **The Planner**: Takes your natural language instructions (e.g., "Find open ports on example.com") and figures out the logical steps to achieve them.
2. **The Execution Engine**: Safely executes the planned steps. It checks if the required tools exist, runs them in the background, and captures the standard output and errors.
3. **The Shell Knowledge Library**: Helps Phalanx understand your operating system so it can write commands natively (like using `Test-NetConnection` on Windows vs `ping` on Linux).

*(For a deep dive into the code structure, check out our [Architecture Guide](docs/architecture.md)!)*

## 🚀 Quick Start

### Installation

The easiest way to get started is using Python (3.11+ is required). We highly recommend using a virtual environment or a modern package manager like `uv`.

```bash
# Using pip
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate
pip install phalanx
```

*(Note: For the full AI-planning experience, you can install the optional dependencies: `pip install "phalanx[autonomous]"`).*

### Basic Usage

You can use Phalanx directly from the command line for quick tasks:

```bash
# Run a simple network scan
phalanx scan 192.168.1.1

# Tell the agent what to do using natural language
phalanx run "scan example.com with nmap and nuclei, then summarize the results"

# List the security tools Phalanx has found on your system
phalanx tool-registry list
```

### The Interactive Chat

For the best experience, just run `phalanx` with no arguments. This launches the interactive chat assistant!

```bash
phalanx
```

Once inside the interactive shell, you can use slash commands to configure your environment:
```text
/key set gemini <your-api-key>
/theme mode dark
/help
```

## 📖 Comprehensive Documentation

Whether you're just getting started or looking to understand the internals, our detailed docs have you covered:

- **[Overview (docs/overview.md)](docs/overview.md)** — A detailed look at what Phalanx is and why we built it.
- **[Architecture (docs/architecture.md)](docs/architecture.md)** — Comprehensive breakdown of the internals, planners, and engines.
- **[CLI Reference (docs/cli-reference.md)](docs/cli-reference.md)** — A complete, detailed list of all commands and flags.
- **[Installation (docs/installation.md)](docs/installation.md)** — Step-by-step setup guides for various environments.
- **[Usage Guide (docs/usage.md)](docs/usage.md)** — Extensive examples of how to use Phalanx day-to-day.
- **[Security & Privacy (docs/security.md)](docs/security.md)** — How we handle your data, API keys, and keep executions safe.
- **[Troubleshooting (docs/troubleshooting.md)](docs/troubleshooting.md)** — Help when things go wrong.

## 🤝 Contributing & Community

We absolutely love contributions! Since Phalanx is a community project, we welcome everyone—especially beginners, students, and hobbyists looking for their first open-source project. 

If you want to add a new tool parser, fix a bug, or just improve these docs, check out our [Contributing Guide](docs/contributing.md) and [Development Guide](docs/development.md) for a friendly introduction to the codebase.

## 📜 License

Phalanx is released under the [MIT License](LICENSE). 

*Please use it responsibly. Only run security scans against systems, networks, and applications that you own or have explicit, documented permission to test. Be safe and happy hacking!*
