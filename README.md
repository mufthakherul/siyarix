# NexSec Security Agent

<div align="center">
  <img src="assets/logo.png" alt="NexSec Logo" width="200">
  <p><strong>A security agent by CosmicSec-Lab — Autonomous execution engine for DevOps, penetration testing & threat hunting.</strong></p>
  <p>
    <a href="https://github.com/CosmicSec-Lab/nexsec/actions/workflows/ci.yml"><img src="https://github.com/CosmicSec-Lab/nexsec/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
    <a href="https://github.com/CosmicSec-Lab/nexsec/blob/main/LICENSE"><img src="https://img.shields.io/github/license/CosmicSec-Lab/nexsec?style=flat-square" alt="License"></a>
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome">
  </p>
</div>

---

**NexSec** is a security agent that brings autonomous threat detection and intelligent tool orchestration to your terminal. Developed by CosmicSec-Lab, it combines dynamic task planning with integrated execution modes to automate security scanning, threat hunting, and incident management across DevOps and penetration testing workflows.

When you run `nexsec` with no subcommand, it opens an interactive command-center style chat experience. The landing screen shows your current mode, theme, session status, and model provider, plus quick actions for `/help`, `/tools`, `/key`, `/theme`, `/model`, and `/palette`.

## 🏗️ Architecture & Domain

NexSec is built as a modular security orchestrator. It uses a **Task Planner** to interpret high-level instructions (natural language or structured) and an **Execution Engine** to run these tasks using a suite of security tools.

- **Planner**: Converts instructions into a structured sequence of steps.
- **Engine**: Handles the execution of steps, managing tool registry, safety validation, and results.
- **Interpreters**: Heuristic and model-based interpreters for command understanding.

## 🚀 Quick Start

### Installation

```bash
pip install nexsec
```

### Basic Usage

```bash
# Run a simple scan
nexsec scan 192.168.1.1

# Run an autonomous command
nexsec run "scan example.com with nmap and nuclei then generate report"

# List discovered security tools
nexsec tool-registry list

# Launch the interactive assistant shell
nexsec

# Configure keys and theme from the interactive shell
# /key set gemini <your-api-key>
# /theme mode dark
# /theme appearance
```

## 📖 Documentation

- `docs/overview.md` — project goals and features
- `docs/architecture.md` — internal design and module breakdown
- `docs/cli-reference.md` — full command-line documentation
- `docs/installation.md` — detailed setup and model configuration
- `docs/usage.md` — common workflows and examples
- `docs/security.md` — secrets, vault, and audit trail guidance
- `docs/troubleshooting.md` — common issues and fixes

## 🤝 Contributing

We welcome contributions! Please see `docs/contributing.md` for guidelines on how to get started.

## 📜 License

NexSec is released under the [MIT License](LICENSE).
