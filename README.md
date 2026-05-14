<div align="center">
  <img src="assets/logo.png" alt="Cosmic Security Agent Logo" width="160" />
  <h1>🚀 NexSec</h1>
  <p><strong>A security agent by CosmicSec-Lab — AI-powered hybrid execution for DevOps, penetration testing & threat hunting.</strong></p>
  
  <p>
    <a href="https://github.com/CosmicSec-Lab/cosmicsec-cli/actions"><img src="https://img.shields.io/github/actions/workflow/status/CosmicSec-Lab/cosmicsec-cli/build.yml?logo=github&style=flat-square" alt="Build Status"></a>
    <a href="https://github.com/CosmicSec-Lab/cosmicsec-cli/issues"><img src="https://img.shields.io/github/issues/CosmicSec-Lab/cosmicsec-cli?style=flat-square" alt="Issues"></a>
    <a href="https://github.com/CosmicSec-Lab/cosmicsec-cli/pulls"><img src="https://img.shields.io/github/issues-pr/CosmicSec-Lab/cosmicsec-cli?style=flat-square" alt="Pull Requests"></a>
    <a href="https://github.com/CosmicSec-Lab/cosmicsec-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/CosmicSec-Lab/cosmicsec-cli?style=flat-square" alt="License"></a>
  </p>
</div>

<hr />

## 📖 Table of Contents
- [Executive Summary](#-executive-summary)
- [Architecture & Domain](#-architecture--domain)
- [Technical Specifications](#-technical-specifications)
- [Getting Started](#-getting-started)
- [Contributing](#-contributing)
- [License & Security](#-license--security)

---

## 🎯 Executive Summary
**NexSec** is a security agent that brings AI-powered threat detection and intelligent tool orchestration to your terminal. Developed by CosmicSec-Lab, it combines dynamic AI planning with hybrid execution modes to automate security scanning, threat hunting, and incident management across DevOps and penetration testing workflows.

## 🏗️ Architecture & Domain
- **Terminal UI (TUI):** A rich, highly interactive terminal experience for executing scans, monitoring progress bars, and viewing immediate, color-coded results.
- **Headless Automation:** Scriptable execution modes specifically designed for triggering platform workflows and outputting strictly typed JSON/YAML results for downstream CI/CD parsers.
- **Extensibility:** Support for custom plugins and configuration files (`.cosmicsec.yml`).

## 🛠 Technical Specifications
- **Language:** Python 3.10+ / Go
- **Framework:** Typer / Click / Cobra
- **Distribution:** PyPI, Homebrew, Apt

## 🚀 Getting Started
\`\`\`bash
# Install NexSec globally
pip install nexsec

# Quick start — scan a target
nexsec scan 192.168.1.0/24

# Hunt for threats
nexsec threat hunt --ai

# Manage incidents
nexsec incident list
nexsec incident resolve INC-001

# Execute hybrid plans (AI + tools)
nexsec plan create --target my-app.com --ai-assist
```

**Entry points:** \`nexsec\` (primary) or \`cosmicsec-agent\` (CosmicSec branding) — both work!

## 🛡️ License & Security
All rights reserved by **CosmicSec-Lab**.
