# Phalanx — Overview

Phalanx (by CosmicSec-Lab) is a lightweight, open-source security agent designed to make security operations accessible, fast, and repeatable straight from your terminal. It explores how we can blend modern AI task planning with deterministic, classic security tools like Nmap, Nuclei, and Ffuf to create a seamless security workflow.

### 🌱 How It Started
We originally built Phalanx as a college project to experiment with large language models in a security context. The goal was simple: could an AI understand a network topology well enough to run the right scanning tools automatically? 

As we kept adding features, the codebase grew into something much more robust. We realized it could actually be a great learning tool for other students, researchers, and junior penetration testers to understand how security tools map to real-world threats. Now, it is fully public and open-source for anyone to use, learn from, and contribute to!

### ✨ Key Principles
- **Keep it Simple**: We believe cognitive load should be minimal. You shouldn't need a 50-page manual to run a port scan. The primary CLI command is just `phalanx`.
- **Friendly Assistant UX**: When you type `phalanx` with no arguments, it opens a polished, interactive chat center rather than a confusing blank prompt. It shows you what models are active, your theme, and provides quick actions to get started immediately.
- **Integrated Execution**: Phalanx doesn't just "chat" with you like a standard web LLM; it uses AI to orchestrate and run actual security tools on your machine. It then reads the standard output from those tools and helps you understand the results.
- **Educational & Scriptable**: You can use it as a learning companion to figure out how tools work, or you can leverage its machine-readable JSON/YAML outputs to plug it directly into your own scripts and automation pipelines.
- **Verified Stability**: We run a comprehensive suite of offline-safe, high-fidelity End-to-End (E2E) tests. This ensures that all planning loops, parser modules, user prompt systems, and self-correction fallbacks behave reliably on every supported operating system.

### 🛠️ What Can It Do?

Phalanx comes packed with features designed to help you interact with your operating system securely:

- **Interactive AI Assistant**: Chat with your local or cloud models to plan complex security scans. The REPL retains session history so you can ask follow-up questions.
- **Network & Web Scanning**: Easily orchestrate tools to map out networks, find open ports, or discover web vulnerabilities without needing to remember complex bash flags.
- **Threat Hunting**: Ask the agent to help you search through logs or enrich data based on MITRE ATT&CK techniques.
- **Cross-Platform Compatibility**: Phalanx tries its best to understand your native shell (Bash, Zsh, PowerShell) whether you're on Linux, macOS, or Windows. It translates concepts into the right syntax for your machine.
- **Credential Management**: A built-in, encrypted vault ensures your API keys are never leaked to your bash history or public `.env` files.

Our goal is not to replace human security professionals, but to create a helpful, modern companion that makes learning and executing security tasks a little bit easier and a lot more fun.
