# Architecture

NexSec is an enterprise-grade cybersecurity command center designed for modularity, cross-platform awareness, and autonomous orchestration.

## Architectural Layers

- **CLI Layer (Typer & Rich)**: A nested, multi-level command routing system using Typer for structure and Rich for premium console output, themes, and interactive components.
- **Interactive REPL (Chat Mode)**: A specialized cybersecurity AI assistant that maintains session history, supports slash commands, and provides natural language to execution pipelines.
- **Orchestration & Planning**:
    - **Task Planner**: Decomposes high-level instructions into multi-step execution plans.
    - **Execution Engine**: Orchestrates tasks with support for retries, dependency management, and workflow persistence.
- **Execution Modes**:
    - **Registry Mode**: High-speed, offline execution using local tool discovery.
    - **Autonomous Mode**: Model-driven planning and decision making for complex or unknown tasks.
    - **Integrated Mode (Default)**: Combines AI planning with registry-backed tool verification for optimal reliability.
- **Security & Knowledge**:
    - **Enterprise Vault**: Secure, encrypted storage for API keys and secrets using Fernet and AWS KMS.
    - **Shell Knowledge Library**: A cross-platform translation engine that maps intents to platform-native (Bash, PowerShell, CMD) security commands.
    - **Tool Registry**: Auto-discovery system for security binaries and their capabilities.
- **Persistence & Compliance**:
    - **Offline Store**: Local database for findings, execution plans, and scan history.
    - **Audit Engine**: High-integrity, chained audit log for enterprise compliance and forensic verification.

## Design Principles

- **Surgical Execution**: The engine prioritizes precise, verified tool invocations over "hallucinated" shell commands.
- **Platform Agnostic**: All core intents are translated to the host's native shell environment, ensuring consistent behavior across Linux, macOS, and Windows.
- **Offline-First Resilience**: Critical operations (registry scans, vault access, audit logging) function without internet connectivity.
- **Policy-Driven Safety**: Integrated safety resolvers and CI/CD gates ensure that autonomous actions adhere to organizational security policies.
