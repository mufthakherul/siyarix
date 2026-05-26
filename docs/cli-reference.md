# CLI Reference

Phalanx CLI Version: **1.2.0**

This document provides a comprehensive reference for the Phalanx command hierarchy. The CLI is built using the [Typer](https://typer.tiangolo.com/) framework, which means it is self-documenting.

*(Tip: You can append `--help` to any command in your terminal to get real-time usage and flag details, e.g., `phalanx scan --help`).*

> **The Quick Start**: Launching `phalanx` with no subcommand at all opens the interactive assistant shell. The beautiful landing screen will show you your operating system, current execution mode, theme, AI model provider, session ID, and quick actions for the most common tasks.

---

## Global Options

These flags can be applied to almost any command:
- `--mode <registry|autonomous|integrated>`: Set how the execution engine behaves (Default: `integrated`).
- `--no-banner`: Suppress the ASCII startup banner if you want a quieter output.
- `--help`: Show the help documentation for the current context.

---

## Core Commands

These are the primary commands you will use on a day-to-day basis.

### `chat`
Start an interactive AI cybersecurity REPL (Read-Eval-Print Loop).
- **Flags**:
  - `--mode, -m`: Override the execution mode.
  - `--target, -t`: Set an initial session target (so you don't have to type it later).
  - `--session, -s`: Resume a specific session by its unique ID.
  - `--resume, -r`: Automatically resume your most recent session.

**High-Value Chat Slash Commands:**
While inside the `chat` interface, you can type these to control the agent:
- `/help`: Show all available slash commands.
- `/tools`: Discover which security tools Phalanx can see installed on your local machine.
- `/palette`: Search and run saved commands or "intents".
- `/key set <provider> <api_key>`: Securely store your AI keys in the encrypted vault.
- `/key list`: Show your configured providers.
- `/theme mode <system|dark|light|minimal|neon>`: Change the UI theme on the fly.
- `/model <auto|openai|gemini|ollama|cloud>`: Set the preferred AI planner provider.

### `scan`
Run specific security tools against targets using the execution engine directly (without the AI planner).
- **Arguments**: `targets` (An IP, CIDR, URL, or hostname)
- **Flags**:
  - `--tool, -t`: Specify a tool (e.g., `nmap`, `nuclei`).
  - `--output, -o`: Formatting preference (`table`, `json`, `yaml`, `csv`).
  - `--save, -s`: Persist the results to your local offline SQLite store.
  - `--dry-run`: Don't actually run anything; just show the proposed execution plan.

### `run`
Execute a natural language instruction through the autonomous engine right from your shell.
- **Example**: `phalanx run "find open ports on 10.0.0.1 and output to a file"`

### `health`
Run system health checks to ensure your vault, databases, and AI endpoints are reachable.

---

## Specialized Sub-Groups

If you want to dive deeper, Phalanx organizes its advanced features into sub-command groups.

### `security` (🔐 Security Ops & Management)
Manage local security data.
- `incidents`: List and filter security incidents you have recorded.
- `incident-create`: Manually report a new incident.
- `hunt`: Execute threat hunting queries against your local logs.
- `queries`: List available MITRE-mapped hunt queries.

### `shell` (🖥 Cross-platform Helper)
Learn about your environment and translate commands.
- `platform`: Detailed terminal and OS diagnostics.
- `doctor`: Readiness report showing which external security binaries Phalanx found on your `PATH`.
- `translate <intent>`: Convert goals (e.g., `ping`) into platform-specific commands (e.g., `Test-Connection` on PowerShell).
- `list-intents`: Show all the cross-platform concepts Phalanx understands.

### `auth` (🔑 Secrets Management)
- `set-key <provider>`: Securely store API keys (OpenAI, Gemini, Anthropic, etc.).
- `show`: Check the configuration status of your keys.

### `config` (⚙️ Settings)
- `list`: Show all current settings and defaults.
- `set <key> <val>`: Update a configuration value locally.
- `reset`: Restore settings to their fresh-install defaults.

### `theme` (🎨 Customization)
- `list`: Show available UI color themes.
- `set <name>`: Set the global UI theme (e.g., `dark`, `neon`).
- `preview`: Preview the interface with shell, text, and command samples to see how your colors look.
