# CLI Commands Reference

Siyarix is a CLI-first platform built with Typer. This reference covers all available commands and sub-command groups in v3.0.0.

## Global Options

```bash
siyarix [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--config`, `-c` | Path to custom config file (YAML/JSON) |
| `--batch`, `-b` | Path to batch script file to execute |
| `--mode`, `-m` | Execution mode: `autonomous`, `integrated`, `offline` |
| `--target`, `-t` | Set initial target for the session |
| `--session` | Resume a previous session by ID |
| `--resume` | Resume the last existing session |
| `--version` | Show version information |
| `--help` | Show help message |

## Usage Modes

1. **Interactive Chat**: `siyarix` (no subcommand) — launches the context-aware chat REPL
2. **Direct Command**: `siyarix scan 10.0.0.1` — executes and exits
3. **Pipe Mode**: `echo "scan 10.0.0.1" | siyarix` — batch commands via stdin
4. **Batch File**: `siyarix --batch script.txt` — execute a script file

---

## Core Commands

### Scan

Run security scans against one or more targets. Uses discovered tools on your `PATH`.

```bash
siyarix scan <targets...> [OPTIONS]
```

**Target Modifiers:** Supports `@targets.txt` multi-target mode. Prefix a file path with `@` to load targets line by line.

| Option | Description |
|--------|-------------|
| `--tool`, `-t` | Specific tool to use |
| `--mode`, `-m` | Execution mode (`autonomous`, `integrated`, `offline`) |
| `--output`, `-o` | Output format: `table`, `json`, `yaml`, `csv` |
| `--parallel`, `-p` | Number of parallel workers |
| `--timeout` | Timeout per tool in seconds |
| `--save`, `-s` | Save results to database |
| `--dry-run` | Plan only, do not execute |
| `--profile` | Use specific command profile |

### Run / Agent

Convert natural language into structured commands or execute goal-driven autonomous agents.

```bash
siyarix run "scan my network for open ports"
siyarix agent "find all vulnerabilities on our web server"
```

### Discover

Asset and service discovery for specified targets.

```bash
siyarix discover <target>
```

### Init

Initialize Siyarix using the interactive setup wizard. Runs the ethics pledge, requirements check, provider setup, and persona configuration.

```bash
siyarix init [--force] [--skip-requirements]
```

### Palette & Render

Command palette and profile execution.

| Command | Description |
|---------|-------------|
| `siyarix palette` | Open an interactive command palette (requires `prompt_toolkit`) |
| `siyarix render-cmd <name> [kv...]` | Render a saved command profile using provided key=value pairs |

---

## Sub-Command Groups

### Profile

Workspace and command profile management.

| Command | Description |
|---------|-------------|
| `siyarix profile list-cmds` | List saved command profiles |
| `siyarix profile save-cmd <name> <command>`| Save a reusable command profile |
| `siyarix profile rm-cmd <name>` | Remove a saved command profile |

### Config

CLI configuration and settings management.

| Command | Description |
|---------|-------------|
| `siyarix config list` | Show all settings |
| `siyarix config get <key>` | Get a single setting |
| `siyarix config set <key> <value>`| Set a setting |
| `siyarix config reset` | Reset to defaults |
| `siyarix config edit` | Open config in default editor |

### Auth

Authentication & API keys configuration.

```bash
siyarix auth set-key <provider>
```

Configure AI provider API keys interactively.

### Security

Security operations management and workflows.

| Command | Description |
|---------|-------------|
| `siyarix security incidents` | View and manage security incidents |
| `siyarix security vulns` | Vulnerability management |
| `siyarix security hunt` | Threat hunting operations |
| `siyarix security mitre` | MITRE ATT&CK coverage mapping |
| `siyarix security playbooks` | Incident response playbooks |
| `siyarix security dashboard` | View security dashboard |

### Theme

Customize the terminal color themes.

| Command | Description |
|---------|-------------|
| `siyarix theme list` | List available color themes |
| `siyarix theme set <name>` | Set the default color theme |
| `siyarix theme preview [name]`| Preview a theme's appearance |

### Cache

Manage the LRU cache.

| Command | Description |
|---------|-------------|
| `siyarix cache status` | Show cache statistics |
| `siyarix cache clear` | Clear all cached data |

### Tool Registry

Manage and view discovered tools and providers.

| Command | Description |
|---------|-------------|
| `siyarix tool-registry providers` | List configured model providers (order of preference) |

### System & Ops

| Group / Command | Description |
|-----------------|-------------|
| `siyarix audit ...` | Audit trail & compliance logs management |
| `siyarix report ...` | Report generation & distribution |
| `siyarix health` | System health checks (components, latency, state) |
| `siyarix completions` | Generate and install shell completions |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / unknown command / target missing |
| 2 | Validation error |
| 3 | Permission denied / file missing |
| 4 | Timeout |
