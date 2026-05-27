# First Run

This guide walks through your first Siyarix session.

## Launch the CLI

```bash
siyarix
```

You will see the banner and available commands grouped by category.

## Check help

```bash
siyarix --help
```

Command groups include:

| Group | Purpose |
|-------|---------|
| `scan` | Network/service scanning |
| `recon` | Reconnaissance and enumeration |
| `exploit` | Exploitation chains |
| `report` | Report generation |
| `config` | Configuration management |
| `creds` | Credential management |
| `chat` | Interactive AI chat session |
| `security` | Security operations (incidents, playbooks) |
| `health` | System health check |
| `metrics` | Performance metrics |

## Run a health check

```bash
siyarix health
```

Reports component status, Python version, platform info, and system state.

## Run a basic scan

```bash
siyarix scan quick example.com
```

This runs a quick port scan against the target using default tools.

## Interactive chat mode

Start an AI-powered interactive session:

```bash
siyarix chat
```

This opens the REPL with slash commands, auto-complete, and multi-turn conversation. Type `/help` inside the chat for available commands.

## Check discovered tools

```bash
siyarix scan --list-tools
```

Lists all security tools discovered on your system (100+ supported tools).

## What happens on first run

1. Bootstrap detects your platform and Python version
2. `~/.siyarix/` directory is created
3. Settings file is initialized with defaults
4. Available tools on PATH are cataloged
5. AI provider connections are validated (if API keys are set)

## Next steps

- [Configuration Guide](configuration.md)
- [CLI Commands Reference](../user/cli-commands.md)
