# @mufthakherul/nexsec-agent

Official npm launcher for the NexSec Python CLI agent.

## Install

```bash
npm install -g @mufthakherul/nexsec-agent
```

## Usage

```bash
# Auto-installs Python package when needed and runs the CLI
nexsec-agent --help

# Alias
nexsec --version

# Explicit installer command
nexsec-agent-install
```

## How it works

- Detects Python 3.11+.
- Installs `nexsec-agent` via `pipx` (preferred) or `pip --user`.
- Runs `python -m nexsec.main` with your CLI arguments.

## Requirements

- Node.js 20+
- Python 3.11+
