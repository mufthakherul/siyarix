# @mufthakherul/cosmicsec-agent-cli

Official npm launcher for the CosmicSec Python CLI agent.

## Install

```bash
npm install -g @mufthakherul/cosmicsec-agent-cli
```

## Usage

```bash
# Auto-installs Python package when needed and runs the CLI
cosmicsec-agent --help

# Alias
cosmicsec --version

# Explicit installer command
cosmicsec-agent-install
```

## How it works

- Detects Python 3.11+.
- Installs `cosmicsec-agent` via `pipx` (preferred) or `pip --user`.
- Runs `python -m cosmicsec_agent.main` with your CLI arguments.

## Requirements

- Node.js 20+
- Python 3.11+
