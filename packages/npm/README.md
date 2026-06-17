# @mufthakherul/siyarix

Official npm launcher for [Siyarix](https://github.com/mufthakherul/siyarix) — AI-Native Cybersecurity Orchestration Agent.

Siyarix is a CLI-based AI cybersecurity orchestration agent that routes natural-language security tasks through a multi-provider AI abstraction layer to plan and execute tool-based workflows.

## Prerequisites

- **Python 3.11+** must be installed on your system
- The Siyarix Python package will be installed automatically on first run

## Usage

```bash
# Run any Siyarix command
npx @mufthakherul/siyarix --help

# Interactive chat session
npx @mufthakherul/siyarix

# Quick scan
npx @mufthakherul/siyarix scan quick example.com

# Natural language command
npx @mufthakherul/siyarix run "scan for open ports"
```

## Features

- 24 AI provider profiles with automatic failover and circuit breakers
- 114+ tool output parsers for structured findings extraction
- 50+ CLI commands across scan, recon, exploit, report, config, and security groups
- Interactive chat REPL with slash commands and multi-turn context
- Multi-wave AI execution with real-time streaming output
- Encrypted credential vault (AES-256-GCM) with keyring integration
- Two-stage permission gate with 38 dangerous-command patterns
- Multi-platform: Windows, macOS, Linux (including WSL2)

## Documentation

Full documentation: [https://github.com/mufthakherul/siyarix/tree/main/docs](https://github.com/mufthakherul/siyarix/tree/main/docs)

## License

AGPL-3.0-or-later. See [LICENSE](https://github.com/mufthakherul/siyarix/blob/main/LICENSE).

*SPDX-License-Identifier: AGPL-3.0-or-later*
