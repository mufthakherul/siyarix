# NexSec — Overview

NexSec (by CosmicSec-Lab) is a lightweight, AI-powered security agent designed for fast, repeatable security operations from the terminal. It blends AI-driven planning with deterministic tooling to support scanning, threat hunting, incident management, and CI/CD automation.

Key principles:
- Minimal cognitive load: easy commands and short names (primary CLI: `nexsec`, legacy alias: `cosmicsec-agent`).
- Hybrid execution: use AI to orchestrate and combine classic tools (nmap, nuclei, ffuf) and internal analyzers.
- Extensible: plugin system and parsers for third-party tools.
- Scriptable: outputs machine-readable JSON/YAML for pipelines.

Primary capabilities:
- Network & web scanning
- Threat hunting and enrichment (AI-assisted)
- Incident management and audit trail
- Hybrid plans combining multiple tools
