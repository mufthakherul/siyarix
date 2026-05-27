# Documentation Map

## Navigation guide

```
docs/
├── getting-started/     → New user onboarding
├── user/                → Daily usage & workflows
├── developer/           → Codebase & contributions
├── architecture/        → System design & internals
├── ai/                  → AI provider & agent docs
├── security/            → Ethics, safety, threat model
├── legal/               → Licensing & governance
```

## Who should read what

### New users

Start here:

1. `getting-started/installation.md` — install Siyarix
2. `getting-started/setup.md` — configure API keys and settings
3. `getting-started/first-run.md` — run your first commands
4. `getting-started/configuration.md` — detailed configuration reference
5. `user/cli-commands.md` — command reference

### Daily users

- `user/interactive-chat.md` — using the REPL and slash commands
- `user/security-workflows.md` — common security workflows
- `user/ai-workflows.md` — AI-powered operations
- `user/reporting.md` — output formats, reports, audit logs

### Developers

- `developer/contribution-guide.md` — how to contribute
- `developer/codebase-overview.md` — module structure
- `developer/module-architecture.md` — key system internals
- `developer/testing.md` — testing conventions
- `developer/building.md` — build and packaging

### Architects

- `architecture/overview.md` — high-level system design
- `architecture/ai-agent-pipeline.md` — AI processing pipeline
- `architecture/provider-abstraction.md` — multi-provider design
- `architecture/execution-engine.md` — plan execution
- `architecture/memory-and-state.md` — persistence and caching
- `architecture/security-model.md` — security architecture

### AI engineers

- `ai/multi-provider-routing.md` — provider registration and failover
- `ai/prompt-architecture.md` — prompt construction
- `ai/agent-reasoning.md` — planning and reasoning pipeline
- `ai/tool-execution.md` — tool lifecycle and parsing
- `ai/safety-and-hallucination.md` — safety constraints

### Security researchers

- `security/ethical-hacking-policy.md` — authorized use
- `security/abuse-prevention.md` — safety controls
- `security/threat-model.md` — security analysis
- `security/vulnerability-reporting.md` — how to report issues
- `security/operational-security.md` — OPSEC features

### Legal & compliance

- `legal/agpl-license-guide.md` — AGPL-3.0 explained
- `legal/note-file-explained.md` — NOTICE file purpose
- `legal/disclaimer.md` — warranty and liability
- `legal/trademark-policy.md` — trademark usage
- `legal/responsible-ai-usage.md` — AI governance

## Documentation tree

```
docs/
├── getting-started/
│   ├── installation.md          # pip, brew, winget, npm, source installs
│   ├── setup.md                 # API keys, env vars, config, credential store
│   ├── first-run.md             # Health check, scan, chat, first commands
│   ├── configuration.md         # Settings reference, env var mapping
│   └── troubleshooting.md       # Common issues and solutions
│
├── user/
│   ├── cli-commands.md          # Full command reference
│   ├── interactive-chat.md      # REPL, slash commands, multi-turn chat
│   ├── security-workflows.md    # Recon, vuln assessment, exploitation, IR
│   ├── ai-workflows.md          # AI planning, multi-agent, failover
│   └── reporting.md             # Report formats, audit logging, metrics
│
├── developer/
│   ├── codebase-overview.md     # Module structure and key subsystems
│   ├── contribution-guide.md    # Setup, workflow, conventions, PR process
│   ├── module-architecture.md   # Execution engine, planner, gate, agents
│   ├── testing.md               # Test framework, writing tests, coverage
│   └── building.md              # Build, package, publish
│
├── architecture/
│   ├── overview.md              # High-level system design and data flow
│   ├── ai-agent-pipeline.md     # Intent routing, planning, execution
│   ├── provider-abstraction.md  # Provider interface, registry, failover
│   ├── execution-engine.md      # Step execution, dependency resolution
│   ├── memory-and-state.md      # Knowledge graph, persistence, caching
│   └── security-model.md        # Permission gate, masking, audit
│
├── ai/
│   ├── multi-provider-routing.md  # 10 providers, preference chains, CB
│   ├── prompt-architecture.md     # System context, safety constraints
│   ├── agent-reasoning.md         # Goal decomposition, multi-agent
│   ├── tool-execution.md          # Tool discovery, parsing, errors
│   └── safety-and-hallucination.md  # Response sensor, danger analysis
│
├── security/
│   ├── ethical-hacking-policy.md   # Authorized use, scope, compliance
│   ├── abuse-prevention.md         # Danger analysis, kill switch, OPSEC
│   ├── threat-model.md             # Assets, boundaries, mitigations
│   ├── vulnerability-reporting.md  # Reporting process, disclosure
│   └── operational-security.md     # TOR, proxy rotation, stealth
│
└── legal/
    ├── agpl-license-guide.md       # AGPL-3.0-or-later explained
    ├── note-file-explained.md      # NOTICE structure and purpose
    ├── disclaimer.md               # Warranty and liability disclaimer
    ├── trademark-policy.md         # Name/logo usage guidelines
    └── responsible-ai-usage.md     # AI governance and transparency
```

## Section purposes

| Section | Purpose | Primary audience |
|---------|---------|-----------------|
| `getting-started/` | First-time setup, configuration, troubleshooting | All users |
| `user/` | Daily CLI usage, command reference, workflows | Operators |
| `developer/` | Codebase internals, contribution guide | Contributors |
| `architecture/` | System design, data flow, security model | Architects |
| `ai/` | AI provider system, agent reasoning | AI engineers |
| `security/` | Ethics, safety, threat model, OPSEC | Security team |
| `legal/` | Licensing, trademark, governance | Legal/compliance |

## Scalability plan

The current structure supports expansion into these additional areas as the project grows:

```
docs/
├── plugins/       → When plugin system matures (sandboxing, lifecycle, SDK)
├── api/           → If REST/gRPC API is added (auth, endpoints, SDK)
├── deployment/    → Docker, cloud, enterprise deployment guides
├── operations/    → Monitoring, logging, performance tuning
├── governance/    → Additional governance beyond legal
└── contributing/  → Expanded contributor guides
```

Each new section can be added without breaking the existing structure. Internal cross-references use relative paths and will continue to work.

## Conventions

- **Filenames**: lowercase with hyphens (`multi-provider-routing.md`)
- **Cross-references**: relative paths (`../security/threat-model.md`)
- **Code examples**: fenced with language tag (```bash, ```python)
- **Tables**: Used for structured reference data
- **Consistent terminology**: "provider" not "LLM", "tool" not "binary", "plan" not "script"
