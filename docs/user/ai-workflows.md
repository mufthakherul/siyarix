# AI-Powered Workflows

Siyarix uses AI providers for planning, interpretation, and autonomous execution.

## Natural language command interpretation

```bash
siyarix run "scan the network 10.0.0.0/24 for open ports and service versions"
```

The AI planner (`TaskPlanner`) converts natural language into structured execution steps:

1. Parse intent and extract target/parameters
2. Select appropriate tools from the registry
3. Build an execution plan with dependencies
4. Execute steps in parallel where possible
5. Collect and present results

## Goal-driven autonomous agent

```bash
siyarix agent "enumerate all subdomains, find live hosts, scan for vulns, and report"
```

The `CoordinatorAgent` orchestrates multi-agent execution:

1. **Decomposition**: Goal is split into sub-tasks
2. **Assignment**: Tasks are assigned to role-based agents (recon, scanner, enumerator, exploiter, reporter)
3. **Execution**: Agents work in parallel with dependency resolution
4. **Synthesis**: Results are combined into a final report

## Multi-provider failover

If the primary AI provider fails:

1. Circuit breaker opens (3 failures in 60 seconds)
2. Next provider in the preference chain is tried
3. If all remote providers fail, heuristic fallback is used
4. The system degrades gracefully — commands still execute, just without AI planning

## Prompt architecture

AI prompts are constructed from:

- System context (platform, available tools, session state)
- User input (natural language or structured command)
- Conversation history (multi-turn context)
- Safety constraints (permission gates, forbidden commands)
- Persona instructions (behavior profile)

## Tool selection

The AI selects tools based on:

1. **Capability**: What the tool does (port scan, vulnerability check, etc.)
2. **Availability**: Is the tool installed on PATH?
3. **Platform**: Does it work on the current OS?
4. **Safety**: Is the tool appropriate for the current persona/safe mode?

The `ToolRegistry` maintains metadata for 100+ security tools including their capabilities, platforms, and invocation patterns.

## Execution modes

Three execution modes control how AI decisions are applied:

| Mode | Description |
|------|-------------|
| `integrated` (default) | AI plans, selects tools, executes, and parses results automatically |
| `registry` | Uses tool registry metadata for planning without AI (deterministic) |
| `autonomous` | Full AI autonomy — plans and executes without user confirmation |

## Context management

The AI context window is managed to prevent overflow:

- Conversation history is truncated oldest-first when it exceeds limits
- Tool outputs are summarized rather than included verbatim
- Large result sets are stored in the offline store and referenced by ID

## Response quality

The `ResponseSensor` validates AI outputs:

- Checks for hallucinations (confidence scoring)
- Validates command syntax before execution
- Flags dangerous or out-of-scope commands
- Ensures structured output format compliance

## Offline operation

When no AI provider is available:

- The `NoopProvider` activates automatically
- Heuristic fallback (`RuleInterpreter`) handles command parsing
- Pattern matching and keyword extraction replace AI-driven planning
- All existing tools remain usable
