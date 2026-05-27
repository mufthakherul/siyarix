# Agent Reasoning Pipeline

The agent reasoning pipeline transforms user objectives into executed actions through planning, decomposition, and multi-agent coordination.

## Planning pipeline

```
User Goal → Task Decomposition → Tool Selection → Dependency Resolution → Execution → Synthesis
```

### 1. Goal decomposition

The `CoordinatorAgent` breaks down complex goals:

```
Input: "Find all vulnerabilities on the web server and generate a report"

Decomposition:
├── Recon: discover subdomains and endpoints
├── Scan: port scan and service detection
├── Enumerate: identify web technologies
├── Vuln Scan: run vulnerability scanners
├── Report: aggregate findings into a report
```

### 2. Tool selection

For each sub-task, tools are selected based on:

- **Capability match**: Tool metadata says it can do the task
- **Platform support**: Tool runs on current OS
- **Availability**: Tool is installed and on PATH
- **Safety**: Tool is permitted by current persona

The `ToolRegistry` maintains a capability index:

```python
tool_registry.find_by_capability("port_scan")
# Returns: [nmap, masscan, unicornscan]
```

### 3. Dependency resolution

Steps are ordered by dependency:

```
Recon (no deps)
  │
  ▼
Scan (depends on recon results)
  │
  ▼
Enumerate (depends on scan results)
  │
  ▼
Vuln Scan (depends on enumerate results)
  │
  ▼
Report (depends on all previous)
```

Independent steps execute in parallel.

### 4. Execution

The `ExecutionEngine` processes the plan:

```python
for layer in plan.layers:
    results = await asyncio.gather(*[
        execute_step(step) for step in layer
    ])
```

Each step:
1. Resolves the tool binary via `DynamicResolver`
2. Formats the command with appropriate arguments
3. Runs the subprocess with timeout
4. Routes output through the tool's parser
5. Extracts findings into the knowledge graph

### 5. Result synthesis

The multi-agent `Reporter` agent aggregates findings:

- Removes duplicates
- Correlates related findings
- Assigns severity (via CVSS scoring)
- Generates remediation suggestions
- Produces formatted output

## Multi-agent coordination

The `AgentTeam` manages role-based agents:

```python
team = AgentTeam()
team.add_agent(Agent(role=AgentRole.RECON))
team.add_agent(Agent(role=AgentRole.SCANNER))
team.add_agent(Agent(role=AgentRole.ENUMERATOR))
team.add_agent(Agent(role=AgentRole.EXPLOITER))
team.add_agent(Agent(role=AgentRole.REPORTER))
```

Agents communicate via `AgentMessage`:

- **task**: Assignment from coordinator
- **result**: Findings from completed work
- **query**: Request for information
- **broadcast**: Team-wide notification

## Reasoning loop

The `AgenticLoop` implements Observe-Reason-Act:

```
while objective_incomplete and iterations < max:
    # Observe
    state = collect_environment_state()
    findings = knowledge_graph.query(objective.targets)

    # Reason
    analysis = analyze_findings(findings, state)
    next_action = select_next_action(analysis)

    # Act
    result = execute_action(next_action)
    knowledge_graph.update(result)

    # Reflect
    if result.indicates_new_targets:
        objectives.add(result.new_targets)
```

## Heuristic fallback

When no AI provider is available, the `RuleInterpreter` provides deterministic planning:

```
Input: "scan 10.0.0.1"
  → Extract intent: "scan"
  → Extract target: "10.0.0.1"
  → Match tool: nmap (port_scan capability)
  → Build command: "nmap -sV -p 1-1000 10.0.0.1"
  → Return structured plan
```

Patterns are defined in `shell_knowledge.py` with 60+ intents across 6 shell types.
