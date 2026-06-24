# Multi-Agent Framework (Experimental / Stub)

The Multi-Agent Framework in Siyarix is **experimental** and provides a stub implementation for future multi-agent collaboration. It is not yet production-ready and should not be relied upon for operational use.

---

> **Status: EXPERIMENTAL — STUB IMPLEMENTATION**
>
> This framework provides placeholder infrastructure for future development. All agents return mock data and are not connected to real tool execution.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       SwarmRouter                           │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ ReconAgent   │  │ ExploitAgent │  │ ReportAgent  │     │
│  │ (stub)       │  │ (stub)       │  │ (stub)       │     │
│  │              │  │              │  │              │     │
│  │ mock:        │  │ mock:        │  │ mock:        │     │
│  │ open ports,  │  │ vuln check,  │  │ findings,    │     │
│  │ services,    │  │ brute,       │  │ summary,     │     │
│  │ OS detection │  │ exploit      │  │ report       │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  All agents sleep 2 seconds, return hardcoded mock data     │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components (siyarix/core/swarm.py)

### SwarmRouter

Orchestrates the multi-agent workflow. Accepts a goal, selects appropriate agents, and returns aggregated results.

```python
router = SwarmRouter(provider="openai")
results = await router.run(goal="Scan 10.0.0.1 for vulnerabilities")
```

Returns a list of `SwarmTask` results from each involved agent.

### SpecializedAgent (Base Class)

All agents inherit from `SpecializedAgent`:

```python
@dataclass
class SpecializedAgent:
    name: str
    description: str
    provider: str
    max_iterations: int = 3

    async def run(self, goal: str, context: dict) -> SwarmTask:
        ...
```

### SwarmTask

```python
@dataclass
class SwarmTask:
    agent: str
    goal: str
    status: str          # pending | running | completed | failed
    result: str
    findings: list
    error: str | None
    started_at: float
    completed_at: float
    duration_ms: float
```

---

## Available Agents (Stubs)

### ReconAgent

| Aspect | Current Behavior |
|--------|-----------------|
| **Intent** | Network reconnaissance |
| **Description** | Scans for open ports, running services, OS detection on target |
| **Provider** | openai |
| **Actual Behavior** | Sleeps 2s, returns hardcoded mock with open ports (22, 80, 443, 3306, 8080), services, OS detection |
| **Readiness** | ❌ Not functional |

### ExploitAgent

| Aspect | Current Behavior |
|--------|-----------------|
| **Intent** | Vulnerability exploitation |
| **Description** | Checks for known vulnerabilities, brute force, exploits |
| **Provider** | openai |
| **Actual Behavior** | Sleeps 2s, returns hardcoded mock with vulnerabilities and exploit attempts |
| **Readiness** | ❌ Not functional |

### ReportAgent

| Aspect | Current Behavior |
|--------|-----------------|
| **Intent** | Report generation |
| **Description** | Analyzes findings and generates comprehensive reports |
| **Provider** | openai |
| **Actual Behavior** | Sleeps 2s, returns hardcoded mock with findings, summary, severity assessment |
| **Readiness** | ❌ Not functional |

---

## Additional Stubs (siyarix/chat/stubs.py)

The `chat/stubs.py` module contains additional stubs used for CLI chat demo/testing:

- **SimulatedAgent**: Returns mock responses mimicking different agent behaviors
- **SimulatedCollaboration**: Stubs for multi-agent collaboration scenarios
- **SimulatedFindings**: Pre-defined mock findings for testing

These are used exclusively for development and demonstration, never in production execution.

---

## Limitations (Current)

| Limitation | Detail |
|------------|--------|
| No inter-agent communication | Agents don't share findings or coordinate |
| No state machine | No lifecycle management (idle→running→completed) |
| No AgentMessage protocol | No structured messaging between agents |
| No real tool access | All results are mock/hardcoded |
| Fixed 2s sleep | Simulates async execution, not real concurrency |
| No task decomposition | Goals are passed as-is, no sub-tasking |
| No result passing | Agent A's output is not fed to Agent B |
| No error propagation | Failures are captured but not acted upon |

---

## Planned Capabilities (Future)

- **Dynamic agent spawning** based on goal complexity
- **Inter-agent message bus** with publish/subscribe
- **Task decomposition** via LLM planning
- **Sharing KnowledgeGraph** across agents
- **Sequential chaining** with output dependencies
- **Agent lifecycle** with health checks and restart
- **Real tool delegation** through `RegistryExecutor`
- **Sub-agent coordination** for large-scale operations

---

## Integration with AgentCore

```python
class AgentCore:
    def __init__(self, swarm: SwarmRouter | None = None):
        self.swarm = swarm  # Injected, not created by default

    async def run_swarm(self, goal: str) -> list[SwarmTask]:
        if not self.swarm:
            logger.warning("No SwarmRouter configured")
            return []
        return await self.swarm.run(goal)
```

Swarm is opt-in and injected from outside. AgentCore does not create a SwarmRouter by default.

---

## Use Cases (Future)

| Scenario | Agents Involved | Future Flow |
|----------|----------------|-------------|
| Full pentest of single host | Recon → Exploit → Report | Sequential chaining |
| Network segment assessment | Recon (scaling) → Report | Scaled recon + analysis |
| Multi-vector attack | Recon → Exploit (multiple) → Report | Parallel exploitation |
| Continuous monitoring | Recon (scheduled) → Report | Periodic execution |
