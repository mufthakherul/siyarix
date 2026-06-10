# Multi-Agent Framework

Siyarix includes a full multi-agent framework for collaborative autonomous security operations.

## Architecture

```
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │  Recon   │  │ Scanner  │  │Exploiter │  ...
         │  Agent   │  │  Agent   │  │  Agent   │
         └──────────┘  └──────────┘  └──────────┘
               │              │              │
               └──────────────┼──────────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │   Reporter       │
                     │   Agent          │
                     └──────────────────┘
```

## Agent roles

| Role | Purpose | Typical tasks |
|------|---------|---------------|
| `RECON` | Reconnaissance | Subdomain enumeration, OSINT, WHOIS lookups |
| `SCANNER` | Network scanning | Port scans, service detection, banner grabbing |
| `ENUMERATOR` | Enumeration | Directory brute-force, technology fingerprinting |
| `EXPLOITER` | Exploitation | Vulnerability verification, proof-of-concept |
| `REPORTER` | Reporting | Result aggregation, report generation |
| `SOC` | Monitoring | Log analysis, alert triage |
| `DFIR` | Forensics | Evidence collection, timeline analysis |

## Agent lifecycle

```
IDLE → WORKING → DONE
            ↓
         WAITING (for dependencies)
            ↓
         FAILED (on error)
```

## Message protocol

Agents communicate via `AgentMessage`:

```python
@dataclass
class AgentMessage:
    sender: str
    recipient: str
    content: str
    msg_type: str  # task | result | query | broadcast
    payload: dict
```

| Message type | Direction | Purpose |
|-------------|-----------|---------|
| `task` | Coordinator → Agent | Assignment of a sub-task |
| `result` | Agent → Coordinator | Return of findings |
| `query` | Agent → Agent | Request for information |
| `broadcast` | Any → All | Team-wide notification |

## Agent memory

Each agent maintains working memory as a `deque(maxlen=100)`:

- `findings`: Discovered items during operation
- `commands_run`: History of executed commands
- `messages_received`: Incoming messages (deque cap 100)
- `messages_sent`: Outgoing messages

## Team coordination

The `AgentTeam` orchestrates multi-agent execution:

```python
team = AgentTeam()
team.add_agent(Agent(role=RECON, name="recon-1"))
team.add_agent(Agent(role=SCANNER, name="scanner-1"))
team.add_agent(Agent(role=EXPLOITER, name="exploit-1"))
team.add_agent(Agent(role=REPORTER, name="report-1"))

result = await team.execute_goal(
    "enumerate services and find vulnerabilities on 10.0.0.1"
)
```

### Execution flow

1. Goal is received by the team
2. Agents start in role order: RECON → SCANNER → ENUMERATOR → EXPLOITER → REPORTER
3. Within each role group, agents execute in parallel via `asyncio.gather()`
4. Results are broadcast to the team via `team.broadcast(message)`
5. Final results are aggregated and returned
