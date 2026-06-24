# 🔀 Workflow Files

At the heart of Siyarix is the `WorkflowEngine`, a powerful system that uses Directed Acyclic Graphs (DAGs) to execute complex, multi-step processes. Workflows allow you to define dependencies between tasks, ensuring that steps run in the correct order—and in parallel when they don't depend on each other!

> [!NOTE]
> Workflow files are executed programmatically via the `WorkflowEngine` API or through the primary CLI command: `siyarix playbook run`. (There is no dedicated `siyarix workflow run` command).

---

## 📝 The Workflow Format

Workflows are written in clean, easy-to-read YAML. Here is an example of a standard network assessment:

```yaml
name: network-assessment
description: Standard network security assessment
steps:
  - id: recon
    instruction: "scan subdomains of {{target}}"
    mode: integrated
    depends_on: [] # Runs immediately

  - id: port-scan
    instruction: "nmap -sV -p 1-1000 {{target}}"
    mode: registry
    depends_on: [recon] # Waits for recon

  - id: vuln-scan
    instruction: "run vulnerability scan on {{target}}"
    mode: integrated
    depends_on: [port-scan] # Waits for port-scan

  - id: report
    instruction: "generate report from findings"
    mode: integrated
    depends_on: [vuln-scan] # Waits for vuln-scan
    retries: 2             # Try up to 3 times total!
    timeout: 600           # Kill if it takes over 10 minutes
```

---

## ⚙️ Step Specification

Every step in a workflow is highly configurable. Here is what you can define:

| Field | Required? | Default | What It Does |
|-------|-----------|---------|--------------|
| `id` | **Yes** | — | A unique identifier for the step (e.g., `recon`). |
| `instruction` | **Yes** | — | The command or natural language instruction to execute. |
| `mode` | No | `integrated`| The AI execution mode (`registry`, `autonomous`, or `integrated`). |
| `depends_on` | No | `[]` | A list of step IDs that must finish before this step can start. |
| `retries` | No | `0` | How many times to automatically retry if the step fails. |
| `timeout` | No | `300` | The maximum time (in seconds) the step is allowed to run. |
| `persist` | No | `true` | Should the results be saved to the offline database? |

---

## 🚀 Execution

Executing a workflow from the command line is simple:

```bash
# 🏃 Run a workflow file directly
siyarix playbook run network-assessment.yaml

# 🎯 Inject custom variables at runtime
siyarix playbook run assessment.yml --var target=example.com
```

### 💻 Programmatic API
You can also build and run workflows dynamically in Python!

```python
from siyarix.workflow import WorkflowEngine

engine = WorkflowEngine()

# Build the graph dynamically
workflow = engine.create_workflow(
    name="my-workflow",
    nodes=[
        {"id": "scan", "name": "Port Scan", "step_fn": "nmap", "args": {"target": "10.0.0.1"}},
    ],
    edges=[],
)

# Execute it!
await engine.run_workflow(workflow)
```

---

## 🚦 How It Works Under the Hood

### Step States
Every step transitions through a strict lifecycle:
```
PENDING → RUNNING → COMPLETED
               ↓
            FAILED
               ↓
           SKIPPED
```

### Dependency Resolution
Siyarix executes steps in **topological order**. 
- Steps with empty `depends_on` arrays run first. 
- Independent steps run simultaneously! 
- The engine uses an `asyncio.Semaphore(4)` to prevent overwhelming your system, bounding execution to 4 concurrent tasks by default.

### Retries & Persistence
- **Retries**: If a network glitch causes a step to fail, Siyarix automatically tries again based on your `retries` configuration (up to a default max of 3 attempts).
- **Persistence**: Every output, finding, error, and timestamp is safely stored in the `OfflineStore` for later review.

### Strict Validation
Before Siyarix runs a single command, it validates your entire workflow. It ensures all IDs are unique, dependencies actually exist, and prevents catastrophic circular dependencies!
