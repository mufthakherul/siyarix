# Execution Engine

The execution engine (`engine/executor.py`) is the core runtime that transforms plans into executed commands.

## Architecture

```
ExecutionPlan
    │
    ▼
┌─────────────────────────────────────┐
│         ExecutionEngine             │
│                                     │
│  1. Validate plan structure         │
│  2. Check permission gate per step  │
│  3. Resolve dependency ordering     │
│  4. Execute steps (parallel where   │
│     possible)                       │
│  5. Route output through parsers    │
│  6. Collect findings                │
│  7. Handle errors with backoff      │
│  8. Aggregate results               │
└─────────────────────────────────────┘
    │
    ▼
EngineResult
```

## Plan structure

An `ExecutionPlan` contains:

```python
@dataclass
class ExecutionPlan:
    target: str                    # Target host/network/URL
    steps: list[ExecutionStep]     # Ordered/parallel steps
    errors: list[str]              # Planning errors (if any)
    mode: ExecutionMode            # REGISTRY / AUTONOMOUS / INTEGRATED
```

Each `ExecutionStep` has:

- **tool**: Tool name from registry (nmap, nuclei, etc.)
- **command**: Full command string to execute
- **args**: Structured arguments
- **dependencies**: Step indices that must complete first
- **output_parser**: Parser class for results
- **timeout**: Per-step timeout

## Step execution

### Dependency resolution

Steps are grouped into layers:

```
Layer 0: [nmap scan]           (no dependencies)
Layer 1: [nuclei, nikto]       (depends on nmap results)
Layer 2: [metasploit]          (depends on nuclei & nikto)
```

Steps within the same layer execute in parallel via `asyncio.gather()`.

### Parallel execution

The `worker_pool.py` bounds concurrency:

```python
pool = AsyncWorkerPool(max_workers=config.get("default_parallel", 3))
results = await pool.map(execute_step, parallel_steps)
```

### Tool execution

Each tool is executed via `executor.py::safe_run_sync()`:

1. Tool name resolved to binary path (`dynamic_resolver.py`)
2. Command formatted with target and arguments
3. Executed as subprocess with timeout
4. Stdout/stderr captured
5. Return code checked

### Output parsing

Tool output is routed through the appropriate parser:

```python
parser = NmapParser()   # for nmap output
findings = parser.parse(stdout)
```

Each parser extracts structured findings: ports, services, vulnerabilities, banners.

### Error recovery

`engine/recovery.py` implements exponential backoff with jitter:

- Transient errors (connection reset, timeout): retry with delay
- Permanent errors (invalid target, bad tool): fail immediately
- Backoff: `min(2^attempt + jitter, max_delay)` where jitter is random 0-1s

## Execution modes

### REGISTRY mode

Uses the `ToolRegistry` to build plans without AI:

1. Intent determines tool capability requirement
2. Registry returns matching tools with platform support
3. Tools are ordered by specificity
4. Each tool is invoked with standard arguments

### AUTONOMOUS mode

AI provider has full control:

1. Provider receives intent, target, and context
2. Provider returns structured plan (tool names, order, arguments)
3. Plan is executed without user confirmation
4. Safety still enforced by permission gate

### INTEGRATED mode (default)

AI-assisted with safety gates:

1. AI provider suggests a plan
2. Permission gate evaluates each step
3. Flagged commands require user confirmation
4. User can modify, approve, or reject steps

## Tool registry

The `ToolRegistry` (`registry.py`) maintains metadata for 100+ tools with a capability graph:

```python
@dataclass
class ToolInfo:
    name: str
    tags: list[str]    # ["port_scan", "vuln_scan", "web_scan"]
    platforms: list[str]       # ["linux", "darwin", "win32"]
    binary: str                # Expected binary name
    install_hints: str         # How to install
    version_cmd: str           # How to check version
    default_args: dict         # Default arguments
```

Discovery happens at startup: the registry scans PATH for known binaries and records their tags.

## Result collection

The engine produces `EngineResult`:

- **steps_completed**: Count of successfully executed steps
- **steps_failed**: Count of failed steps
- **findings**: List of extracted findings from parsers
- **duration**: Total execution time
- **errors**: Error messages for failed steps
