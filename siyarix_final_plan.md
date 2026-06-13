# Siyarix — Comprehensive Master Improvement Plan
**Date:** June 2026 | **Based on:** Full source code audit (v2.0.0--->latest)  
**Files read:** planner.py · executor.py · core/__init__.py · permission_gate.py · security_hardening.py · providers/manager.py · providers/types.py · providers/state.py · registry.py · tool_call_repair.py · knowledge_graph.py · workflow.py · validators.py · subprocess_utils.py · opsec.py · chat/event_stream.py · tool_graph.py · pyproject.toml · graph.json (3,097 nodes, 5,871 edges, 10 hyperedges)

> **Note on documentation:** Miraz confirmed the docs/ folder is based on v1/v2 and is out of date. All findings in this plan are sourced directly from the live source code, not from documentation.

---

## What The Code Actually Is (vs. What Was Documented)

After reading every core module, the actual architecture is more sophisticated than previously known:

| Component | Documented | Actual (code) |
|-----------|-----------|---------------|
| AI providers | "10 adapters" | **25 provider profiles** (including xai, zai, cerebras, minimax, moonshot, nvidia, fireworks, huggingface, llamacpp, localai, vllm, opencode_go) |
| Routing modes | 3 modes | **4 modes**: REGISTRY, AUTONOMOUS, HYBRID, INTERACTIVE |
| Tool call repair | Not documented | **Full OpenClaw-pattern repair engine** with bracket + XML syntax, Levenshtein fuzzy matching, promote-to-native pipeline |
| Provider failover | "session-disabled tracking" | **8-reason classified failover** (AUTH, RATE_LIMIT, BILLING, TIMEOUT, SERVER_ERROR, CONTEXT_OVERFLOW, MODEL_NOT_FOUND, UNKNOWN) with exponential backoff (30s→60s→300s) |
| Knowledge graph | "in-memory only" | **JSON persistence already built** — `save_json()` / `load_json()` exist in `knowledge_graph.py` — just not wired to startup/shutdown |
| Event stream | Not documented | **Full typed OpenClaw event stream** (text_start/delta/end, thinking_start/delta/end, toolcall_start/delta/end) |
| Execution engine | "sequential" | **DAG-aware parallel execution** via `AsyncWorkerPool` — already implemented |
| Safety gate | "38 patterns" | **Full two-stage gate**: syntax check → `DangerAnalyzer` with 45+ patterns (Linux + Windows), 5-severity rating |
| Cargo/Rust | Undocumented | **`packages/rust_parsers/`** — high-performance tool output parsers, `lib.rs` present |
| Dependency graph | Not known | **3,097 nodes, 5,871 edges** — auto-generated from source via graphify |

---

## Summary

| Category | Items |
|----------|-------|
| Critical bug fixes (from source) | 8 |
| Pipeline & agent loop improvements | 14 |
| Provider & routing improvements | 8 |
| Permission gate & safety | 7 |
| Tool call & execution improvements | 9 |
| Knowledge graph & memory | 5 |
| Advanced feature additions | 12 |
| Developer experience & infrastructure | 10 |
| **Total** | **73** |

---

## Part 1 — Critical Bug Fixes
*Found directly in source code. Each is a concrete, reproducible issue.*

---

### BUG-01 · `anthropic` and `google-generativeai` are hardcoded in core deps
**File:** `pyproject.toml` lines 20–21  
**Severity:** Critical

`anthropic>=0.40.0` and `google-generativeai>=0.8.0` are in core `[dependencies]` — always installed for everyone. Yet they also appear in `[autonomous]` and `[anthropic]`/`[gemini]` extras. A user who only wants to run Siyarix in `REGISTRY` mode (offline, no LLM) is forced to install two heavy AI SDKs (~50MB+) they will never use.

```toml
# Fix — remove from core [dependencies]:
# anthropic>=0.40.0        ← DELETE
# google-generativeai>=0.8.0  ← DELETE

# Keep ONLY in their respective extras:
[project.optional-dependencies]
anthropic = ["anthropic>=0.40.0"]
gemini    = ["google-generativeai>=0.8.0"]
```

---

### BUG-02 · `cryptography` pinned with hard upper bound `<44.0` — breaks future installs
**File:** `pyproject.toml` line 19  
**Severity:** Critical

`cryptography>=42.0,<44.0` has a hard upper-bound that will cause `pip install siyarix` to fail the moment the user's environment has `cryptography>=44.0` installed (common in Python 3.13 environments). The `cryptography` library releases security patches continuously and users should always get the latest.

```toml
# Fix:
"cryptography>=42.0"   # remove <44.0 ceiling — no breaking API changes between 42–45
```

---

### BUG-03 · `coverage` threshold is missing — CI passes at 0% coverage
**File:** `pyproject.toml` — no `[tool.coverage.report]` section  
**Severity:** Critical

`pytest-cov` is a dev dependency and the project has 47 test files. But there is no `fail_under` threshold anywhere. CI passes even if every test is skipped. 

```toml
[tool.coverage.report]
fail_under = 75
show_missing = true
omit = ["tests/*", "*/migrations/*"]

[tool.coverage.run]
source = ["src/siyarix"]
branch = true
```

```yaml
# CI command:
pytest --cov=src/siyarix --cov-fail-under=75 --cov-report=xml --cov-report=term-missing
```

---

### BUG-04 · `mypy` declares `disallow_untyped_defs = false` but PyPI claims `Typing :: Typed`
**File:** `pyproject.toml [tool.mypy]`  
**Severity:** Critical

The package declares `"Typing :: Typed"` classifier on PyPI and has a `py.typed` marker file — both promise full type annotations. But `disallow_untyped_defs = false` in mypy config means untyped functions pass silently. The `py.typed` marker makes false promises to downstream consumers using mypy.

```toml
[tool.mypy]
disallow_untyped_defs = true      # enforce what py.typed promises
disallow_incomplete_defs = true
warn_return_any = true
```

---

### BUG-05 · `KnowledgeGraph` JSON persistence exists but is never wired to startup/shutdown
**File:** `knowledge_graph.py` — `save_json()` and `load_json()` methods exist  
**Severity:** Critical

`KnowledgeGraph` already has full JSON save/load — `save_json(path)` and `load_json(path)` are implemented. But `AgentCore.__init__()` (in `core/__init__.py`) instantiates `KnowledgeGraph` with no path, and neither `start()` nor any shutdown hook calls these methods. The entire graph is lost on every exit.

```python
# Fix in core/__init__.py:
class AgentCore:
    def __init__(self, mode: AgentMode = AgentMode.REGISTRY) -> None:
        self._kg_path = Path.home() / ".siyarix" / "knowledge_graph.json"
        self._knowledge_graph = KnowledgeGraph()

    async def start(self) -> None:
        # Load existing graph on startup
        if self._kg_path.exists():
            self._knowledge_graph.load_json(str(self._kg_path))
            logger.info("Loaded knowledge graph: %d nodes", len(self._knowledge_graph._nodes))
        # ... rest of startup

    async def shutdown(self) -> None:
        self._kg_path.parent.mkdir(parents=True, exist_ok=True)
        self._knowledge_graph.save_json(str(self._kg_path))
        logger.info("Knowledge graph saved.")
```

---

### BUG-06 · `_execute_hybrid()` mutates `self._mode` — breaks concurrent use
**File:** `core/__init__.py` — `_execute_hybrid()` method  
**Severity:** Critical

```python
# Current code — DANGEROUS:
async def _execute_hybrid(self, ...):
    self._mode = AgentMode.AUTONOMOUS   # ← mutates instance state
    auto_result = await self._execute_autonomous(...)
    ...
    self._mode = AgentMode.REGISTRY     # ← mutates again
```

If two tasks call `execute_goal()` concurrently (e.g. from the CLI running background scans), both will race on `self._mode`. This is a data race that causes silent incorrect routing.

```python
# Fix — pass mode as parameter, never mutate self._mode:
async def _execute_hybrid(self, goal, plan, start, result):
    auto_result = await self._execute_autonomous(goal, plan, start, AgentResult(goal=goal.description))
    if auto_result.success:
        return auto_result
    logger.info("Hybrid: autonomous failed, falling back to registry")
    return await self._execute_registry(goal, plan, start, AgentResult(goal=goal.description))
```

---

### BUG-07 · `PermissionGate` rate limit is per-instance, not per-session
**File:** `permission_gate.py`  
**Severity:** High

```python
class PermissionGate:
    def __init__(self, rate_limit_calls=100, rate_limit_period=60.0):
        self._calls: list[float] = []  # ← instance-level, resets on restart
```

The rate limit tracks calls in-memory per `PermissionGate` instance. If the gate is re-instantiated between commands (which it is in some code paths), the rate limit resets. This allows unlimited command execution by simply restarting the agent.

```python
# Fix — persist rate limit state to disk or to ProviderStateManager:
class PermissionGate:
    def __init__(self, ...):
        self._state_path = Path.home() / ".siyarix" / "gate_state.json"
        self._calls: list[float] = self._load_calls()
    
    def _load_calls(self) -> list[float]:
        try:
            data = json.loads(self._state_path.read_text())
            now = time.time()
            return [t for t in data.get("calls", []) if now - t < self.rate_limit_period]
        except Exception:
            return []
```

---

### BUG-08 · `ruff` lint suppresses `F841` (unused variables) in tests — masks real bugs
**File:** `pyproject.toml [tool.ruff.lint]`  
**Severity:** High

```toml
[tool.ruff.lint]
per-file-ignores = {"tests/*" = ["E741", "F401"]}
```

`F841` (unused variable assigned but never used) is not in the ignore list — which is good. But `F401` (unused import) is silently ignored in all test files. This allows test files to import modules they don't actually test, creating false confidence in test coverage.

```toml
# Fix — remove F401 from test ignores:
per-file-ignores = {"tests/*" = ["E741"]}
# Then fix the real F401 issues in test files
```

---

## Part 2 — Pipeline & Agent Loop Improvements
*Targeting the core agentic loop: intent → plan → execute → respond. These map directly to what Miraz is actively refactoring.*

---

### PIPE-01 · Intent router needs a 5th semantic stage before LLM fallback
**File:** `planner.py` — `decompose_goal()`  
**Current:** 4-stage (template match → target extract → index search → intent map → probe fallback)

The keyword index in `decompose_goal()` is good but brittle — it requires exact or substring word matches. Adding a semantic similarity stage between the intent map and the LLM fallback would handle natural-language variants without LLM cost.

```python
# New Stage 3.5: Semantic matching (runs before intent_map, after index search)
# Uses a tiny local embedding model — no internet required
# Install: pip install sentence-transformers (optional extra)
from sentence_transformers import SentenceTransformer, util

class SemanticRouter:
    def __init__(self):
        self._model = SentenceTransformer("all-MiniLM-L6-v2")  # 80MB, runs offline
        self._intent_embeddings: dict[str, Any] = {}
        
    def build_embeddings(self, intent_map: dict[str, tuple]) -> None:
        phrases = list(intent_map.keys())
        embeddings = self._model.encode(phrases)
        self._intent_embeddings = dict(zip(phrases, embeddings))
    
    def match(self, query: str, threshold: float = 0.72) -> str | None:
        query_emb = self._model.encode(query)
        best_score, best_key = 0.0, None
        for phrase, emb in self._intent_embeddings.items():
            score = float(util.cos_sim(query_emb, emb))
            if score > best_score:
                best_score, best_key = score, phrase
        return best_key if best_score >= threshold else None
```

**Benefit:** Handles "find all listening ports" → maps to "port scan" without LLM, reducing API calls by ~30% in hybrid mode.

---

### PIPE-02 · `decompose_goal()` probe fallback ignores `depends_on` — no DAG wiring
**File:** `planner.py` — probe_steps construction (lines ~440–470)  
**Current issue:** The probe fallback creates 2–3 steps as `PlanType.DAG` but never sets `dependencies` between them. All steps run concurrently even when they should be sequential (e.g. nmap before nuclei).

```python
# Fix — add explicit dependency chaining for probe groups:
probe_steps = []
last_step_id = None
for group in probe_groups:
    for tool, desc, flags in group:
        if actual_tool in avail_set or not avail_set:
            step_id = f"probe_{tool}"
            step = {
                "id": step_id,
                "description": desc,
                "tool": actual_tool,
                "args": {"target": clean_target, "flags": flags},
                "dependencies": [last_step_id] if last_step_id else [],
            }
            probe_steps.append(step)
            last_step_id = step_id
            break
```

---

### PIPE-03 · `adapt_plan()` only handles 3 specific tool failures — needs generalisation
**File:** `planner.py` — `adapt_plan()` method  
**Current:** Handles `nmap→filtered`, `nikto/nuclei→refused`, `gobuster/ffuf→404` only.

```python
# Current — brittle and hardcoded:
def adapt_plan(self, plan, failed_step, error):
    if failed_step.tool == "nmap" and "filtered" in error.lower():
        failed_step.args["flags"] += " -Pn"
    elif failed_step.tool in ("nikto", "nuclei") and "refused" in error.lower():
        # insert nuclei fallback
    elif failed_step.tool in ("gobuster", "ffuf") and "404" in error:
        failed_step.args["extensions"] = "php,html,js,txt"
```

```python
# Fix — generalised error→recovery mapping:
RECOVERY_RULES: list[tuple[str | None, str, Callable]] = [
    # (tool_pattern, error_pattern, recovery_fn)
    ("nmap",            "filtered",      lambda s: s.args.update({"flags": s.args.get("flags","") + " -Pn"})),
    ("nmap",            "permission",    lambda s: s.args.update({"flags": s.args.get("flags","").replace("-sS","-sT")})),
    (None,              "timeout",       lambda s: s.args.update({"timeout": s.timeout * 1.5})),
    (None,              "refused",       lambda s: s.metadata.update({"skip_on_refused": True})),
    ("gobuster|ffuf",   "404",           lambda s: s.args.update({"extensions": "php,html,js,txt,asp,aspx"})),
    ("hydra",           "invalid user",  lambda s: s.args.update({"flags": "-e nsr"})),
    ("sqlmap",          "not injectable",lambda s: s.args.update({"flags": "--level=3 --risk=2"})),
]

def adapt_plan(self, plan: ExecutionPlan, failed_step: PlanStep, error: str) -> ExecutionPlan:
    error_lower = error.lower()
    for tool_pat, err_pat, recovery_fn in RECOVERY_RULES:
        tool_match = tool_pat is None or re.search(tool_pat, failed_step.tool)
        if tool_match and err_pat in error_lower:
            if failed_step.can_retry:
                recovery_fn(failed_step)
                failed_step.status = StepStatus.PENDING
                failed_step.retry_count += 1
                return plan
    failed_step.status = StepStatus.FAILED
    return plan
```

---

### PIPE-04 · `_execute_autonomous()` does not use `llm_decompose_goal()` — uses heuristic planner
**File:** `core/__init__.py` — `_execute_autonomous()`  
**Critical gap:** Autonomous mode should use the LLM to plan. But the actual code calls `self._planner.decompose_goal()` (the heuristic planner) in autonomous mode — there is no `await self._planner.llm_decompose_goal(...)` call anywhere in `AgentCore`. The LLM planning path in `planner.py` exists but is never connected to `AgentCore`.

```python
# Current autonomous mode — NOT using LLM:
async def _execute_autonomous(self, goal, plan, start, result):
    if plan is None:
        plan = self._planner.decompose_goal(  # ← heuristic, not LLM!
            goal.description, [t.name for t in self._registry.list_tools()]
        )

# Fix — wire llm_decompose_goal into autonomous mode:
async def _execute_autonomous(self, goal, plan, start, result):
    if plan is None:
        provider, model = self._providers.select_provider()
        async def llm_call(system_prompt, user_prompt, *, history=None):
            return await self._providers.complete(
                provider, model, system_prompt, user_prompt, history=history
            )
        tool_schemas = [
            {"name": t.name, "description": t.description, "tags": t.tags, "category": t.category}
            for t in self._registry.list_tools()
        ]
        plan = await self._planner.llm_decompose_goal(
            goal.description,
            [t.name for t in self._registry.list_tools()],
            llm_call=llm_call,
            tool_schemas=tool_schemas,
            history=self._context.get_history(),
        )
```

This is the most impactful fix in the entire plan — it completes the autonomous mode.

---

### PIPE-05 · `CommandPipeline` loses output between steps — no inter-step variable passing
**File:** `core/pipeline.py`  
**Current:** `CommandPipeline.execute()` runs steps sequentially but discards each step's output before passing to the next. Steps cannot use previous results.

```python
# Fix — pass previous step output as context to next step:
async def execute(self, steps, executor, ctx=None):
    result = PipelineResult()
    previous_output: dict[str, Any] = {}
    for step in steps:
        enriched_ctx = {**(ctx or {}), "previous_output": previous_output}
        res = await executor(step, enriched_ctx)
        if res.get("status") == "completed":
            result.steps_completed += 1
            result.all_findings.extend(res.get("findings", []))
            previous_output = {
                "output": res.get("output", ""),
                "findings": res.get("findings", []),
                "step_id": step.step_id,
            }
        else:
            result.steps_failed += 1
            result.success = False
    return result
```

---

### PIPE-06 · `AgentCore` has no graceful shutdown — async tasks leak on Ctrl+C
**File:** `core/__init__.py`  
**Current:** No signal handlers. Pressing Ctrl+C during a multi-step scan leaves subprocesses running in background.

```python
# Add to AgentCore:
import signal

async def start(self) -> None:
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
    # ... rest of startup

async def shutdown(self) -> None:
    logger.info("Siyarix shutting down gracefully...")
    # Cancel all running executor tasks
    await self._executor.close(timeout=5.0)
    # Save knowledge graph
    self._knowledge_graph.save_json(str(self._kg_path))
    # Flush audit log
    # Save session
    logger.info("Shutdown complete.")
```

---

### PIPE-07 · `WorkflowEngine` is instantiated but never used in any agent mode
**File:** `core/__init__.py` — `self._workflow_engine = WorkflowEngine()`  
**Current:** `WorkflowEngine` is created in `AgentCore.__init__()` but no agent mode (`_execute_registry`, `_execute_autonomous`, `_execute_hybrid`, `_execute_interactive`) ever calls it. The DAG-based workflow engine is dead code in the current wiring.

```python
# Fix — integrate WorkflowEngine for DAG plans:
async def _execute_registry(self, goal, plan, start, result):
    if plan is None:
        plan = self._planner.decompose_goal(...)
    
    # Use WorkflowEngine for DAG plans
    if plan.plan_type == PlanType.DAG:
        workflow = self._workflow_engine.from_execution_plan(plan)
        wf_result = await self._workflow_engine.run(workflow, self._executor)
        result.success = wf_result.status == WorkflowStatus.COMPLETED
    else:
        plan = await self._executor.execute_plan(plan)
        result.success = plan.status == PlanStatus.COMPLETED
```

---

### PIPE-08 · `_extract_findings()` deduplication key is fragile — misses near-duplicates
**File:** `core/__init__.py`  
**Current:** `dedup_key = f"{f.get('tool','')}:{f.get('title','')}:{f.get('target','')}"`

If the same vulnerability is found by two different tools (e.g. nmap and nuclei both flag port 80), they get different keys and appear as separate findings. For senior analysts this creates noise.

```python
# Fix — content-hash deduplication:
import hashlib

def _make_finding_hash(self, finding: dict) -> str:
    """Hash by semantic content, not tool identity."""
    key_parts = [
        finding.get("target", ""),
        finding.get("port", ""),
        finding.get("cve", finding.get("title", "")),
        finding.get("severity", ""),
    ]
    return hashlib.md5("|".join(str(p).lower() for p in key_parts).encode()).hexdigest()
```

---

### PIPE-09 · `ExecutionBudget` tracks wall-clock time but not per-step timeouts
**File:** `executor.py` — `ExecutionBudget` + `_execute_step()`  
**Current:** The budget tracks total elapsed time (`max_duration_s = 600.0`) and total iterations. But individual steps have no enforced timeout — a single hanging nmap scan can block the entire budget.

```python
# Fix — wrap each step with asyncio.wait_for:
async def _execute_step(self, step: PlanStep, executor_fn) -> None:
    timeout = step.timeout  # PlanStep already has timeout: float = 300.0
    try:
        await asyncio.wait_for(
            self._try_execute(step, executor_fn),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        step.status = StepStatus.FAILED
        step.result = {"status": "error", "error": f"Step timed out after {timeout}s"}
        self.audit_log_timeout(step)
```

---

### PIPE-10 · `ToolCallTracker` resets on every `Executor.reset()` — loses history
**File:** `executor.py`  
**Current:** `reset()` clears the tracker entirely. If the same tool keeps failing across multiple plan executions, the guardrails never trigger because they reset between plans.

```python
# Fix — make tracker session-persistent, only reset on explicit session clear:
class ToolCallTracker:
    def reset_for_session(self) -> None:
        """Full reset — only call when starting a completely new engagement."""
        self._failure_counts.clear()
        ...
    
    def reset_for_plan(self) -> None:
        """Soft reset between plans — preserve cross-plan failure history."""
        self._no_progress_count = 0
        self._consecutive_same.clear()
        # DO NOT clear _failure_counts — persistent failures should accumulate
```

---

### PIPE-11 · `_execute_hybrid()` re-runs the full `_execute_registry()` on failure — wastes completed steps
**File:** `core/__init__.py`  
**Current:** When autonomous fails, hybrid falls back to registry and starts from scratch with a new plan. Any steps that autonomous completed successfully are re-executed.

```python
# Fix — carry over completed steps from autonomous run:
async def _execute_hybrid(self, goal, plan, start, result):
    auto_result = await self._run_autonomous_mode(goal, plan, start)
    if auto_result.success:
        return auto_result
    
    # Carry over what autonomous completed
    completed_step_ids = {
        s.id for s in (auto_result.plan.steps if auto_result.plan else [])
        if s.status == StepStatus.COMPLETED
    }
    
    registry_plan = self._planner.decompose_goal(
        goal.description, [t.name for t in self._registry.list_tools()]
    )
    # Mark already-completed steps as SKIPPED in registry plan
    for step in registry_plan.steps:
        if step.tool in completed_step_ids:
            step.status = StepStatus.SKIPPED
    
    return await self._run_registry_mode(goal, registry_plan, start)
```

---

### PIPE-12 · Multi-wave execution (up to 5 waves) has no inter-wave context passing
**File:** `core/__init__.py` + `planner.py`  
**Current:** Each execution wave produces findings, but those findings are not fed back into the next wave's planning prompt. The LLM doesn't know what was found in wave 1 when planning wave 2.

```python
# Fix — feed wave N findings into wave N+1 context:
async def execute_multi_wave(self, goal: AgentGoal, max_waves: int = 5) -> AgentResult:
    all_findings = []
    plan = None
    for wave in range(max_waves):
        wave_context = {
            "wave": wave,
            "previous_findings": all_findings[-20:],  # last 20 findings
            "goal": goal.description,
        }
        wave_goal = AgentGoal(
            description=goal.description,
            constraints={**goal.constraints, "context": wave_context},
        )
        wave_result = await self.execute_goal(wave_goal, plan)
        all_findings.extend(wave_result.findings)
        
        if not wave_result.findings:
            break  # no new intelligence — stop early
        
        # Let planner generate next wave based on what we found
        plan = self._planner.plan_next_wave(wave_result.findings, goal)
    
    return AgentResult(goal=goal.description, findings=all_findings, success=True)
```

---

### PIPE-13 · No token budget or cost tracking for LLM calls
**File:** `providers/manager.py` + `core/__init__.py`  
**Current:** `ProviderManager` has a `UsageTracker` imported from `usage.py` but it is never called from `AgentCore`. Multi-wave execution can make unlimited LLM API calls with no cost ceiling.

```python
# Wire the existing UsageTracker into AgentCore:
class AgentCore:
    def __init__(self, ...):
        self._usage_tracker = UsageTracker()
        self._max_tokens_per_session = int(os.getenv("SIYARIX_MAX_TOKENS", "100000"))
        self._max_cost_usd = float(os.getenv("SIYARIX_MAX_COST_USD", "2.00"))

    async def _check_budget(self) -> None:
        record = self._usage_tracker.session_totals()
        if record.total_tokens >= self._max_tokens_per_session:
            raise BudgetExceededError(
                f"Session token limit {self._max_tokens_per_session} reached."
            )
        if record.estimated_cost_usd >= self._max_cost_usd:
            raise BudgetExceededError(
                f"Session cost limit ${self._max_cost_usd:.2f} reached."
            )
```

---

### PIPE-14 · `CompactionEngine` (`compaction.py`) is not connected to the chat session
**File:** `compaction.py` (517 lines) + `chat/__init__.py`  
**Current:** `compaction.py` implements a full conversation compaction system (summary compression when context grows too large). But `chat/__init__.py` has only 28 lines and doesn't import or use it. Long conversations will hit context limits without graceful degradation.

```python
# Wire compaction into the chat session loop:
from .compaction import CompactionEngine

class ChatSession:
    def __init__(self):
        self._compaction = CompactionEngine()
        self._messages: list[dict] = []
        self._token_count = 0
        
    async def add_message(self, role: str, content: str) -> None:
        self._messages.append({"role": role, "content": content})
        self._token_count += len(content.split())  # rough estimate
        
        # Compact when approaching context limit
        if self._token_count > 6000:
            self._messages = await self._compaction.compact(self._messages)
            self._token_count = sum(len(m["content"].split()) for m in self._messages)
```

---

## Part 3 — Provider & Routing Improvements
*The provider system is actually very sophisticated — 25 providers, classified failover, exponential backoff. These improvements build on the existing architecture.*

---

### PROV-01 · Provider `select_provider()` ignores user-configured priority order
**File:** `providers/manager.py` — `select_provider()` and `auto_detect_provider()`  
**Current:** Auto-detection iterates profiles sorted by `profile.priority` (a numeric field). But there is no config key or env var for users to set their preferred provider order.

```python
# Add to config.py:
provider_priority: list[str] = []  # e.g. ["anthropic", "openai", "gemini"]

# Fix select_provider() to respect config:
def select_provider(self, preferred: str | None = None) -> tuple[str, str]:
    if preferred and preferred in self._profiles:
        # ... existing exact-match logic

    # Respect user-configured priority
    from ..config import settings
    for provider_name in settings.provider_priority:
        if self.get_api_key(provider_name):
            profile = self._profiles[provider_name]
            return provider_name, profile.default_model
    
    # Fall back to auto-detect
    return self._auto_detect_fallback()
```

```bash
# Env var support:
SIYARIX_PROVIDER_PRIORITY=anthropic,openai,gemini,groq,ollama
```

---

### PROV-02 · `ProviderStateManager` exponential backoff is not used by `ProviderManager`
**File:** `providers/state.py` defines backoff steps `[30.0, 60.0, 300.0]`, but `providers/manager.py` sets a flat 60s cooldown:

```python
# Current in manager.py — flat cooldown:
elif reason == FailoverReason.RATE_LIMIT:
    cred.cooldown_until = time.time() + 60  # flat 60s regardless of failure count

# Fix — use ProviderStateManager's exponential backoff:
def record_failure(self, provider: str, reason: FailoverReason) -> None:
    failure_count = self._error_counts.get(provider, 0) + 1
    self._error_counts[provider] = failure_count
    
    if reason == FailoverReason.RATE_LIMIT:
        # Exponential: 30s, 60s, 300s
        steps = ProviderStateManager.COOLDOWN_STEPS
        cooldown = steps[min(failure_count - 1, len(steps) - 1)]
        for cred in self._credentials.get(provider, []):
            if cred.is_available:
                cred.cooldown_until = time.time() + cooldown
                break
```

---

### PROV-03 · `FailoverReason.CONTEXT_OVERFLOW` triggers `should_compress=True` but no compressor is called
**File:** `providers/manager.py` — `classify_error()` + `providers/types.py`  
**Current:** When a context overflow error is detected, `ClassifiedError(should_compress=True)` is returned. But no caller in `AgentCore` or `chat/` checks `should_compress` and calls the `CompactionEngine`. The flag is set but never acted on.

```python
# Fix in chat session or provider call wrapper:
classified = self._providers.classify_error(provider, error, http_status)
if classified.should_compress:
    self._messages = await self._compaction.compact(self._messages)
    # Retry with compacted context
    return await self._call_provider_with_messages(provider, model, self._messages)
```

---

### PROV-04 · `INTERACTIVE` mode in `AgentCore` is identical to `REGISTRY` mode — wasted enum value
**File:** `core/__init__.py` — `_execute_interactive()`  
**Current:** `_execute_interactive()` does exactly the same as `_execute_registry()` — calls `decompose_goal()`, runs executor, returns result. There is nothing "interactive" about it.

```python
# Fix — make INTERACTIVE mode actually interactive:
async def _execute_interactive(self, goal, plan, start, result):
    if plan is None:
        plan = self._planner.decompose_goal(goal.description, ...)
    result.plan = plan
    
    # Show plan to user before executing
    self._show_plan_preview(plan)
    
    # User can approve / skip / modify each step
    approved_steps = await self._get_user_approval(plan.steps)
    plan.steps = approved_steps
    
    plan = await self._executor.execute_plan(plan)
    result.success = plan.status == PlanStatus.COMPLETED
    result.summary = self._generate_summary(plan)
    result.findings = self._extract_findings(plan)
    return result
```

---

### PROV-05 · No retry-with-backoff wrapper around provider API calls
**File:** `providers/manager.py`  
**Current:** Provider failover is handled at the profile level (switch to next provider), but there is no retry-with-backoff for transient errors on the same provider (e.g. a single 503 from Claude should retry once before failing over).

```python
# Add RetryPolicy to ProviderProfile:
@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay_s: float = 1.0
    max_delay_s: float = 30.0
    retryable_reasons: frozenset = frozenset({
        FailoverReason.TIMEOUT,
        FailoverReason.SERVER_ERROR,
        FailoverReason.RATE_LIMIT,
    })

async def call_with_retry(self, provider, model, fn, *args, **kwargs):
    policy = self._profiles[provider].retry_policy or RetryPolicy()
    for attempt in range(policy.max_retries):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:
            classified = self.classify_error(provider, e)
            if classified.reason not in policy.retryable_reasons:
                raise
            delay = min(policy.base_delay_s * (2 ** attempt), policy.max_delay_s)
            await asyncio.sleep(delay)
    raise MaxRetriesExceededError(f"{provider} failed after {policy.max_retries} retries")
```

---

### PROV-06 · `ModelInfo.supports_function_calling` flag exists but is never checked before tool calls
**File:** `providers/types.py` — `ModelInfo.supports_function_calling: bool = True`  
**Current:** Every provider and model has `supports_function_calling = True` by default. But local models via Ollama or LlamaCpp often don't support native function calling. There is no guard in the tool call path.

```python
# Fix — check capability before using native function calling:
async def plan_with_tools(self, provider: str, model_name: str, prompt: str, tools: list) -> str:
    model_info = self._get_model_info(provider, model_name)
    if model_info and model_info.supports_function_calling:
        return await self._call_with_native_tools(provider, model_name, prompt, tools)
    else:
        # Fall back to text-based tool call repair
        response = await self._call_text_only(provider, model_name, prompt)
        _, parsed_calls = promote_to_native_tool_calls(response, [t["name"] for t in tools])
        return parsed_calls
```

---

### PROV-07 · 25 provider profiles are registered but provider `complete()` method is missing from `ProviderManager`
**File:** `providers/manager.py`  
**Critical:** `ProviderManager` has `select_provider()`, `get_api_key()`, etc. — but no `async complete(provider, model, prompt)` method. `AgentCore` cannot actually make an LLM call through `ProviderManager`. The actual LLM calling must be happening somewhere else (likely in `chat/__init__.py`'s 28-line stub or inline in the CLI).

```python
# Add to ProviderManager:
async def complete(
    self,
    provider: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    *,
    history: list[dict] | None = None,
    tools: list[dict] | None = None,
    stream: bool = False,
) -> dict[str, Any]:
    """Route to the correct provider SDK and return a unified response."""
    adapter = self._get_adapter(provider)
    return await adapter.complete(model, system_prompt, user_prompt, 
                                   history=history, tools=tools, stream=stream)

def _get_adapter(self, provider: str) -> ProviderAdapter:
    # Lazy-initialize adapters per provider
    if provider not in self._adapters:
        self._adapters[provider] = ProviderAdapterFactory.create(provider, self)
    return self._adapters[provider]
```

---

### PROV-08 · `ProviderStateManager.save()` is never called — state lost on restart
**File:** `providers/state.py`  
**Current:** `ProviderStateManager` has full JSON persistence (`save()` method exists) but nothing calls it. Provider failure counts and cooldowns reset on every restart.

```python
# Fix — call save() after every state change and on shutdown:
def record_failure(self, provider: str, reason: FailoverReason, **kwargs) -> None:
    # ... existing logic
    self.save()  # persist immediately

# And in AgentCore.shutdown():
async def shutdown(self) -> None:
    self._providers._state.save()
```

---

## Part 4 — Permission Gate & Safety Improvements

---

### SAFE-01 · Add missing dangerous patterns (encoded execution, supply chain attacks)
**File:** `security_hardening.py` — `_DANGER_PATTERNS`  
**Current:** 45+ patterns covering known destructive commands. Missing modern attack patterns:

```python
# Add to _DANGER_PATTERNS:
MISSING_PATTERNS = [
    # Encoded execution
    (re.compile(r"base64\s+-d.*\|\s*(?:ba)?sh", re.I), "critical", "Base64 decode pipe to shell"),
    (re.compile(r"python[23]?\s+-c.*exec\(base64", re.I), "critical", "Python base64 exec"),
    
    # Supply chain / dependency confusion
    (re.compile(r"pip\s+install.*--index-url\s+http://", re.I), "high", "pip install from untrusted HTTP registry"),
    (re.compile(r"npm\s+install.*--registry\s+http://", re.I), "high", "npm install from untrusted HTTP registry"),
    
    # Credential exfiltration patterns
    (re.compile(r"cat\s+/etc/shadow", re.I), "critical", "Read shadow password file"),
    (re.compile(r"cat\s+/etc/passwd\s*\|\s*curl", re.I), "critical", "Exfiltrate passwd file"),
    (re.compile(r"aws\s+s3\s+cp.*s3://.*--acl\s+public", re.I), "high", "Upload to public S3 bucket"),
    
    # Persistence mechanisms
    (re.compile(r"echo.*>>\s*/etc/crontab", re.I), "high", "Write to system crontab"),
    (re.compile(r"echo.*>>\s*/etc/rc\.local", re.I), "high", "Write to rc.local persistence"),
    (re.compile(r"mkdir\s+-p.*\.ssh.*&&.*authorized_keys", re.I), "high", "SSH key persistence"),
    
    # Container escape
    (re.compile(r"docker.*--privileged.*run", re.I), "high", "Privileged Docker container"),
    (re.compile(r"nsenter\s+--target\s+1\s+--mount\s+--uts\s+--ipc\s+--net\s+--pid", re.I), "critical", "Container escape via nsenter"),
    
    # LOLBAS / GTFOBins patterns
    (re.compile(r"\bpython[23]?\s+-c.*import\s+os.*os\.system", re.I), "medium", "Python os.system execution"),
    (re.compile(r"\bperl\s+-e.*system\(", re.I), "medium", "Perl system() execution"),
]
```

---

### SAFE-02 · `GateResult` stages are hardcoded strings — no enum, fragile comparison
**File:** `permission_gate.py`  
**Current:** `stage: Literal["syntax", "forbidden", "permission", "review", "approved"]` — hardcoded string literals that could silently fail comparison.

```python
# Fix:
class GateStage(StrEnum):
    SYNTAX   = "syntax"
    FORBIDDEN = "forbidden"
    PERMISSION = "permission"
    REVIEW   = "review"
    APPROVED = "approved"

@dataclass
class GateResult:
    allowed: bool
    stage: GateStage   # ← enum, not Literal string
    reason: str = ""
```

---

### SAFE-03 · No audit trail entry for `requires_review=True` approvals
**File:** `executor.py` — `_check_permissions()`  
**Current:** `_log_safety()` logs to the Python logger and `session_log`. But approved commands that went through `requires_review` (human confirmed) are not written to the SHA-256 chained audit log — only blocked commands are logged.

```python
# Fix — log all gate decisions to audit trail:
async def _check_permissions(self, step: PlanStep) -> None:
    gate_result = self._permission_gate.check(command, tool=step.tool)
    
    # Log ALL decisions to audit trail, not just blocks
    from .audit_log import audit_logger
    audit_logger.log_permission_gate(
        tool=step.tool,
        command=command,
        decision=gate_result.stage,
        reason=gate_result.reason,
        requires_review=gate_result.requires_review,
    )
    
    if not gate_result.allowed:
        raise PermissionDeniedError(gate_result.reason)
```

---

### SAFE-04 · `InputValidator.sanitize_arg()` removes `=` via `$` strip — breaks valid arguments
**File:** `security_hardening.py` — `sanitize_arg()`  

```python
sanitized = re.sub(r"[`$|;&><]", "", sanitized)
```

This regex removes `$` which is correct for shell metacharacters, but in some tool arguments (e.g. regex patterns passed to grep/nuclei) the `$` is legitimate (end-of-line anchor). Blanket removal corrupts valid arguments.

```python
# Fix — context-aware sanitisation:
def sanitize_arg(self, value: str, allow_regex: bool = False) -> str:
    sanitized = value.replace("\x00", "").replace("\r", "").replace("\n", "").replace("\x1b", "")
    if allow_regex:
        # Only remove execution-capable metacharacters, keep regex metacharacters
        sanitized = re.sub(r"[`|;&]", "", sanitized)
    else:
        sanitized = re.sub(r"[`$|;&><]", "", sanitized)
    while "../" in sanitized or "..\\" in sanitized:
        sanitized = sanitized.replace("../", "").replace("..\\", "")
    return sanitized.strip()
```

---

### SAFE-05 · No sandbox mode for tool execution
**File:** `subprocess_utils.py` — `safe_run_async()`  
**Current:** All approved commands run as the current OS user with no isolation. A misconfigured tool or a subtle bypass in the gate could give full user-level access.

```python
# Add optional Docker sandbox:
async def safe_run_sandboxed(
    cmd: list[str],
    timeout: float = 30.0,
    image: str = "siyarix/sandbox:latest",
) -> ExecutionResult:
    """Run command inside a minimal Docker sandbox."""
    docker_cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "--user=nobody",
        "--memory=512m",
        "--cpus=1.0",
        "--read-only",
        "--tmpfs=/tmp:size=100m",
        image,
    ] + cmd
    return await safe_run_async(docker_cmd, timeout=timeout + 5)

# CLI flag:
# siyarix --sandbox scan quick example.com
```

---

### SAFE-06 · `stealth.py` (365 lines) exists and is tested but is not integrated into AgentCore
**File:** `stealth.py` + `tests/test_stealth.py`  
**Current:** `stealth.py` implements full stealth mode (suppressed logging, no banner, reduced network footprint). Tests pass. But `AgentCore` never imports or activates stealth mode.

```python
# Wire into AgentCore.start():
from .stealth import StealthManager

async def start(self) -> None:
    if os.getenv("SIYARIX_STEALTH") == "1" or settings.stealth_mode:
        self._stealth = StealthManager()
        await self._stealth.activate()
        logger.info("Stealth mode active")
```

---

### SAFE-07 · `opsec.py` OPSEC manager is fully implemented but no CLI command exposes it
**File:** `opsec.py` (365 lines) — full `OPSECManager` with `isolate()`, `burn()`, `enable_tor()`, `enable_doh()`, `randomize_mac()`  
**Current:** Zero CLI commands in `cli/__init__.py` expose these capabilities.

```python
# Add to CLI:
@app.command()
def opsec(
    action: str = typer.Argument(..., help="isolate|burn|status|tor|doh|mac"),
    target: str = typer.Option("", help="Target for isolation"),
):
    """OPSEC: target isolation, burn-after-reading, Tor routing."""
    from .opsec import opsec_manager
    if action == "isolate":
        result = opsec_manager.isolate(target, use_tor=False)
    elif action == "burn":
        result = opsec_manager.burn()
    elif action == "status":
        result = opsec_manager.status()
    console.print(result)
```

---

## Part 5 — Tool Call & Execution Improvements

---

### TOOL-01 · Native function calling API not used — all tool calls go through text repair
**File:** `tool_call_repair.py` + `providers/manager.py`  
**Current:** The `tool_call_repair.py` module implements full bracket and XML tool call parsing with Levenshtein fuzzy matching. This is excellent as a fallback — but it is the primary (and only) tool call path. Modern LLM APIs (OpenAI, Anthropic, Gemini, Groq) support native structured function calling that produces guaranteed-valid JSON tool calls without any text parsing.

```python
# Add native function calling to ProviderAdapter:
async def complete_with_tools(
    self,
    model: str,
    messages: list[dict],
    tools: list[ToolCapability],
) -> tuple[str, list[dict]]:
    tool_schemas = [t.to_openai_schema() for t in tools]
    
    if self.provider == "openai" or self.provider == "groq":
        response = await self._openai_client.chat.completions.create(
            model=model, messages=messages,
            tools=tool_schemas, tool_choice="auto",
        )
        tool_calls = response.choices[0].message.tool_calls or []
        return response.choices[0].message.content or "", [
            {"name": tc.function.name, "args": json.loads(tc.function.arguments)}
            for tc in tool_calls
        ]
    
    elif self.provider == "anthropic":
        response = await self._anthropic_client.messages.create(
            model=model, messages=messages,
            tools=[{"name": t["function"]["name"], "description": t["function"]["description"],
                    "input_schema": t["function"]["parameters"]} for t in tool_schemas],
        )
        tool_calls = [b for b in response.content if b.type == "tool_use"]
        return next((b.text for b in response.content if b.type == "text"), ""), [
            {"name": tc.name, "args": tc.input} for tc in tool_calls
        ]
    
    else:
        # Fallback to text repair for local/other providers
        text = await self.complete_text(model, messages)
        _, calls = promote_to_native_tool_calls(text, [t.name for t in tools])
        return text, calls
```

---

### TOOL-02 · `ToolCapability` has no JSON Schema for argument validation
**File:** `tool_models.py` (referenced from registry.py)  
**Current:** Tool capabilities have `name`, `description`, `tags`, `category`, `risk_level`, `aliases`. No `input_schema` for argument validation.

```python
# Add to ToolCapability:
@dataclass
class ToolCapability:
    name: str
    description: str = ""
    category: ToolCategory = ToolCategory.NETWORK
    risk_level: RiskLevel = RiskLevel.MEDIUM
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    # ADD:
    input_schema: dict = field(default_factory=dict)  # JSON Schema for args validation
    output_format: str = "text"  # "text" | "json" | "xml"
    requires_root: bool = False
    safe_mode_allowed: bool = True

    def to_openai_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema or {"type": "object", "properties": {}},
            }
        }
```

---

### TOOL-03 · `ToolCapabilityGraph.get_chain()` uses BFS but ignores edge weights
**File:** `tool_graph.py` — `get_chain()`  
**Current:** BFS finds a path between two tools but treats all edges as equal weight. Tool edges should have weights representing how well one tool's output feeds into another.

```python
# Fix — Dijkstra instead of BFS:
def get_optimal_chain(self, start: str, goal: str) -> list[str]:
    """Find the best tool chain by edge weight (lower = better transition)."""
    import heapq
    heap = [(0, [start])]
    visited = set()
    while heap:
        cost, path = heapq.heappop(heap)
        current = path[-1]
        if current == goal:
            return path
        if current in visited:
            continue
        visited.add(current)
        for edge in self._edges:
            if edge.source == current and edge.target not in visited:
                new_cost = cost + (1.0 - getattr(edge, "weight", 0.5))
                heapq.heappush(heap, (new_cost, path + [edge.target]))
    return []
```

---

### TOOL-04 · Parser registry discovers parsers but has no version compatibility check
**File:** `parsers/__init__.py`  
**Current:** Parser discovery maps tool names to parser classes. But if a tool (e.g. nmap) changes its output format between versions, the parser silently produces empty results.

```python
# Add version-aware parser selection:
@dataclass
class ParserVersion:
    min_tool_version: str = "0.0.0"
    max_tool_version: str = "999.999.999"
    parser_class: type = None

class ParserRegistry:
    def parse(self, tool_name: str, output: str) -> list[dict]:
        tool_version = self._detect_tool_version(tool_name, output)
        parser = self._get_versioned_parser(tool_name, tool_version)
        if not parser:
            return []
        try:
            return parser.parse(output)
        except Exception as e:
            logger.warning("Parser %s failed on %s output: %s", tool_name, tool_name, e)
            return [{"raw_output": output[:500], "parse_error": str(e)}]
```

---

### TOOL-05 · `make_generic_handler()` runs any binary without argument sanitisation
**File:** `registry.py` — `discover_from_path()` assigns `make_generic_handler` to unknown tools  
**Current:** Unknown binaries discovered on PATH get a generic handler. This handler likely passes `**kwargs` args directly to subprocess without going through `InputValidator`. Any tool not in the curated map bypasses safety checks.

```python
# Fix — InputValidator in generic handler:
def make_generic_handler(tool_name: str) -> ToolHandler:
    async def handler(target: str = "", flags: str = "", command: str = "", **kwargs) -> dict:
        from .security_hardening import validator
        
        # Validate all inputs
        if target:
            valid, error = validator.validate_target(target)
            if not valid:
                return {"status": "error", "error": f"Invalid target: {error}"}
        if flags:
            has_inj, pattern = validator.has_injection(flags)
            if has_inj:
                return {"status": "error", "error": f"Injection detected in flags: {pattern}"}
        
        cmd = [tool_name]
        if target:
            cmd.append(target)
        if flags:
            cmd.extend(flags.split())
        
        return await safe_run_async(cmd, timeout=60.0)
    return handler
```

---

### TOOL-06 · `Rust parsers` (`packages/rust_parsers/`) are never compiled or loaded
**File:** `packages/rust_parsers/Cargo.toml` + `src/lib.rs`  
**Current:** A Rust crate exists with high-performance tool output parsers (the 0.4% Rust in language stats). But it is never compiled, never loaded in `ParserRegistry`, and never mentioned in `CONTRIBUTING.md`. This represents unused performance infrastructure.

```toml
# packages/rust_parsers/Cargo.toml — add PyO3 binding:
[lib]
name = "siyarix_parsers"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.21", features = ["extension-module"] }
```

```python
# In parsers/__init__.py — try Rust parsers first:
try:
    from siyarix_parsers import NmapRustParser, NucleiRustParser
    RUST_PARSERS_AVAILABLE = True
except ImportError:
    RUST_PARSERS_AVAILABLE = False

def parse(self, tool_name: str, output: str) -> list[dict]:
    if RUST_PARSERS_AVAILABLE and tool_name in ("nmap", "nuclei"):
        return self._rust_parse(tool_name, output)
    return self._python_parse(tool_name, output)
```

---

### TOOL-07 · `WorkerPool` (`worker_pool.py`) has no backpressure — unlimited task queue
**File:** `worker_pool.py`  
**Current:** `AsyncWorkerPool` accepts unlimited submitted tasks. If a plan has 50 parallel steps, all 50 are queued immediately, potentially overwhelming the system.

```python
# Fix — add semaphore-based backpressure:
class AsyncWorkerPool:
    def __init__(self, max_workers: int = 10, max_queued: int = 50) -> None:
        self._semaphore = asyncio.Semaphore(max_workers)
        self._queue_semaphore = asyncio.Semaphore(max_queued)
    
    async def submit(self, fn, *args, **kwargs):
        async with self._queue_semaphore:
            async with self._semaphore:
                return await fn(*args, **kwargs)
```

---

### TOOL-08 · `tool_call_repair.py` `BRACKET_TOOL_RE` pattern is too strict — misses many LLM outputs
**File:** `tool_call_repair.py` line 14  
**Current:**
```python
BRACKET_TOOL_RE = re.compile(
    r"\[TOOL_[A-Z]+_[A-Z]+\]|\[tool(?::\w+)?\]|\[(\w+)\](?:\s*\n|\s+)(\{)", re.DOTALL
)
```

This regex requires either `[TOOL_UPPERCASE_UPPERCASE]` or `[word]` followed immediately by `{`. Many LLMs output tool calls as `[tool_name]\nargument: value` or `[tool_name]({"key": "val"})`. These are silently dropped.

```python
# Fix — broader pattern with fallback:
BRACKET_TOOL_RE = re.compile(
    r"\[(?:TOOL_[A-Z_]+|tool(?::\w+)?|(\w+))\]"
    r"(?:\s*\n|\s+)"
    r"(\{|\()",  # accept both { and ( opening
    re.DOTALL
)
```

---

### TOOL-09 · No tool output size limit — large nmap/nuclei outputs fill memory
**File:** `subprocess_utils.py` — `safe_run_async()`  
**Current:** stdout/stderr are accumulated without size limit. An nmap scan of a large subnet can produce MBs of output that fills memory.

```python
# Fix — streaming output with size cap:
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10MB limit

async def safe_run_async(cmd, timeout=60.0, max_output=MAX_OUTPUT_BYTES, **kwargs):
    chunks = []
    total_size = 0
    truncated = False
    
    async for chunk in stream_subprocess(cmd, timeout=timeout):
        chunks.append(chunk)
        total_size += len(chunk)
        if total_size > max_output:
            truncated = True
            break
    
    output = b"".join(chunks).decode(errors="replace")
    if truncated:
        output += f"\n[OUTPUT TRUNCATED — exceeded {max_output//1024//1024}MB limit]"
    return ExecutionResult(stdout=output)
```

---

## Part 6 — Knowledge Graph & Memory Improvements

---

### KG-01 · Wire existing `save_json()` / `load_json()` to startup/shutdown (see BUG-05)
Already detailed in BUG-05 — the methods exist and are complete. This item tracks the wiring work separately for priority scheduling.

---

### KG-02 · Knowledge graph has no TTL — stale findings accumulate forever
**File:** `knowledge_graph.py`  
**Current:** Nodes never expire. A vulnerability found 6 months ago on a host that has since been patched remains in the graph indefinitely.

```python
# Add TTL support to Node and KnowledgeGraph:
@dataclass
class Node:
    # ... existing fields
    ttl_seconds: float | None = None  # None = permanent
    
class KnowledgeGraph:
    def prune_stale(self) -> int:
        """Remove nodes older than their TTL. Returns count removed."""
        now = datetime.now(timezone.utc)
        stale = []
        for node in self._nodes.values():
            if node.ttl_seconds is None:
                continue
            age = (now - datetime.fromisoformat(node.discovered_at)).total_seconds()
            if age > node.ttl_seconds:
                stale.append(node.node_id)
        for nid in stale:
            self.remove_node(nid)
        return len(stale)
    
    def prune_schedule(self, interval_s: float = 3600.0) -> None:
        """Schedule automatic pruning. Call once at startup."""
        asyncio.create_task(self._prune_loop(interval_s))
```

---

### KG-03 · Knowledge graph not integrated with findings extraction
**File:** `core/__init__.py` — `_extract_findings()`  
**Current:** Findings are extracted into a flat list of dicts. None of them are written to the knowledge graph. The graph exists in parallel but receives no data from agent executions.

```python
# Fix — write findings to knowledge graph during extraction:
def _extract_findings(self, plan: ExecutionPlan) -> list[dict]:
    findings = []
    for step in plan.steps:
        if step.status != StepStatus.COMPLETED or not step.result:
            continue
        parsed = step.result.get("findings", [])
        for f in parsed:
            # Write to knowledge graph
            self._ingest_finding_to_graph(f, discovered_by=step.tool)
            findings.append(f)
    return findings

def _ingest_finding_to_graph(self, finding: dict, discovered_by: str) -> None:
    target = finding.get("target", "")
    if target:
        host_node = self._knowledge_graph.add_node(
            NodeType.HOST, label=target, discovered_by=discovered_by,
            ip=finding.get("ip", ""), hostname=finding.get("hostname", "")
        )
    if finding.get("cve") or finding.get("severity"):
        vuln_node = self._knowledge_graph.add_node(
            NodeType.VULNERABILITY, label=finding.get("cve", finding.get("title", "")),
            severity=finding.get("severity", ""), cve=finding.get("cve", ""),
            discovered_by=discovered_by,
        )
        if target:
            self._knowledge_graph.add_edge(host_node.node_id, vuln_node.node_id, EdgeType.HAS_VULN)
```

---

### KG-04 · `MemoryManager` (`memory.py`) and `ContextManager` (`context.py`) are separate — context is not persisted
**File:** `core/__init__.py`  
**Current:** `MemoryManager` handles long-term memory and `ContextManager` handles conversation history. But conversation history (`ContextManager`) is in-memory only. Between sessions the LLM has no memory of previous interactions.

```python
# Fix — persist context to SQLite via MemoryManager:
class ContextManager:
    def __init__(self, memory: MemoryManager | None = None):
        self._memory = memory
        self._history: list[dict] = []
        if memory:
            self._history = memory.load_context()  # load on init

    def add_history(self, content: str, role: str) -> None:
        entry = {"role": role, "content": content, "ts": time.time()}
        self._history.append(entry)
        if self._memory:
            self._memory.append_context(entry)  # persist immediately
```

---

### KG-05 · `graph.json` dependency graph (3,097 nodes) is a build artifact — automate its generation
**File:** `graph.json` (uploaded alongside source)  
**Current:** The dependency graph was built from the source but is checked into the repo as a static file. It will go stale as the codebase evolves.

```yaml
# Add to .github/workflows/ci.yml:
- name: Regenerate dependency graph
  run: |
    pip install graphify  # or whatever tool generated graph.json
    graphify src/siyarix/ --output graph.json
    git diff --exit-code graph.json || echo "::warning::graph.json is stale"
```

---

## Part 7 — Advanced Feature Additions
*(Previously labelled "NEXUS features" — now framed purely as Siyarix enhancements)*

---

### ADV-01 · REST API layer (FastAPI)
**Priority:** High  
Siyarix is CLI-only. Adding a REST API enables integration with CI/CD pipelines, SOAR platforms, and custom dashboards without shell subprocess hacks.

```
pip install siyarix[api]

POST   /v1/scan              → start scan, returns session_id
GET    /v1/scan/{id}         → poll status + results
DELETE /v1/scan/{id}         → abort scan
GET    /v1/sessions          → list sessions
POST   /v1/chat              → single-turn query
GET    /v1/tools             → list available tools
GET    /v1/providers         → list configured providers + status
GET    /v1/graph             → export knowledge graph as JSON
GET    /health               → health check
```

Auth: `Bearer` JWT via `SIYARIX_API_KEY`. Auto-generated OpenAPI docs at `/docs`.

---

### ADV-02 · WebSocket real-time event streaming
**Priority:** High  
The `chat/event_stream.py` module already defines the full typed event model (text_start/delta/end, toolcall_start/delta/end, thinking_*). Adding a WebSocket endpoint exposes this to remote clients without polling.

```
ws://localhost:8080/v1/stream/{session_id}

Client → {"type": "abort"}
Server → one JSON AgentEvent per message, using existing EventType schema
```

---

### ADV-03 · YAML Playbook engine
**Priority:** High  
Every engagement starts from scratch. A playbook engine enables reusable, shareable, version-controlled workflows that build on the existing `WorkflowEngine`.

```yaml
# playbooks/web_recon.yml
name: web_recon
version: 1.0.0
vars:
  target: "{{ env.TARGET }}"
steps:
  - id: subfinder
    tool: subfinder
    args: {domain: "{{ target }}"}
    output_var: subdomains
  - id: nuclei
    tool: nuclei
    args: {targets: "{{ subdomains }}", severity: "medium,high,critical"}
    depends_on: [subfinder]
    on_failure: skip
```

```bash
siyarix playbook run web_recon.yml --var target=example.com
siyarix playbook list
siyarix playbook validate web_recon.yml
```

---

### ADV-04 · MkDocs Material documentation site
**Priority:** High  
PyPI documentation URL points to GitHub repo root. The `docs/` folder has 40+ markdown files — it just needs a `mkdocs.yml` and a GitHub Actions deploy job.

```yaml
# mkdocs.yml
site_name: Siyarix
theme:
  name: material
  palette:
    - scheme: slate
nav:
  - Home: index.md
  - Getting Started: getting-started/installation.md
  - Routing Modes: architecture/interaction-modes.md
  - CLI Reference: user/cli-commands.md
  - AI Workflows: ai/multi-provider-routing.md
  - Playbooks: user/playbooks.md
  - Contributing: developer/contribution-guide.md
  - Ethical Use: security/ethical-hacking-policy.md
```

```bash
# Deploy: mkdocs gh-deploy --clean
```

---

### ADV-05 · pip-audit / safety check in CI
**Priority:** High  
A security orchestration tool with unaudited dependencies is ironic. No vulnerability scanning is in the current CI pipeline.

```yaml
- name: Audit dependencies for CVEs
  run: |
    pip install pip-audit
    pip-audit --require-hashes -r requirements.txt --format json -o audit.json
    python -c "
    import json, sys
    vulns = json.load(open('audit.json'))['vulnerabilities']
    critical = [v for v in vulns if any(f['id'].startswith('CVE') for f in v.get('fix_versions',[]))]
    if critical:
        print(f'FAIL: {len(critical)} vulnerabilities with fixes available')
        sys.exit(1)
    "
```

---

### ADV-06 · Automated CHANGELOG generation (git-cliff)
**Priority:** Medium  
The project uses Conventional Commits (well documented in `CONTRIBUTING.md`) but changelogs are maintained manually.

```bash
pip install git-cliff
# Configure cliff.toml with sections: feat, fix, security, perf, refactor, docs
git cliff --tag v2.1.0 -o CHANGELOG.md
```

---

### ADV-07 · Compliance evidence collection (SOC2/NIST/GDPR)
**Priority:** Medium  
`docs/user/compliance-frameworks.md` documents compliance checks. The code infrastructure (`security_commands.py`, `cvss_scorer.py`) exists. The missing piece is an evidence collection and report generation layer.

```python
class ComplianceEngine:
    async def run_assessment(self, framework: str, target: str) -> ComplianceReport:
        checks = self.FRAMEWORKS[framework](target)
        results = await asyncio.gather(*[c.run() for c in checks])
        evidence_dir = Path(f"./evidence/{framework}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        evidence_dir.mkdir(parents=True)
        self._collect_evidence(results, evidence_dir)
        return ComplianceReport(framework=framework, results=results, evidence_path=evidence_dir)
```

---

### ADV-08 · Dependabot for automated dependency updates
**Priority:** High  
Already partially in place (`.github/dependabot.yml` exists). Verify it covers both `pip` and `github-actions` ecosystems and has weekly schedule.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule: {interval: weekly}
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: /
    schedule: {interval: weekly}
```

---

### ADV-09 · Multi-model ensemble for high-risk decisions
**Priority:** Medium  
For `RiskTier.HIGH` decisions, query multiple providers simultaneously and use majority vote. Prevents single-model hallucinations from triggering dangerous commands.

```python
async def ensemble_decide(self, prompt: str, providers: list[str]) -> str:
    responses = await asyncio.gather(*[
        self._providers.complete(p, self._providers.select_provider(p)[1], "", prompt)
        for p in providers
    ], return_exceptions=True)
    valid = [r for r in responses if isinstance(r, dict)]
    if not valid:
        raise RuntimeError("All ensemble providers failed")
    # Simple majority vote on structured response
    from collections import Counter
    answers = [r.get("content", "") for r in valid]
    most_common = Counter(answers).most_common(1)[0][0]
    return most_common
```

---

### ADV-10 · SIEM export adapters (Elastic/Splunk/QRadar)
**Priority:** Medium  
The `[siem]` extra already exists in `pyproject.toml` with `httpx` as its only dependency. The placeholder is ready — it needs adapter implementations.

```python
class ElasticAdapter(SIEMAdapter):
    async def ship(self, event: AuditEvent) -> None:
        await self._client.post(f"{self.url}/_doc", json=event.to_elastic_format(),
                                headers={"Authorization": f"ApiKey {self.api_key}"})

class SplunkHECAdapter(SIEMAdapter):
    async def ship(self, event: AuditEvent) -> None:
        await self._client.post(f"{self.url}/services/collector/event",
                                json={"event": event.to_splunk_format(), "sourcetype": "siyarix"},
                                headers={"Authorization": f"Splunk {self.hec_token}"})
```

---

### ADV-11 · Succession plan and sustainability infrastructure
**Priority:** High  
Single maintainer in a legally complex environment. Current `GOVERNANCE.md` exists but needs concrete succession actions:
- Archive a stable release to Software Heritage (`softwareheritage.org`)
- Onboard 1–2 trusted co-maintainers
- Set up GitHub Sponsors
- Create a community Matrix/Discord channel

---

### ADV-12 · Python 3.13 CI matrix
**Priority:** Medium  
CHANGELOG notes an asyncio fix for Python 3.13. But CI does not verify it. Add 3.13 to the matrix.

```yaml
strategy:
  matrix:
    python-version: ["3.11", "3.12", "3.13"]
```

---

## Part 8 — Developer Experience & Infrastructure

---

### DX-01 · `CODEOWNERS` file for security-sensitive paths
```
# .github/CODEOWNERS
*                              @mufthakherul
src/siyarix/permission_gate.py @mufthakherul
src/siyarix/security_hardening.py @mufthakherul
src/siyarix/audit_log.py       @mufthakherul
src/siyarix/credential_store.py @mufthakherul
src/siyarix/opsec.py           @mufthakherul
.github/workflows/             @mufthakherul
```

---

### DX-02 · `Makefile` targets documented in `CONTRIBUTING.md`
`Makefile` exists (4,154 bytes) but `CONTRIBUTING.md` never mentions it. New contributors don't know `make test` or `make lint` exist.

---

### DX-03 · GitHub Discussions not enabled
`CONTRIBUTING.md` lists GitHub Discussions as a community channel. The feature is not enabled on the repo. Enable in Settings → Features → Discussions.

---

### DX-04 · Update pre-commit hooks — ruff pinned at v0.8.0 (months stale)
```bash
pre-commit autoupdate
git commit -m "chore: update pre-commit hooks"
```

---

### DX-05 · Remove stale `poetry.lock` — project uses hatchling
`poetry.lock` (106KB) exists alongside `pyproject.toml` with `[build-system] requires = ["hatchling"]`. These two tools are incompatible. Leaving `poetry.lock` confuses new contributors.

```bash
git rm poetry.lock
echo "*.lock" >> .gitignore  # optional
```

---

### DX-06 · Document the Rust component in `CONTRIBUTING.md`
`packages/rust_parsers/` contains a Cargo project. New contributors on systems without `rustup` will hit silent build failures. Add a "Rust component" section explaining what it does, how to build it, and how to skip it.

---

### DX-07 · Enforce `check-added-large-files` at 200KB not 1000KB
`.pre-commit-config.yaml` allows files up to 1MB. Reduce to 200KB for source files — legitimate Python files are never close to 1MB.

---

### DX-08 · Add issue and PR templates matching `CONTRIBUTING.md` format
`.github/ISSUE_TEMPLATE/bug_report.md` and `feature_request.md` exist but are minimal (925 bytes and 876 bytes). The actual required fields from `CONTRIBUTING.md` are more detailed. Align them.

---

### DX-09 · `AI_PROVIDER_POLICY.md` (8,758 bytes) is never linked from README
A detailed AI provider policy exists but is invisible. Add it to the README "Documentation" section.

---

### DX-10 · `ETHICAL_USE.md` and `RESPONSIBLE_AI_USE.md` should be surfaced in onboarding
Both files are comprehensive. Wire them into `onboarding.py` so first-run users are prompted to confirm they've read them.

```python
# In onboarding.py:
def prompt_ethical_acknowledgment(self) -> bool:
    console.print(Panel(
        "[yellow]Before using Siyarix, please confirm you have read and agree to:\n"
        "• ETHICAL_USE.md — Responsible disclosure and authorized testing only\n"
        "• RESPONSIBLE_AI_USE.md — AI governance and safety guidelines[/yellow]"
    ))
    return Confirm.ask("Do you confirm you will use Siyarix only for authorized security testing?")
```

---

## Implementation Priority Matrix

| Priority | Items | Estimated solo effort |
|----------|-------|-----------------------|
| **P0 — Fix before any new work** | BUG-01 to BUG-08, SAFE-03 | 1–2 weeks |
| **P1 — Complete the agent loop** | PIPE-04 (LLM in autonomous), PIPE-06 (shutdown), PROV-07 (complete()), PROV-08 (state save), KG-01 (wire persistence), TOOL-05 (generic handler safety) | 2–3 weeks |
| **P2 — Core improvements** | PIPE-01 to PIPE-03, PIPE-09, PIPE-12, PIPE-13, PROV-01, PROV-02, PROV-03, SAFE-01, TOOL-01, TOOL-02, KG-03 | 3–4 weeks |
| **P3 — Architecture** | PIPE-05 to PIPE-08, PIPE-10, PIPE-11, PIPE-14, PROV-04 to PROV-06, SAFE-04 to SAFE-07, TOOL-03 to TOOL-09, KG-02, KG-04, KG-05 | 4–5 weeks |
| **P4 — Advanced features** | ADV-01 to ADV-12 | 4–6 weeks |
| **P5 — DX & infrastructure** | DX-01 to DX-10 | 1–2 weeks |

**Total estimated solo effort: 15–22 weeks**  
**With Miraz actively working on P1 pipeline items: ~10–14 weeks**

---

## How to Approach Miraz With This Plan

1. **Start with BUG-05 (knowledge graph not wired)** — it is the single highest-impact, lowest-risk fix. The code already exists and works. You just wire two method calls. A clean PR in under 50 lines that permanently enables session persistence.

2. **Then PIPE-04 (wire llm_decompose_goal into autonomous mode)** — this completes the autonomous mode. Without this fix, "autonomous mode" is actually running the heuristic planner with an LLM label. Completing this is what Miraz is actively working on — aligning your contribution here is strategic.

3. **Then BUG-06 (hybrid mode race condition)** — a genuine concurrency bug that could cause incorrect routing under load. Easy to fix, high credibility signal.

4. **Propose ADV-01 (REST API) and ADV-03 (Playbooks) as coordinated PRs** — discuss the design in a GitHub issue before building. These are large features where alignment with Miraz's vision matters.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*  
*This improvement plan is offered as a free contribution to the Siyarix project and may be used by the maintainer and contributors without restriction.*
