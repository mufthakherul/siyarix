# NexSec Implementation Roadmap & Action Items

**Updated**: May 17, 2026  
**Status**: READY FOR EXECUTION  
**Target**: Production-grade autonomous security agent

---

## PHASE 1: CRITICAL PATH (Weeks 1-6)

### WEEK 1: Retry Logic & Error Recovery

#### Task 1.1: Add Tenacity Retry Framework
- **Effort**: 4 hours
- **Files**: `engine.py`, `executor.py`
- **Changes**:
  ```python
  # engine.py
  from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
  
  @retry(
      stop=stop_after_attempt(3),
      wait=wait_exponential(multiplier=1, min=2, max=10),
      retry=retry_if_exception_type((TimeoutError, ConnectionError))
  )
  async def _execute_step_safe(self, step, interactive):
      return await self._execute_step(step, interactive)
  ```
- **Dependencies**: `tenacity>=8.2.0`
- **Tests**: Add test for retry behavior with mock failures

#### Task 1.2: Implement Circuit Breaker for Model Providers
- **Effort**: 6 hours
- **Files**: `planner.py`
- **Pattern**:
  ```python
  # planner.py
  from pybreaker import CircuitBreaker
  
  class TaskPlanner:
      def __init__(self):
          self._providers = []
          self._circuit_breakers = {}
      
      async def _plan_from_model(self, instruction, context):
          for provider in self._providers:
              cb = self._circuit_breakers.get(provider.__class__.__name__)
              if cb is None:
                  cb = CircuitBreaker(
                      fail_max=3,
                      reset_timeout=60,
                      name=provider.__class__.__name__
                  )
                  self._circuit_breakers[provider.__class__.__name__] = cb
              
              try:
                  with cb:
                      return await provider.plan(instruction, context)
              except:
                  continue
          return None
  ```
- **Dependencies**: `pybreaker>=1.4.0`
- **Tests**: Test open/closed/half-open states

#### Task 1.3: Add Step Result Caching
- **Effort**: 3 hours
- **Files**: `engine.py`
- **Goal**: If same tool + target has been run before, reuse results (with TTL)
- **Implementation**: LRU cache with 1-hour TTL

### WEEK 2: Workflow State Persistence

#### Task 2.1: Add Workflow State Tables
- **Effort**: 6 hours
- **Files**: `offline_store.py`
- **Schema**:
  ```sql
  CREATE TABLE execution_plans (
      id TEXT PRIMARY KEY,
      instruction TEXT NOT NULL,
      plan_json TEXT NOT NULL,
      source TEXT,
      status TEXT,
      created_at TEXT,
      completed_at TEXT,
      error TEXT
  );
  
  CREATE TABLE step_executions (
      id TEXT PRIMARY KEY,
      plan_id TEXT NOT NULL REFERENCES execution_plans(id),
      step_id TEXT NOT NULL,
      step_json TEXT NOT NULL,
      status TEXT NOT NULL,
      output TEXT,
      findings_json TEXT,
      error TEXT,
      created_at TEXT,
      updated_at TEXT
  );
  
  CREATE INDEX idx_plan_status ON execution_plans(status);
  CREATE INDEX idx_plan_created ON execution_plans(created_at DESC);
  CREATE INDEX idx_step_plan_id ON step_executions(plan_id);
  CREATE INDEX idx_step_status ON step_executions(status);
  ```
- **Methods**:
  - `save_plan(plan: ExecutionPlan) -> str` → returns plan_id
  - `save_step_result(plan_id, step_id, result) → None`
  - `get_plan(plan_id) → ExecutionPlan | None`
  - `get_plan_steps(plan_id) → list[StepExecution]`
  - `update_step_status(plan_id, step_id, status) → None`
  - `list_incomplete_plans() → list[ExecutionPlan]`

#### Task 2.2: Add Resume Capability
- **Effort**: 8 hours
- **Files**: `engine.py`, `main.py`
- **Changes**:
  ```python
  # engine.py
  async def resume_plan(self, plan_id: str) -> EngineResult:
      """Resume execution of a previously started plan."""
      # 1. Load plan from DB
      plan = self._offline_store.get_plan(plan_id)
      if not plan:
          raise ValueError(f"Plan {plan_id} not found")
      
      # 2. Get completed steps
      completed_steps = self._offline_store.get_plan_steps(plan_id)
      completed_ids = {s.step_id for s in completed_steps if s.status == "success"}
      
      # 3. Filter plan to unexecuted steps
      unexecuted = [s for s in plan.steps if s.id not in completed_ids]
      
      # 4. Execute remaining steps
      return await self._execute_plan_steps(unexecuted)
  ```
- **CLI Command**:
  ```bash
  siyarix run --resume <plan_id>
  ```

#### Task 2.3: Add Plan Serialization/Deserialization
- **Effort**: 4 hours
- **Files**: `planner.py`
- **Ensure**: `ExecutionPlan.to_dict()` and `ExecutionPlan.from_dict()` are robust

### WEEK 3: Fix Parallel Execution

#### Task 3.1: Implement Parallel Step Execution
- **Effort**: 8 hours
- **Files**: `engine.py`
- **Implementation**:
  ```python
  # engine.py
  async def _run_parallel_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
      """Execute a group of steps in parallel with concurrency limit."""
      sub_steps = step.metadata.get("steps", [])
      max_concurrent = step.metadata.get("max_concurrent", 3)
      
      if not sub_steps:
          return StepResult(step_id=step.id, status=StepStatus.SKIPPED)
      
      # Create semaphore for concurrency control
      semaphore = asyncio.Semaphore(max_concurrent)
      
      async def run_bounded(s):
          async with semaphore:
              return await self._execute_step(s, interactive)
      
      # Run all steps with bounded concurrency
      start = time.monotonic()
      results = await asyncio.gather(
          *[run_bounded(s) for s in sub_steps],
          return_exceptions=True
      )
      
      # Aggregate results
      all_findings = []
      all_outputs = []
      all_errors = []
      
      for res in results:
          if isinstance(res, Exception):
              all_errors.append(str(res))
          elif isinstance(res, StepResult):
              all_findings.extend(res.findings)
              all_outputs.append(res.output)
              if res.error:
                  all_errors.append(res.error)
      
      duration = (time.monotonic() - start) * 1000
      
      return StepResult(
          step_id=step.id,
          status=StepStatus.SUCCESS if not all_errors else StepStatus.FAILED,
          output="\n".join(all_outputs),
          error="; ".join(all_errors) if all_errors else "",
          findings=all_findings,
          duration_ms=duration,
      )
  ```
- **Plan Generation Update**: Planner should generate `parallel_group` steps for independent scans
- **Test**: Create mock plan with 5 parallel tool_run steps; measure speedup

#### Task 3.2: Remove --parallel Flag from CLI (Unused)
- **Effort**: 1 hour
- **Files**: `main.py`
- **Action**: Remove or document that parallel is now done via plan, not CLI flag

### WEEK 4: Integration Testing

#### Task 4.1: Create Integration Test Suite
- **Effort**: 16 hours
- **Files**: `tests/test_integration.py` (NEW)
- **Test Cases**:
  ```python
  # tests/test_integration.py
  
  class TestEndToEnd:
      """End-to-end integration tests."""
      
      async def test_full_scan_workflow(self):
          """Test: scan → parse → store → export"""
          engine = ExecutionEngine()
          result = await engine.execute("scan 127.0.0.1 with nmap")
          assert result.success
          assert len(result.all_findings) > 0
      
      async def test_workflow_persistence(self):
          """Test: execute → save → resume → complete"""
          engine = ExecutionEngine()
          result1 = await engine.execute("scan 127.0.0.1", dry_run=False)
          
          # Get plan ID
          plan_id = result1.plan.id
          
          # Resume
          result2 = await engine.resume_plan(plan_id)
          assert result2.success
      
      async def test_parallel_execution(self):
          """Test: parallel steps execute concurrently"""
          engine = ExecutionEngine()
          plan = ExecutionPlan(steps=[
              ExecutionStep(id="1", step_type=StepType.TOOL_RUN, tool="nmap", args=[...]),
              ExecutionStep(id="2", step_type=StepType.TOOL_RUN, tool="nikto", args=[...]),
          ])
          # Should run in ~same time, not 2x
          result = await engine._execute_plan(plan, None, False)
          assert result.total_duration_ms < 100000  # Not linear
      
      async def test_retry_on_timeout(self):
          """Test: transient timeout → retry → success"""
          # Mock tool that times out once, then succeeds
          # Verify retry happened
          pass
      
      async def test_model_provider_fallback(self):
          """Test: Model 1 fails → Model 2 succeeds"""
          planner = TaskPlanner()
          # Add mock providers with different availability
          planner.add_provider(MockProviderFails())
          planner.add_provider(MockProviderSucceeds())
          
          plan = await planner.plan("scan target")
          assert plan.source == "autonomous"
  
  class TestSecurity:
      """Security-focused integration tests."""
      
      def test_blocked_command_rejected(self):
          """Test: rm -rf / is blocked"""
          resolver = DynamicResolver()
          result = resolver.resolve("rm", ["-rf", "/"])
          assert not result.is_safe
      
      def test_safe_command_allowed(self):
          """Test: nmap is allowed"""
          resolver = DynamicResolver()
          result = resolver.resolve("nmap", ["-sV", "127.0.0.1"])
          assert result.is_safe
      
      def test_credential_roundtrip(self):
          """Test: Encrypt → Decrypt → Verify"""
          creds = CredentialStore()
          creds.set_password("test", "api_key", "secret123")
          retrieved = creds.get_password("test", "api_key")
          assert retrieved == "secret123"
  ```
- **CI Integration**: Run on every commit; fail if any test fails

#### Task 4.2: Performance Benchmarks
- **Effort**: 4 hours
- **Files**: `tests/test_performance.py` (NEW)
- **Metrics**:
  - Startup time: < 2 seconds
  - Single scan: < 30 seconds
  - Parallel 5 scans: < 20 seconds
  - Plan generation: < 5 seconds

### WEEK 5: Production Hardening

#### Task 5.1: Add Health Check Endpoints
- **Effort**: 6 hours
- **Files**: `engine.py`, `main.py`
- **Implementation**:
  ```python
  # engine.py
  @dataclass
  class HealthStatus:
      status: str  # "healthy" | "degraded" | "unhealthy"
      model_providers: dict[str, bool]
      tool_registry: dict[str, bool]
      offline_store: bool
      uptime_seconds: float
  
  async def health_check(self) -> HealthStatus:
      """Check system health."""
      return HealthStatus(
          status="healthy" if self._all_healthy() else "degraded",
          model_providers={
              type(p).__name__: p.available for p in self._planner._providers
          },
          tool_registry={
              t.name: t.path_exists for t in self._discovered_tools[:5]
          },
          offline_store=self._offline_store.is_connected,
          uptime_seconds=time.time() - self._start_time,
      )
  ```
- **CLI Command**:
  ```bash
  siyarix health
  ```

#### Task 5.2: Add Logging Improvements
- **Effort**: 4 hours
- **Files**: All Python files
- **Changes**:
  - Structured logging with JSON output option
  - Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Include context (plan_id, step_id, target) in all logs

#### Task 5.3: Add Metrics Collection
- **Effort**: 8 hours
- **Files**: `metrics.py` (NEW), `engine.py`
- **Implementation**:
  ```python
  # metrics.py
  from prometheus_client import Counter, Histogram, Gauge
  
  scans_total = Counter(
      'siyarix_scans_total',
      'Total scans executed',
      ['status', 'mode']
  )
  
  scan_duration = Histogram(
      'siyarix_scan_duration_seconds',
      'Scan duration in seconds'
  )
  
  findings_total = Gauge(
      'siyarix_findings_total',
      'Current number of findings'
  )
  ```
- **Export**: Prometheus format on `/metrics` endpoint

### WEEK 6: Documentation & Release

#### Task 6.1: Complete Migration Guide
- **Effort**: 4 hours
- **File**: `docs/v0.4.0-migration.md`
- **Content**:
  - Breaking changes (none expected)
  - New retry behavior
  - Resume workflow feature
  - Performance improvements

#### Task 6.2: Release v0.4.0
- **Effort**: 2 hours
- **Files**: `pyproject.toml`, `CHANGELOG.md`
- **Changes**:
  - Version bump to 0.4.0
  - Update README with new features
  - Tag GitHub release

---

## PHASE 2: ENTERPRISE FEATURES (Weeks 7-14)

### WEEK 7-8: Multi-Agent Orchestration

#### Feature: Agent Registry & Discovery
- Agents register on startup
- Heartbeat to central controller
- Auto-deregister on timeout

#### Feature: Task Queue
- Redis-based task queue
- Work stealing scheduler
- Result aggregation

### WEEK 9-10: Knowledge Graph

#### Feature: Asset Tracking
- Host inventory
- Service mapping
- Port/protocol tracking

#### Feature: Vulnerability Correlation
- CVE linking
- CVSS scoring
- Exploitability assessment

### WEEK 11-12: Agentic Loop

#### Feature: Reflection Step
- Analyze results
- Decide next actions
- Feed back into planning

#### Feature: Conditional Branching
- If-then-else support
- Dynamic plan modification
- Adaptive workflows

### WEEK 13-14: Enterprise Integrations

#### Feature: SIEM Connectors
- Splunk
- ELK Stack
- Azure Sentinel

#### Feature: Multi-Tenancy
- User isolation
- RBAC
- Audit trail per user

---

## PHASE 3: AUTONOMY BREAKTHROUGH (Weeks 15-24)

### Self-Improving Agent
- Model fine-tuning from results
- Prompt optimization
- Automated playbook generation

### Distributed Reconnaissance
- Swarm scanning
- Coordinated enumeration
- Result federation

### Advanced Threat Intelligence
- Threat feed integration
- Vulnerability prediction
- Attack path discovery

---

## QUICK START FOR DEVELOPERS

### Install Development Environment
```bash
cd /workspaces/siyarix
python -m venv venv
source venv/bin/activate
pip install -e ".[all]"
pip install -e ".[dev]"  # testing, linting
```

### Run Existing Tests
```bash
pytest tests/ -v
```

### Run New Integration Tests (After Phase 1)
```bash
pytest tests/test_integration.py -v --asyncio-mode=auto
```

### Build & Test Locally
```bash
# Single change
python -m pytest tests/test_execution_engine.py::TestExecutionEngine::test_retry_logic -v

# Full suite
python -m pytest tests/ -v --cov=src/siyarix
```

---

## SUCCESS CRITERIA

### Phase 1 Success
- [ ] All retry logic tests pass
- [ ] Can resume interrupted workflows
- [ ] Parallel scans run concurrently (measured)
- [ ] Integration tests all pass
- [ ] Health check endpoint working
- [ ] Release v0.4.0 published
- **Target**: 6 weeks, 0 regressions

### Phase 2 Success
- [ ] Multiple agents coordinate via queue
- [ ] Knowledge graph stores relationships
- [ ] Reflection step modifies plans
- [ ] SIEM integration tested
- [ ] Multi-tenant isolation verified
- **Target**: 8 weeks, handles 100+ concurrent scans

### Phase 3 Success
- [ ] Agent self-improves from execution data
- [ ] Swarm mode operational
- [ ] Attack path discovery functional
- [ ] Autonomous 24-hour operations without human input
- **Target**: 12 weeks, elite-level platform

---

## RISK MITIGATION

| Risk | Mitigation |
|------|-----------|
| Retry logic causes infinite loops | Add max_retries + circuit breaker |
| State persistence causes data corruption | Add transaction support; backup before deploy |
| Parallel execution causes race conditions | Use asyncio primitives; test thoroughly |
| Performance regressions | Add benchmarks; fail on regression |
| Breaking changes | Maintain backwards compatibility; version carefully |

---

## COMMUNITY & SUPPORT

- **Weekly Dev Calls**: Thursdays 10am UTC
- **GitHub Discussions**: For feature requests
- **Bug Reports**: GitHub Issues with reproduction steps
- **Security Issues**: security@siyarix.dev

---

## CONCLUSION

This roadmap is aggressive but achievable. **Focus on Phase 1 for production readiness.** Each phase builds on the previous; no skipping.

Key principle: **Done and working beats perfect and delayed.**

Start with retry logic this week. Measure. Deploy. Iterate.

Good luck! 🚀

