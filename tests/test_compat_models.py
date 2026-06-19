"""Tests for siyarix.compat - backward compatibility wrappers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch


from siyarix.compat import (
    EngineResult,
    ExecutionEngine,
    ExecutionMode,
    IntentRoute,
    IntentRouter,
    OperationCard,
    RiskTier,
    SessionContext,
    SessionKernel,
    SessionPersistenceLevel,
)
from siyarix.registry import RiskLevel


class TestExecutionMode:
    def test_values(self):
        assert ExecutionMode.REGISTRY == "registry"
        assert ExecutionMode.OFFLINE == "offline"
        assert ExecutionMode.AUTONOMOUS == "autonomous"
        assert ExecutionMode.INTEGRATED == "integrated"

    def test_members(self):
        assert len(ExecutionMode) == 4


class TestSessionPersistenceLevel:
    def test_values(self):
        assert SessionPersistenceLevel.EPHEMERAL == "ephemeral"
        assert SessionPersistenceLevel.WORKSPACE == "workspace"
        assert SessionPersistenceLevel.ORG_SHARED == "org_shared"

    def test_members(self):
        assert len(SessionPersistenceLevel) == 3


class TestOperationCard:
    def test_defaults(self):
        card = OperationCard(operation_id="op1", instruction="test")
        assert card.operation_id == "op1"
        assert card.instruction == "test"
        assert card.state == "planned"
        assert card.mode == "integrated"
        assert card.risk_tier == "low"
        assert card.retries == 0
        assert card.artifacts == []
        assert card.audit_hash == ""
        assert isinstance(card.created_at, str)
        assert isinstance(card.updated_at, str)

    def test_custom_fields(self):
        card = OperationCard(
            operation_id="op2",
            instruction="scan",
            state="running",
            mode="nmap",
            risk_tier="high",
            retries=2,
            artifacts=["result.txt"],
            audit_hash="abc123",
        )
        assert card.state == "running"
        assert card.mode == "nmap"
        assert card.risk_tier == "high"
        assert card.retries == 2
        assert card.artifacts == ["result.txt"]
        assert card.audit_hash == "abc123"

    def test_created_at_updated_at_iso(self):
        card = OperationCard(operation_id="op3", instruction="test")
        assert "T" in card.created_at
        assert "T" in card.updated_at

    def test_artifacts_mutable(self):
        card = OperationCard(operation_id="op4", instruction="test")
        card.artifacts.append("new_artifact")
        assert len(card.artifacts) == 1


class TestSessionContext:
    def test_defaults(self):
        ctx = SessionContext(session_id="s1")
        assert ctx.session_id == "s1"
        assert ctx.identity == "local-user"
        assert ctx.objective == ""
        assert ctx.scope == ""
        assert ctx.policy_context == {}
        assert ctx.model_context == {}
        assert ctx.tool_context == {}
        assert ctx.persistence == SessionPersistenceLevel.WORKSPACE
        assert ctx.operations == []

    def test_custom_fields(self):
        op = OperationCard(operation_id="op1", instruction="test")
        ctx = SessionContext(
            session_id="s2",
            identity="admin",
            objective="scan network",
            scope="10.0.0.0/24",
            policy_context={"allow": True},
            model_context={"model": "gpt4"},
            tool_context={"nmap": True},
            persistence=SessionPersistenceLevel.EPHEMERAL,
            operations=[op],
        )
        assert ctx.identity == "admin"
        assert ctx.objective == "scan network"
        assert ctx.scope == "10.0.0.0/24"
        assert ctx.policy_context == {"allow": True}
        assert ctx.model_context == {"model": "gpt4"}
        assert ctx.tool_context == {"nmap": True}
        assert ctx.persistence == SessionPersistenceLevel.EPHEMERAL
        assert len(ctx.operations) == 1


class TestSessionKernel:
    def test_init_default(self, tmp_path):
        with patch("siyarix.compat.get_config_dir", return_value=tmp_path):
            kernel = SessionKernel()
        assert (tmp_path / "kernel_sessions").exists()
        assert kernel._root == tmp_path / "kernel_sessions"

    def test_init_with_base_dir(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        assert kernel._root == tmp_path

    def test_start(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start(objective="test", scope="local", identity="admin")
        assert session.objective == "test"
        assert session.scope == "local"
        assert session.identity == "admin"
        assert isinstance(session.session_id, str)
        assert len(session.session_id) == 32
        assert session.persistence == SessionPersistenceLevel.WORKSPACE

    def test_start_defaults(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        assert session.objective == ""
        assert session.scope == ""
        assert session.identity == "local-user"

    def test_add_operation(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        op = kernel.add_operation(session, "scan target", "nmap", "medium")
        assert op.instruction == "scan target"
        assert op.mode == "nmap"
        assert op.risk_tier == "medium"
        assert len(session.operations) == 1
        assert isinstance(op.operation_id, str)
        assert len(op.operation_id) == 32

    def test_update_operation_found(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        op = kernel.add_operation(session, "test", "tool", "low")
        result = kernel.update_operation(
            session,
            op.operation_id,
            state="running",
            retries=1,
            artifact="out.txt",
            audit_hash="abc",
        )
        assert result is not None
        assert result.state == "running"
        assert result.retries == 1
        assert "out.txt" in result.artifacts
        assert result.audit_hash == "abc"

    def test_update_operation_not_found(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        result = kernel.update_operation(session, "nonexistent", state="done")
        assert result is None

    def test_update_operation_partial(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        op = kernel.add_operation(session, "test", "tool", "low")
        result = kernel.update_operation(session, op.operation_id, state="done")
        assert result is not None
        assert result.state == "done"
        assert result.retries == 0
        assert result.artifacts == []

    def test_update_operation_artifact_appends(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start()
        op = kernel.add_operation(session, "test", "tool", "low")
        kernel.update_operation(session, op.operation_id, artifact="a.txt")
        kernel.update_operation(session, op.operation_id, artifact="b.txt")
        assert len(op.artifacts) == 2

    def test_save(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start(objective="test objective")
        kernel.add_operation(session, "scan", "nmap", "low")
        saved_path = kernel.save(session)
        assert saved_path.exists()
        assert saved_path.suffix == ".json"
        assert session.session_id in saved_path.name
        content = saved_path.read_text(encoding="utf-8")
        assert "test objective" in content
        assert "operations" in content

    def test_load_found(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start(objective="test objective")
        kernel.add_operation(session, "scan", "nmap", "low")
        kernel.save(session)
        loaded = kernel.load(session.session_id)
        assert loaded is not None
        assert loaded.objective == "test objective"
        assert len(loaded.operations) == 1
        assert loaded.operations[0].instruction == "scan"

    def test_load_not_found(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        result = kernel.load("nonexistent")
        assert result is None

    def test_load_without_operations(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start(objective="bare session")
        kernel.save(session)
        loaded = kernel.load(session.session_id)
        assert loaded is not None
        assert len(loaded.operations) == 0

    def test_save_persistence_value(self, tmp_path):
        kernel = SessionKernel(base_dir=tmp_path)
        session = kernel.start(persistence=SessionPersistenceLevel.EPHEMERAL)
        path = kernel.save(session)
        data = __import__("json").loads(path.read_text(encoding="utf-8"))
        assert data["persistence"] == "ephemeral"


class TestEngineResult:
    def test_defaults(self):
        r = EngineResult()
        assert r.success is False
        assert r.summary == ""
        assert r.all_findings == []
        assert r.step_results == []
        assert r.raw_output == ""
        assert r.duration_ms == 0.0
        assert r.retries_performed == 0
        assert r.plan_id == ""
        assert r.error_message == ""

    def test_custom_values(self):
        r = EngineResult(
            success=True,
            summary="done",
            all_findings=[{"ip": "10.0.0.1"}],
            step_results=["s1"],
            raw_output="output",
            duration_ms=150.0,
            retries_performed=2,
            plan_id="p1",
            error_message="err",
        )
        assert r.success is True
        assert r.summary == "done"
        assert r.all_findings == [{"ip": "10.0.0.1"}]
        assert r.step_results == ["s1"]
        assert r.raw_output == "output"
        assert r.duration_ms == 150.0
        assert r.retries_performed == 2
        assert r.plan_id == "p1"
        assert r.error_message == "err"


class TestExecutionEngine:
    def test_init_defaults(self):
        engine = ExecutionEngine()
        assert engine._mode == ExecutionMode.INTEGRATED
        assert engine._registry is None
        assert engine._config == {}
        assert engine._session_logger is None

    def test_init_with_args(self):
        registry = MagicMock()
        engine = ExecutionEngine(
            mode=ExecutionMode.AUTONOMOUS,
            registry=registry,
            config={"key": "val"},
            session_logger="logger",
        )
        assert engine._mode == ExecutionMode.AUTONOMOUS
        assert engine._registry is registry
        assert engine._config == {"key": "val"}
        assert engine._session_logger == "logger"

    def test_build_context_with_enum(self):
        engine = ExecutionEngine(mode=ExecutionMode.REGISTRY)
        ctx = engine._build_context()
        assert ctx == {"mode": "registry"}

    def test_build_context_without_value_attr(self):
        engine = ExecutionEngine()
        engine._mode = "custom_mode"
        ctx = engine._build_context()
        assert ctx == {"mode": "custom_mode"}

    async def test_plan_with_registry(self):
        with patch("siyarix.planner_registry.RegistryPlanner") as MockPlanner:
            registry = MagicMock()
            registry.list_tools.return_value = []
            engine = ExecutionEngine(registry=registry)
            planner = MockPlanner.return_value
            await engine.plan("test instruction")
            registry.discover_from_path.assert_called_once()
            registry.scan_path.assert_called_once()
            planner.build_index.assert_called_once()
            planner.smart_plan.assert_called_once_with("test instruction", [])

    async def test_plan_with_registry_with_tools(self):
        with patch("siyarix.planner_registry.RegistryPlanner") as MockPlanner:
            registry = MagicMock()
            tool1 = MagicMock()
            tool1.name = "nmap"
            registry.list_tools.return_value = [tool1]
            engine = ExecutionEngine(registry=registry)
            planner = MockPlanner.return_value
            result = await engine.plan("scan target")
            planner.build_index.assert_called_once_with(
                ["nmap"], tool_registry=registry
            )
            planner.smart_plan.assert_called_once_with("scan target", ["nmap"])

    async def test_plan_without_registry(self):
        with patch("siyarix.planner_registry.RegistryPlanner") as MockPlanner:
            engine = ExecutionEngine()
            planner = MockPlanner.return_value
            result = await engine.plan("test instruction")
            planner.build_index.assert_called_once()
            planner.smart_plan.assert_called_once_with("test instruction", [])

    async def test_execute_success(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = "done"
            result_mock.findings = []
            result_mock.duration_ms = 100.0
            result_mock.plan = None
            agent.execute_goal.return_value = result_mock
            eng_result = await engine.execute("test goal")
            assert eng_result.success is True
            assert eng_result.summary == "done"
            assert eng_result.plan_id == ""
            assert eng_result.step_results == []
            agent.start.assert_awaited_once()
            agent.shutdown.assert_awaited_once()

    async def test_execute_with_plan_steps(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            plan_mock = MagicMock()
            plan_mock.id = "plan_123"
            step_mock = MagicMock()
            step_mock.status = "completed"
            step_mock.result = {"output": "step output"}
            plan_mock.steps = [step_mock]
            plan_mock.goal = "test goal"
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = "done"
            result_mock.findings = [{"finding": "x"}]
            result_mock.duration_ms = 200.0
            result_mock.plan = plan_mock
            agent.execute_goal.return_value = result_mock
            eng_result = await engine.execute("test goal")
            assert eng_result.plan_id == "plan_123"
            assert len(eng_result.step_results) == 1
            assert eng_result.step_results[0].output == "step output"

    async def test_execute_with_persist_and_plan(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
            patch("siyarix.offline_store.OfflineStore") as MockStore,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            plan_mock = MagicMock()
            plan_mock.id = "plan_123"
            step_mock = MagicMock()
            step_mock.tool = "nmap"
            step_mock.status = MagicMock()
            step_mock.status.value = "completed"
            step_mock.description = "scan"
            step_mock.result = {"output": "ok"}
            plan_mock.steps = [step_mock]
            plan_mock.goal = "test goal"
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = "done"
            result_mock.findings = [{"ip": "10.0.0.1"}]
            result_mock.duration_ms = 100.0
            result_mock.plan = plan_mock
            agent.execute_goal.return_value = result_mock
            store = MockStore.return_value
            eng_result = await engine.execute("test goal", persist=True)
            store.save_scan.assert_called_once_with(
                "test goal",
                result_mock.findings,
                mode="integrated",
                plan_id="plan_123",
            )
            store.save_plan.assert_called_once()

    async def test_execute_with_persist_no_plan(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
            patch("siyarix.offline_store.OfflineStore") as MockStore,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = "done"
            result_mock.findings = [{"finding": "x"}]
            result_mock.duration_ms = 100.0
            result_mock.plan = None
            agent.execute_goal.return_value = result_mock
            store = MockStore.return_value
            eng_result = await engine.execute("test goal", persist=True)
            store.save_scan.assert_called_once()
            store.save_plan.assert_not_called()

    async def test_execute_persist_exception(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
            patch("siyarix.offline_store.OfflineStore") as MockStore,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = "done"
            result_mock.findings = [{"finding": "x"}]
            result_mock.duration_ms = 100.0
            result_mock.plan = None
            agent.execute_goal.return_value = result_mock
            MockStore.side_effect = Exception("store error")
            eng_result = await engine.execute("test goal", persist=True)
            assert eng_result.success is True

    async def test_execute_with_mode_mapping(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
        ):
            for mode, expected_agent_mode in [
                (ExecutionMode.REGISTRY, "registry"),
                (ExecutionMode.OFFLINE, "registry"),
                (ExecutionMode.AUTONOMOUS, "autonomous"),
                (ExecutionMode.INTEGRATED, "hybrid"),
            ]:
                MockCore.reset_mock()
                agent = AsyncMock()
                MockCore.return_value = agent
                result_mock = MagicMock()
                result_mock.success = True
                result_mock.summary = ""
                result_mock.findings = []
                result_mock.duration_ms = 0.0
                result_mock.plan = None
                agent.execute_goal.return_value = result_mock
                engine = ExecutionEngine(mode=mode)
                await engine.execute("goal")
                _, kwargs = MockCore.call_args
                assert kwargs["mode"].value == expected_agent_mode

    async def test_execute_step_result_none(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
        ):
            engine = ExecutionEngine()
            agent = AsyncMock()
            MockCore.return_value = agent
            plan_mock = MagicMock()
            plan_mock.id = "p1"
            step_mock = MagicMock()
            step_mock.status = "failed"
            step_mock.result = None
            plan_mock.steps = [step_mock]
            plan_mock.goal = "test"
            result_mock = MagicMock()
            result_mock.success = False
            result_mock.summary = ""
            result_mock.findings = []
            result_mock.duration_ms = 0.0
            result_mock.plan = plan_mock
            agent.execute_goal.return_value = result_mock
            eng_result = await engine.execute("goal")
            assert eng_result.success is False
            assert eng_result.step_results[0].output == ""
            assert eng_result.step_results[0].error == ""

    async def test_execute_unknown_mode_fallback(self):
        with (
            patch("siyarix.core.AgentCore") as MockCore,
            patch("siyarix.core.AgentGoal") as MockGoal,
        ):
            engine = ExecutionEngine(mode="UNKNOWN")
            agent = AsyncMock()
            MockCore.return_value = agent
            result_mock = MagicMock()
            result_mock.success = True
            result_mock.summary = ""
            result_mock.findings = []
            result_mock.duration_ms = 0.0
            result_mock.plan = None
            agent.execute_goal.return_value = result_mock
            await engine.execute("goal")
            _, kwargs = MockCore.call_args
            assert kwargs["mode"].value == "hybrid"

    async def test_run(self):
        engine = ExecutionEngine()
        engine.execute = AsyncMock(return_value=EngineResult(success=True))
        result = await engine.run("test goal")
        assert result.success is True
        engine.execute.assert_awaited_once_with("test goal")

    async def test_resume(self):
        engine = ExecutionEngine()
        engine.execute = AsyncMock(return_value=EngineResult(success=True))
        result = await engine.resume("plan123")
        engine.execute.assert_awaited_once_with("Continue previous security plan (ID: plan123)")
        assert result.success is True


class TestIntentRoute:
    def test_defaults(self):
        route = IntentRoute()
        assert route.mode == "general"
        assert route.risk_tier is not None
        assert route.requires_confirmation is False

    def test_custom(self):
        route = IntentRoute(
            mode="scan", risk_tier=RiskTier("high"), requires_confirmation=True
        )
        assert route.mode == "scan"
        assert route.risk_tier == RiskTier("high")
        assert route.requires_confirmation is True

    def test_risk_tier_default(self):
        route = IntentRoute(mode="test")
        assert route.risk_tier == RiskTier("low")


class TestIntentRouter:
    def test_route_scan(self):
        router = IntentRouter()
        route = router.route("run nmap scan")
        assert route.mode == "scan"
        assert route.risk_tier == RiskTier("medium")
        assert route.requires_confirmation is False

    def test_route_port_scan(self):
        router = IntentRouter()
        route = router.route("port scan 10.0.0.1")
        assert route.mode == "scan"

    def test_route_recon(self):
        router = IntentRouter()
        route = router.route("recon target")
        assert route.mode == "recon"
        assert route.risk_tier == RiskTier("low")

    def test_route_enumerate(self):
        router = IntentRouter()
        route = router.route("enumerate services")
        assert route.mode == "recon"

    def test_route_discover(self):
        router = IntentRouter()
        route = router.route("discover hosts")
        assert route.mode == "recon"

    def test_route_web_http(self):
        router = IntentRouter()
        route = router.route("check http server")
        assert route.mode == "web"
        assert route.risk_tier == RiskTier("medium")

    def test_route_web_nikto(self):
        router = IntentRouter()
        route = router.route("run nikto")
        assert route.mode == "web"

    def test_route_web_nuclei(self):
        router = IntentRouter()
        route = router.route("run nuclei")
        assert route.mode == "web"

    def test_route_brute(self):
        router = IntentRouter()
        route = router.route("brute force ssh")
        assert route.mode == "brute"
        assert route.risk_tier == RiskTier("high")
        assert route.requires_confirmation is True

    def test_route_crack(self):
        router = IntentRouter()
        route = router.route("crack hash")
        assert route.mode == "brute"

    def test_route_password(self):
        router = IntentRouter()
        route = router.route("password attack")
        assert route.mode == "brute"

    def test_route_exploit(self):
        router = IntentRouter()
        route = router.route("exploit vulnerability")
        assert route.mode == "exploit"
        assert route.risk_tier == RiskTier("high")
        assert route.requires_confirmation is True

    def test_route_metasploit(self):
        router = IntentRouter()
        route = router.route("metasploit module")
        assert route.mode == "exploit"

    def test_route_attack(self):
        router = IntentRouter()
        route = router.route("attack target")
        assert route.mode == "exploit"

    def test_route_general(self):
        router = IntentRouter()
        route = router.route("hello world")
        assert route.mode == "general"
        assert route.risk_tier == RiskTier("low")
        assert route.requires_confirmation is False

    def test_route_empty(self):
        router = IntentRouter()
        route = router.route("")
        assert route.mode == "general"

    def test_route_case_insensitive(self):
        router = IntentRouter()
        route = router.route("SCAN ME")
        assert route.mode == "scan"


class TestRiskTier:
    def test_alias(self):
        assert RiskTier is RiskLevel

    def test_values(self):
        assert RiskTier.SAFE == "safe"
        assert RiskTier.LOW == "low"
        assert RiskTier.MEDIUM == "medium"
        assert RiskTier.HIGH == "high"
        assert RiskTier.CRITICAL == "critical"


class TestPublicAPI:
    def test_all_exports(self):
        from siyarix import compat
        expected = [
            "ExecutionMode",
            "SessionPersistenceLevel",
            "OperationCard",
            "SessionContext",
            "SessionKernel",
            "EngineResult",
            "ExecutionEngine",
            "IntentRoute",
            "IntentRouter",
        ]
        for name in expected:
            assert hasattr(compat, name)
