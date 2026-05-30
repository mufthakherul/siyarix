# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for planner.py — TaskPlanner (515 stmts, ~50% covered)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.planner import (
    CircuitBreaker,
    CloudModel,
    ExecutionPlan,
    ExecutionStep,
    GeminiModel,
    GroqModel,
    LMStudioModel,
    ModelProvider,
    OllamaModel,
    OpenAIModel,
    StepType,
    TaskPlanner,
    TogetherModel,
    CustomModel,
)
from siyarix.interpreter import InterpretedTask, TaskCategory


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    def test_initial_state(self):
        cb = CircuitBreaker(name="test")
        assert cb.state == "closed"
        assert cb.is_available is True

    def test_open_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=2, name="test")
        cb.record_failure()
        assert cb.is_available is True
        cb.record_failure()
        assert cb.state == "open"
        assert cb.is_available is False

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, reset_timeout=0.01, name="test")
        cb.record_failure()
        assert cb.state == "open"
        import time
        time.sleep(0.02)
        assert cb.state == "half_open"

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=1, name="test")
        cb.record_failure()
        assert cb.state == "open"
        cb.reset()
        assert cb.state == "closed"
        assert cb._failure_count == 0

    def test_record_success_closes(self):
        cb = CircuitBreaker(failure_threshold=1, name="test")
        cb.record_failure()
        assert cb.state == "open"
        cb.record_success()
        assert cb.state == "closed"
        assert cb._failure_count == 0


# ---------------------------------------------------------------------------
# ExecutionStep / ExecutionPlan
# ---------------------------------------------------------------------------

class TestExecutionStep:
    def test_to_dict(self):
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nmap",
                             args=["-sV"], target="10.0.0.1", depends_on=[],
                             condition=None, timeout=300, description="scan")
        d = step.to_dict()
        assert d["id"] == "s1"
        assert d["step_type"] == "tool_run"
        assert d["tool"] == "nmap"
        assert d["args"] == ["-sV"]

    def test_repr(self):
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nmap")
        r = repr(step)
        assert "s1" in r
        assert "nmap" in r


class TestExecutionPlan:
    def test_to_dict(self):
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nmap")
        plan = ExecutionPlan(steps=[step], source="test", confidence=0.8,
                             raw_instruction="scan", interpreted_task=None)
        d = plan.to_dict()
        assert len(d["steps"]) == 1
        assert d["source"] == "test"
        assert d["confidence"] == 0.8

    def test_to_dict_with_interpreted_task(self):
        task = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                               confidence=0.9, tools=["nmap"], targets=["10.0.0.1"])
        plan = ExecutionPlan(steps=[], source="test", raw_instruction="scan",
                             interpreted_task=task)
        d = plan.to_dict()
        assert d["interpreted_task"] is not None

    def test_repr(self):
        plan = ExecutionPlan(steps=[], source="test")
        r = repr(plan)
        assert "test" in r


# ---------------------------------------------------------------------------
# OpenAIModel
# ---------------------------------------------------------------------------

class TestOpenAIModel:
    def test_not_available_without_key(self):
        model = OpenAIModel(api_key="")
        assert model.available is False

    def test_available_with_key(self):
        model = OpenAIModel(api_key="sk-test")
        assert model.available is True

    def test_not_available_missing_env(self):
        with patch.dict("os.environ", {}, clear=True):
            model = OpenAIModel()
            assert model.available is False

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_no_api_key(self):
        model = OpenAIModel(api_key="")
        result = await model.plan("test", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_openai_not_installed(self):
        model = OpenAIModel(api_key="sk-test")
        with patch("builtins.__import__", side_effect=ImportError("no openai")):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.skip(reason="requires openai package")
    @pytest.mark.asyncio
    async def test_plan_success(self):
        model = OpenAIModel(api_key="sk-test", model="gpt-4o")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"steps": [{"tool": "nmap"}]}'
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with patch("openai.AsyncOpenAI", return_value=mock_client):
            with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                result = await model.plan("scan target", {})
                assert "steps" in result
                assert result["steps"][0]["tool"] == "nmap"

    @pytest.mark.asyncio
    async def test_plan_with_base_url(self):
        model = OpenAIModel(api_key="sk-test", base_url="https://custom.api.com")
        assert model._base_url == "https://custom.api.com"

    @pytest.mark.skip(reason="requires openai package")
    @pytest.mark.asyncio
    async def test_plan_exception_returns_empty(self):
        model = OpenAIModel(api_key="sk-test")
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("API error"))

        with patch("openai.AsyncOpenAI", return_value=mock_client):
            with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                result = await model.plan("scan", {})
                assert result == {}


# ---------------------------------------------------------------------------
# GeminiModel
# ---------------------------------------------------------------------------

class TestGeminiModel:
    def test_not_available_without_key(self):
        model = GeminiModel(api_key="")
        assert model.available is False

    def test_available_with_key(self):
        model = GeminiModel(api_key="test-key")
        assert model.available is True

    def test_available_from_env(self):
        with patch.dict("os.environ", {"GEMINI_API_KEY": "env-key"}):
            model = GeminiModel()
            assert model.available is True

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_not_installed(self):
        model = GeminiModel(api_key="test-key")
        with patch("builtins.__import__", side_effect=ImportError("no genai")):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_no_key(self):
        model = GeminiModel(api_key="")
        result = await model.plan("test", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_plan_success(self):
        model = GeminiModel(api_key="test-key", model="gemini-pro")
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"steps": [{"tool": "nmap"}]}'
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch("builtins.__import__", return_value=mock_genai):
            with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                with patch("siyarix.planner.asyncio.to_thread") as mock_thread:
                    mock_thread.return_value = '{"steps": [{"tool": "nmap"}]}'
                    result = await model.plan("scan", {})
                    assert "steps" in result

    @pytest.mark.asyncio
    async def test_plan_exception_returns_empty(self):
        model = GeminiModel(api_key="test-key")
        with patch("builtins.__import__", side_effect=ImportError("no module")):
            result = await model.plan("scan", {})
            assert result == {}


# ---------------------------------------------------------------------------
# OllamaModel
# ---------------------------------------------------------------------------

class TestOllamaModel:
    def test_available_returns_true_optimistically(self):
        model = OllamaModel()
        assert model.available is True

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_httpx_not_installed(self):
        model = OllamaModel()
        with patch("builtins.__import__", side_effect=ImportError("no httpx")):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_plan_lazy_check_fails(self):
        model = OllamaModel()
        with patch.object(model, "_check_available", AsyncMock(return_value=False)):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_plan_success(self):
        model = OllamaModel(base_url="http://localhost:11434", model="llama3")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": {"content": '{"steps": [{"tool": "nmap"}]}'}
        }
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch.object(model, "_check_available", AsyncMock(return_value=True)):
                with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                    result = await model.plan("scan", {})
                    assert "steps" in result

    @pytest.mark.asyncio
    async def test_plan_http_failure(self):
        model = OllamaModel()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch.object(model, "_check_available", AsyncMock(return_value=True)):
                with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                    result = await model.plan("scan", {})
                    assert result == {}

    @pytest.mark.asyncio
    async def test_check_available_failure(self):
        model = OllamaModel()
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("connection refused"))
            ok = await model._check_available()
            assert ok is False

    @pytest.mark.asyncio
    async def test_check_available_success(self):
        model = OllamaModel()
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response)
            ok = await model._check_available()
            assert ok is True


# ---------------------------------------------------------------------------
# CloudModel
# ---------------------------------------------------------------------------

class TestCloudModel:
    def test_not_available_without_url(self):
        model = CloudModel()
        assert model.available is False

    def test_available_with_url_and_key(self):
        model = CloudModel(server_url="https://cloud.example.com", api_key="key")
        assert model.available is True

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_not_available(self):
        model = CloudModel()
        result = await model.plan("test", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_plan_returns_empty_if_no_httpx(self):
        model = CloudModel(server_url="https://example.com", api_key="key")
        with patch("builtins.__import__", side_effect=ImportError("no httpx")):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_plan_success(self):
        model = CloudModel(server_url="https://cloud.example.com", api_key="key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"steps": [{"tool": "nmap"}]}
        mock_client = MagicMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await model.plan("scan", {})
            assert "steps" in result

    @pytest.mark.asyncio
    async def test_plan_exception_returns_empty(self):
        model = CloudModel(server_url="https://cloud.example.com", api_key="key")
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("network error"))
            result = await model.plan("scan", {})
            assert result == {}


# ---------------------------------------------------------------------------
# _OpenAICompatibleModel base (used by Groq, Together, LMStudio, Custom)
# ---------------------------------------------------------------------------

class TestOpenAICompatibleModel:
    @pytest.mark.asyncio
    async def test_plan_no_httpx(self):
        model = GroqModel(api_key="test")
        with patch("builtins.__import__", side_effect=ImportError("no httpx")):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_lazy_check_fails(self):
        model = LMStudioModel()
        with patch.object(model, "_check_available", AsyncMock(return_value=False)):
            result = await model.plan("test", {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_lazy_check_success(self):
        model = LMStudioModel()
        with patch.object(model, "_check_available", AsyncMock(return_value=True)):
            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "choices": [{"message": {"content": '{"steps": []}'}}]
                }
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_resp)
                with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                    result = await model.plan("scan", {})
                    assert "steps" in result

    @pytest.mark.asyncio
    async def test_requires_api_key_missing(self):
        model = GroqModel(api_key="")
        result = await model.plan("test", {})
        assert result == {}


# ---------------------------------------------------------------------------
# GroqModel
# ---------------------------------------------------------------------------

class TestGroqModel:
    def test_defaults(self):
        model = GroqModel(api_key="test")
        assert model._base_url == "https://api.groq.com/openai/v1"
        assert model._name == "Groq"


# ---------------------------------------------------------------------------
# TogetherModel
# ---------------------------------------------------------------------------

class TestTogetherModel:
    def test_defaults(self):
        model = TogetherModel(api_key="test")
        assert model._base_url == "https://api.together.xyz/v1"

    @pytest.mark.asyncio
    async def test_plan_success(self):
        model = TogetherModel(api_key="test-key", model="mixtral")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"steps": [{"tool": "nmap"}]}'}}]
        }
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response)
            with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                result = await model.plan("scan", {})
                assert "steps" in result


# ---------------------------------------------------------------------------
# LMStudioModel
# ---------------------------------------------------------------------------

class TestLMStudioModel:
    def test_available_always_true(self):
        model = LMStudioModel()
        assert model.available is True

    def test_defaults(self):
        model = LMStudioModel()
        assert model._base_url == "http://localhost:1234"
        assert model._lazy_check is True


# ---------------------------------------------------------------------------
# CustomModel
# ---------------------------------------------------------------------------

class TestCustomModel:
    def test_defaults(self):
        model = CustomModel(server_url="https://custom.example.com", api_key="key")
        assert model._json_mode is False

    @pytest.mark.asyncio
    async def test_plan_no_model_sent(self):
        model = CustomModel(server_url="https://custom.example.com", api_key="key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": '{"steps": [{"tool": "nmap"}]}'}}]}
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response)
            with patch("siyarix.planner._build_system_prompt", return_value="sys"):
                result = await model.plan("scan", {})
                assert "steps" in result


# ---------------------------------------------------------------------------
# TaskPlanner
# ---------------------------------------------------------------------------

class TestTaskPlanner:
    def test_init(self):
        planner = TaskPlanner()
        assert len(planner._providers) == 0
        assert planner._interpreter is not None
        assert "OpenAIModel" in planner._circuit_breakers

    def test_add_provider(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        planner.add_provider(provider)
        assert len(planner._providers) == 1

    def test_set_providers(self):
        planner = TaskPlanner()
        p1 = MagicMock(spec=ModelProvider)
        p2 = MagicMock(spec=ModelProvider)
        planner.set_providers([p1, p2])
        assert len(planner._providers) == 2

    # ── plan() ─────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_plan_static_mode(self):
        planner = TaskPlanner()
        with patch.object(planner._interpreter, "interpret") as mock_interp:
            mock_interp.return_value = InterpretedTask(
                action="scan", category=TaskCategory.SCAN,
                confidence=0.9, tools=["nmap"], targets=["10.0.0.1"],
            )
            plan = await planner.plan("scan 10.0.0.1", force_mode="static")
            assert plan.source == "registry"
            assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_autonomous_mode_fails(self):
        planner = TaskPlanner()
        plan = await planner.plan("scan", force_mode="autonomous")
        assert plan.source == "autonomous"
        assert plan.confidence == 0.0
        assert len(plan.steps) == 0

    @pytest.mark.asyncio
    async def test_plan_integrated_high_confidence_interpreter(self):
        planner = TaskPlanner()
        with patch.object(planner._interpreter, "interpret") as mock_interp:
            task = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                   confidence=0.95, tools=["nmap"], targets=["10.0.0.1"])
            mock_interp.return_value = task
            plan = await planner.plan("scan 10.0.0.1")
            assert plan.source == "integrated-registry"
            assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_integrated_model_succeeds(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        provider.plan = AsyncMock(return_value={
            "steps": [{"id": "s1", "step_type": "tool_run", "tool": "nmap"}],
            "confidence": 0.9,
        })
        planner.add_provider(provider)

        with patch.object(planner._interpreter, "interpret") as mock_interp:
            task = InterpretedTask(action="unknown", category=TaskCategory.CUSTOM,
                                   confidence=0.3)
            mock_interp.return_value = task
            plan = await planner.plan("something complex")
            assert plan.source == "integrated-autonomous"
            assert len(plan.steps) > 0

    @pytest.mark.asyncio
    async def test_plan_integrated_fallback(self):
        planner = TaskPlanner()
        with patch.object(planner._interpreter, "interpret") as mock_interp:
            task = InterpretedTask(action="unknown", category=TaskCategory.CUSTOM,
                                   confidence=0.3, raw_text="echo hi")
            mock_interp.return_value = task
            plan = await planner.plan("something complex")
            assert plan.source == "integrated-fallback"

    @pytest.mark.asyncio
    async def test_plan_with_kwargs(self):
        planner = TaskPlanner()
        with patch.object(planner._interpreter, "interpret") as mock_interp:
            task = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                   confidence=0.95, tools=["nmap"], targets=["10.0.0.1"])
            mock_interp.return_value = task
            plan = await planner.plan("scan", extra_arg="val")
            assert plan is not None

    # ── interpret() ────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_interpret_unknown(self):
        planner = TaskPlanner()
        with patch.object(planner, "plan") as mock_plan:
            mock_plan.return_value = ExecutionPlan(steps=[], raw_instruction="unknown")
            result = await planner.interpret("do something weird")
            assert "Unknown instruction" in result

    @pytest.mark.asyncio
    async def test_interpret_known(self):
        planner = TaskPlanner()
        with patch.object(planner, "plan") as mock_plan:
            mock_plan.return_value = ExecutionPlan(
                steps=[ExecutionStep(id="s1", step_type=StepType.TOOL_RUN,
                                      tool="nmap", description="Port scan")],
                raw_instruction="scan")
            result = await planner.interpret("scan target")
            assert "Plan:" in result

    @pytest.mark.asyncio
    async def test_interpret_with_target(self):
        planner = TaskPlanner()
        with patch.object(planner, "plan") as mock_plan:
            mock_plan.return_value = ExecutionPlan(
                steps=[ExecutionStep(id="s1", step_type=StepType.TOOL_RUN,
                                      tool="nmap", description="Port scan")],
                raw_instruction="scan")
            result = await planner.interpret("scan", target="10.0.0.1")
            assert "Plan:" in result

    # ── replan() ───────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_replan_model_succeeds(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        provider.plan = AsyncMock(return_value={
            "steps": [{"id": "r1", "step_type": "tool_run", "tool": "nuclei"}],
        })
        planner.add_provider(provider)
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nmap")
        plan = await planner.replan("scan", {}, step, "step_failed")
        assert plan is not None
        assert plan.source == "adaptive-replan"

    @pytest.mark.asyncio
    async def test_replan_nikto_fallback(self):
        planner = TaskPlanner()
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nikto")
        plan = await planner.replan("scan", {}, step, "step_failed")
        assert plan is not None
        assert plan.steps[0].tool == "nuclei"
        assert plan.source == "adaptive-replan-fallback"

    @pytest.mark.asyncio
    async def test_replan_nmap_zero_findings(self):
        planner = TaskPlanner()
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="nmap")
        plan = await planner.replan("scan", {}, step, "zero_findings")
        assert plan is not None
        assert plan.steps[0].tool == "nuclei"

    @pytest.mark.asyncio
    async def test_replan_gobuster_zero_findings(self):
        planner = TaskPlanner()
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="gobuster")
        plan = await planner.replan("scan", {}, step, "zero_findings")
        assert plan is not None
        assert plan.steps[0].tool == "nikto"

    @pytest.mark.asyncio
    async def test_replan_no_fallback(self):
        planner = TaskPlanner()
        step = ExecutionStep(id="s1", step_type=StepType.TOOL_RUN, tool="unknown")
        plan = await planner.replan("scan", {}, step, "unknown_reason")
        assert plan is None

    # ── _plan_from_model ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_plan_from_model_circuit_breaker_open(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        planner.add_provider(provider)
        planner._circuit_breakers[type(provider).__name__] = MagicMock(
            is_available=False)
        result = await planner._plan_from_model("test", {})
        assert result is None

    @pytest.mark.asyncio
    async def test_plan_from_model_provider_fails(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        provider.plan = AsyncMock(side_effect=Exception("provider error"))
        planner.add_provider(provider)
        result = await planner._plan_from_model("test", {})
        assert result is None

    @pytest.mark.skip(reason="response_sensor/masking removed for v1.0")
    @pytest.mark.asyncio
    async def test_plan_from_model_response_sensor(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        provider.plan = AsyncMock(return_value={
            "steps": [{"id": "s1", "step_type": "tool_run", "tool": "nmap"}],
        })
        planner.add_provider(provider)
        mock_rs = MagicMock()
        mock_rs.mask_for_model.return_value = ("masked", MagicMock())
        mock_rs.unmask_and_redact.return_value = {
            "steps": [{"id": "s1", "step_type": "tool_run", "tool": "nmap"}],
        }
        with patch("siyarix.response_sensor.ResponseSensor", return_value=mock_rs):
            result = await planner._plan_from_model("scan 10.0.0.1", {})
            assert result is not None
            assert len(result.steps) == 1

    @pytest.mark.skip(reason="response_sensor/masking removed for v1.0")
    @pytest.mark.asyncio
    async def test_plan_from_model_masking_engine_fallback(self):
        planner = TaskPlanner()
        provider = MagicMock(spec=ModelProvider)
        provider.available = True
        provider.plan = AsyncMock(return_value={
            "steps": [{"id": "s1", "step_type": "tool_run", "tool": "nmap",
                        "target": "10.0.0.1"}],
        })
        planner.add_provider(provider)
        with patch("siyarix.response_sensor.ResponseSensor", side_effect=ImportError()):
            result = await planner._plan_from_model("scan 10.0.0.1", {})
            assert result is not None

    # ── _parse_model_response ──────────────────────────────────────────

    def test_parse_model_response_basic(self):
        planner = TaskPlanner()
        raw = {
            "steps": [
                {"id": "s1", "step_type": "tool_run", "tool": "nmap",
                 "args": ["-sV"], "target": "10.0.0.1"},
            ],
            "confidence": "0.85",
            "reasoning": "good plan",
        }
        plan = planner._parse_model_response(raw, "scan")
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "nmap"
        assert plan.confidence == 0.85

    def test_parse_model_response_str_steps(self):
        planner = TaskPlanner()
        raw = {
            "steps": '[{"id": "s1", "step_type": "tool_run", "tool": "nmap"}]',
            "confidence": 0.9,
        }
        plan = planner._parse_model_response(raw, "scan")
        assert len(plan.steps) == 1

    def test_parse_model_response_bad_json_steps(self):
        planner = TaskPlanner()
        raw = {"steps": "not valid json!!!"}
        plan = planner._parse_model_response(raw, "scan")
        assert len(plan.steps) == 0

    def test_parse_model_response_args_as_string(self):
        planner = TaskPlanner()
        raw = {
            "steps": [{"id": "s1", "step_type": "tool_run", "tool": "nmap",
                        "args": "-sV -sC"}],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.steps[0].args == ["-sV", "-sC"]

    def test_parse_model_response_depends_on_as_string(self):
        planner = TaskPlanner()
        raw = {
            "steps": [{"id": "s1", "step_type": "tool_run", "depends_on": "prev"}],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.steps[0].depends_on == ["prev"]

    def test_parse_model_response_bad_timeout(self):
        planner = TaskPlanner()
        raw = {
            "steps": [{"id": "s1", "step_type": "tool_run", "timeout": "abc"}],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.steps[0].timeout == 300

    def test_parse_model_response_ai_analysis(self):
        planner = TaskPlanner()
        raw = {
            "steps": [{"id": "s1", "step_type": "ai_analysis"}],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.steps[0].step_type == StepType.ANALYSIS

    def test_parse_model_response_unknown_step_type(self):
        planner = TaskPlanner()
        raw = {
            "steps": [{"id": "s1", "step_type": "nonexistent_type"}],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.steps[0].step_type == StepType.SHELL_CMD

    def test_parse_model_response_reasoning_list(self):
        planner = TaskPlanner()
        raw = {
            "steps": [],
            "reasoning": ["step 1", "step 2"],
        }
        plan = planner._parse_model_response(raw, "scan")
        assert "step 1" in plan.reasoning

    def test_parse_model_response_bad_confidence(self):
        planner = TaskPlanner()
        raw = {
            "steps": [],
            "confidence": "not_a_number",
        }
        plan = planner._parse_model_response(raw, "scan")
        assert plan.confidence == 0.5

    # ── _build_plan_from_task ──────────────────────────────────────────

    def test_build_plan_from_task_conditional(self):
        planner = TaskPlanner()
        then_sub = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                    confidence=0.9, tools=["nmap"], targets=["10.0.0.1"],
                                    flags={"branch": "then"})
        else_sub = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                    confidence=0.8, tools=["nuclei"], targets=["10.0.0.1"],
                                    flags={"branch": "else"})
        task = InterpretedTask(action="conditional", category=TaskCategory.CUSTOM,
                               confidence=0.9, flags={"condition": "port_80_open"},
                               sub_tasks=[then_sub, else_sub])
        plan = planner._build_plan_from_task(task, "conditional scan")
        assert len(plan.steps) > 0
        assert plan.steps[0].condition == "port_80_open"

    def test_build_plan_from_task_chain(self):
        planner = TaskPlanner()
        sub1 = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                confidence=0.9, tools=["nmap"], targets=["10.0.0.1"])
        sub2 = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                                confidence=0.8, tools=["nuclei"], targets=["10.0.0.1"],
                                flags={"chain_op": "&&"})
        task = InterpretedTask(action="chain", category=TaskCategory.WORKFLOW,
                               confidence=0.9, sub_tasks=[sub1, sub2])
        plan = planner._build_plan_from_task(task, "chain scan")
        assert len(plan.steps) == 2

    def test_build_plan_from_task_sub_tasks(self):
        planner = TaskPlanner()
        sub = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                              confidence=0.9, tools=["nmap"], targets=["10.0.0.1"])
        task = InterpretedTask(action="workflow", category=TaskCategory.WORKFLOW,
                               confidence=0.9, sub_tasks=[sub])
        plan = planner._build_plan_from_task(task, "workflow")
        assert len(plan.steps) > 0

    def test_build_plan_from_task_simple(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                               confidence=0.9, tools=["nmap"], targets=["10.0.0.1"])
        plan = planner._build_plan_from_task(task, "scan")
        assert len(plan.steps) > 0

    def test_build_plan_from_task_analysis(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="analyze", category=TaskCategory.ANALYZE,
                               confidence=0.8)
        plan = planner._build_plan_from_task(task, "analyze")
        assert len(plan.steps) > 0
        assert plan.steps[0].step_type == StepType.ANALYSIS

    def test_build_plan_from_task_report(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="report", category=TaskCategory.REPORT,
                               confidence=0.8, flags={"output_format": "html"})
        plan = planner._build_plan_from_task(task, "report")
        assert len(plan.steps) > 0
        assert plan.steps[0].step_type == StepType.REPORT

    def test_build_plan_from_task_custom_no_intent(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="custom", category=TaskCategory.CUSTOM,
                               confidence=0.8, raw_text="echo hi")
        plan = planner._build_plan_from_task(task, "custom")
        assert plan.steps[0].command == "echo hi"

    def test_build_plan_from_task_scan_all_tools(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="scan_all", category=TaskCategory.SCAN,
                               confidence=0.9, flags={"all_tools": True})
        plan = planner._build_plan_from_task(task, "scan all")
        assert plan.steps[0].tool == "__all__"

    def test_build_plan_from_task_scan_no_tools(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="scan", category=TaskCategory.SCAN,
                               confidence=0.8, tools=[])
        plan = planner._build_plan_from_task(task, "scan")
        assert plan.steps[0].tool == "nmap"

    def test_build_plan_from_task_unknown_category(self):
        planner = TaskPlanner()
        task = InterpretedTask(action="unknown", category=TaskCategory.UNKNOWN,
                               confidence=0.3, raw_text="weird command")
        plan = planner._build_plan_from_task(task, "weird")
        assert plan.steps[0].step_type == StepType.SHELL_CMD

    # ── _plan_from_interpretation ──────────────────────────────────────

    def test_plan_from_interpretation(self):
        planner = TaskPlanner()
        with patch.object(planner._interpreter, "interpret") as mock_interp:
            mock_interp.return_value = InterpretedTask(
                action="scan", category=TaskCategory.SCAN,
                confidence=0.9, tools=["nmap"], targets=["10.0.0.1"])
            plan = planner._plan_from_interpretation("scan 10.0.0.1")
            assert len(plan.steps) > 0


# ---------------------------------------------------------------------------
# _build_system_prompt
# ---------------------------------------------------------------------------

class TestBuildSystemPrompt:
    def test_build_system_prompt(self):
        from siyarix.planner import _build_system_prompt
        context = {
            "available_tools": [
                {"name": "nmap", "category": "recon", "capabilities": ["port_scan"]},
            ],
            "platform": "linux",
        }
        prompt = _build_system_prompt(context)
        assert "Siyarix" in prompt
        assert "nmap" in prompt
        assert "linux" in prompt

    def test_build_system_prompt_no_tools(self):
        from siyarix.planner import _build_system_prompt
        prompt = _build_system_prompt({})
        assert "no tools discovered" in prompt.lower()
