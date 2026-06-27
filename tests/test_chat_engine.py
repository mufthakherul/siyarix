import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from siyarix.chat.engine import LLMEngineMixin
from siyarix.exceptions import LLMProviderError


class FakeSettings:
    def __init__(self, data=None):
        self._data = data or {}

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, val):
        self._data[key] = val


class FakeProviderState:
    def is_disabled(self, name):
        return False


class FakeChatSession:
    def __init__(self):
        self.session_id = "test-session"
        self.messages = []
        self.mode = "integrated"
        self.target = ""
        self.context = {}

    def add_message(self, role, content, **metadata):
        class Msg:
            def __init__(self, r, c):
                self.role = r
                self.content = c

        msg = Msg(role, content)
        self.messages.append(msg)
        return msg


class SiyarixChatMock(LLMEngineMixin):
    def __init__(self, settings_data=None):
        self._settings = FakeSettings(settings_data)
        self._provider_state = FakeProviderState()
        self._session = FakeChatSession()

    async def _handle_slash(self, cmd: str) -> None:
        pass

    async def start_chat(self) -> None:
        from siyarix.chat.handlers import Prompt  # if imported

        while getattr(self, "_running", False):
            cmd = Prompt.ask(">>>")
            if cmd and cmd.startswith("/"):
                await self._handle_slash(cmd)


@pytest.fixture
def chat_mock():
    return SiyarixChatMock()


def test_resolve_provider_registry(chat_mock):
    chat_mock._settings.set("model_provider", "registry")
    prov, key = chat_mock._resolve_provider()
    assert prov is None
    assert key is None


@patch("siyarix.providers.ProviderManager")
@patch("siyarix.chat.engine.LLMEngineMixin._resolve_api_key")
def test_resolve_provider_explicit(mock_resolve_api_key, mock_pm_class, chat_mock):
    pm = MagicMock()
    mock_pm_class.get_instance.return_value = pm
    chat_mock._settings.set("model_provider", "openai")

    mock_profile = MagicMock()
    mock_profile.api_key_env = "OPENAI_API_KEY"
    pm.get_profile.return_value = mock_profile

    mock_resolve_api_key.return_value = "sk-test"

    prov, key = chat_mock._resolve_provider()
    assert prov == "openai"
    assert key == "sk-test"


@patch("siyarix.providers.ProviderManager")
def test_llm_available_registry(mock_pm_class, chat_mock):
    chat_mock._settings.set("model_provider", "registry")

    # Let's test a simple env-based provider
    mock_pm = MagicMock()
    mock_pm_class.get_instance.return_value = mock_pm
    mock_profile = MagicMock()
    mock_profile.api_key_env = "OPENAI_API_KEY"
    mock_pm.get_profile.return_value = mock_profile

    chat_mock._settings.set("model_provider", "openai")

    with patch("siyarix.chat.engine.LLMEngineMixin._resolve_api_key", return_value="test-key"):
        assert chat_mock._llm_available() is True


@patch("siyarix.provider_utils.check_provider_health")
def test_check_local_provider_running(mock_check_health):
    mock_check_health.return_value = True
    assert LLMEngineMixin._check_local_provider_running("ollama") is True
    mock_check_health.assert_called_once_with("ollama")


@patch(
    "siyarix.provider_utils.PROVIDER_DEFAULTS",
    {"ollama": {"url": "http://127.0.0.1:11434", "health_endpoint": "/"}},
)
@patch("siyarix.provider_utils.check_provider_health")
@patch("shutil.which")
def test_ensure_local_provider_running_already_running(mock_which, mock_check_health):
    mock_check_health.return_value = True
    mock_which.return_value = "/usr/bin/ollama"
    assert LLMEngineMixin._ensure_local_provider_running("ollama") is True


@pytest.mark.asyncio
async def test_make_llm_call_openai(chat_mock):
    with patch("siyarix.chat.openai_compat.make_openai_adapter") as mock_adapter:
        mock_fn = AsyncMock(
            return_value={"content": "test", "input_tokens": 10, "output_tokens": 5}
        )
        mock_adapter.return_value = mock_fn

        # Test call creation
        fn = chat_mock._make_llm_call("openai", "sk-test")

        res = await fn("system", "user")
        assert res["content"] == "test"

        mock_adapter.assert_called_once()
        assert mock_adapter.call_args.kwargs["provider"] == "openai"
        assert mock_adapter.call_args.kwargs["api_key"] == "sk-test"


@pytest.mark.asyncio
async def test_make_llm_call_unsupported(chat_mock):
    with pytest.raises(LLMProviderError):
        chat_mock._make_llm_call("invalid_provider_123", "key")


@pytest.mark.asyncio
async def test_execute_instruction_command(chat_mock):
    chat_mock._session.target = "127.0.0.1"
    chat_mock._session.mode = "integrated"

    with patch("siyarix.chat.engine.LLMEngineMixin._execute_agent") as mock_run:
        mock_run.return_value = ("stdout", "stderr")
        pass


@pytest.mark.asyncio
async def test_chat_loop_basic(chat_mock):
    with patch("siyarix.chat.handlers.Prompt.ask") as mock_ask:
        mock_ask.side_effect = ["/status", "/exit"]
        chat_mock._running = True

        # We need to mock _handle_slash and _execute_instruction
        with patch.object(chat_mock, "_handle_slash") as mock_slash:
            mock_slash.side_effect = (
                lambda cmd: setattr(chat_mock, "_running", False)
                if cmd.startswith("/exit")
                else None
            )
            await chat_mock.start_chat()
            # Loop should terminate because /exit sets _running = False
            assert mock_ask.call_count == 2


def test_should_use_compact_with_token_saver(chat_mock):
    chat_mock.SYSTEM_REFRESH_INTERVAL = 15

    # 1. When token_saver is False (default) -> should_use_compact should always be False
    chat_mock._settings.set("token_saver", False)
    chat_mock._llm_calls = 5
    assert chat_mock._should_use_compact() is False

    # 2. When token_saver is True -> should_use_compact should be True for calls 1-14, and False for multiples of 15
    chat_mock._settings.set("token_saver", True)

    # 0 calls -> False
    chat_mock._llm_calls = 0
    assert chat_mock._should_use_compact() is False

    # 5 calls -> True
    chat_mock._llm_calls = 5
    assert chat_mock._should_use_compact() is True

    # 15 calls -> False (multiple of 15 refresh interval)
    chat_mock._llm_calls = 15
    assert chat_mock._should_use_compact() is False

    # 16 calls -> True
    chat_mock._llm_calls = 16
    assert chat_mock._should_use_compact() is True


@pytest.mark.asyncio
async def test_wave_command_logging_in_session(chat_mock):
    # We want to test that the command execution is recorded in chat_mock._session.messages
    from siyarix.models import ExecutionPlan, PlanStep, PlanType

    plan = ExecutionPlan(
        goal="test command output preservation",
        steps=[
            PlanStep(
                id="step_0",
                description="test step",
                tool="nmap",
                command="nmap -sT localhost",
            )
        ],
        plan_type=PlanType.SEQUENTIAL,
    )

    # Mock executor and provider state
    with patch("siyarix.core.AgentCore") as mock_agent_class:
        agent = MagicMock()
        mock_agent_class.return_value = agent

        agent.initialize = AsyncMock()
        agent._registry = MagicMock()
        agent._registry.list_tools.return_value = []

        agent.executor_autonomous = MagicMock()
        agent.executor_autonomous.execute_plan = AsyncMock(return_value=plan)
        agent.executor_autonomous.command_review = True

        # Setup executed steps results
        plan.steps[0].result = {
            "status": "success",
            "output": "Nmap scan report for localhost\nHost is up (0.001s).\nPORT   STATE SERVICE\n80/tcp open  http",
            "error": "",
        }

        # Mock LLM engine and planner logic inside _execute_agent
        with (
            patch.object(chat_mock, "_resolve_provider", return_value=("openai", "key")),
            patch.object(
                chat_mock,
                "_make_llm_call",
                return_value=AsyncMock(return_value={"content": "Done."}),
            ),
            patch.object(chat_mock, "_llm_available", return_value=True),
            patch.object(chat_mock, "_check_local_provider_running", return_value=False),
            patch("siyarix.chat.engine.console") as mock_console,
        ):
            # Setup agent.planner_autonomous.plan to return a plan on first call, and empty steps on second call (done)
            second_plan = ExecutionPlan(goal="test", steps=[], plan_type=PlanType.SEQUENTIAL)
            second_plan.context = {"response": "Final synthesis"}

            agent.planner_autonomous = MagicMock()
            agent.planner_autonomous.plan = AsyncMock(side_effect=[plan, second_plan])

            chat_mock._mode = "autonomous"
            chat_mock._session.target = "127.0.0.1"
            # Run _execute_agent
            res = await chat_mock._execute_agent("test", require_llm=True)
            assert res is True

            # Now let's verify that command log messages were added to the session!
            # The session should have the executed command (assistant) and the command output (user).
            messages = chat_mock._session.messages

            # Find the Executed command message
            cmd_msg = next(
                (m for m in messages if m.role == "assistant" and "Executed command:" in m.content),
                None,
            )
            assert cmd_msg is not None
            assert "nmap -sT localhost" in cmd_msg.content

            # Find the Command output message
            output_msg = next(
                (m for m in messages if m.role == "user" and "Command output:" in m.content), None
            )
            assert output_msg is not None
            assert "PORT   STATE SERVICE" in output_msg.content
            assert "80/tcp open  http" in output_msg.content
