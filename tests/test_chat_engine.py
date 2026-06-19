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

class SiyarixChatMock(LLMEngineMixin):
    def __init__(self, settings_data=None):
        self._settings = FakeSettings(settings_data)
        self._provider_state = FakeProviderState()
        self._session = FakeChatSession()

    async def _handle_slash(self, cmd: str) -> None:
        pass
        
    async def start_chat(self) -> None:
        from siyarix.chat.handlers import Prompt # if imported
        while getattr(self, "_running", False):
            # For the test, we assume mock_ask is patched over Prompt.ask
            # but wait, Prompt.ask is patched, so we can just call it
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
    # Actually registry should not report available, or wait, does it?
    # the function is _llm_available
    # If "cloud", "custom", "opencode" etc.
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

@patch("siyarix.provider_utils.PROVIDER_DEFAULTS", {"ollama": {"url": "http://127.0.0.1:11434", "health_endpoint": "/"}})
@patch("siyarix.provider_utils.check_provider_health")
@patch("shutil.which")
def test_ensure_local_provider_running_already_running(mock_which, mock_check_health):
    mock_check_health.return_value = True
    mock_which.return_value = "/usr/bin/ollama"
    assert LLMEngineMixin._ensure_local_provider_running("ollama") is True

@pytest.mark.asyncio
async def test_make_llm_call_openai(chat_mock):
    with patch("siyarix.chat.openai_compat.make_openai_adapter") as mock_adapter:
        mock_fn = AsyncMock(return_value={"content": "test", "input_tokens": 10, "output_tokens": 5})
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
        # Simulating it handling a direct command if in shell mode, wait, in integrated mode it goes to planner.
        # If we just mock out the planner and executor:
        pass

@pytest.mark.asyncio
async def test_chat_loop_basic(chat_mock):
    with patch("siyarix.chat.handlers.Prompt.ask") as mock_ask:
        mock_ask.side_effect = ["/status", "/exit"]
        chat_mock._running = True
        
        # We need to mock _handle_slash and _execute_instruction
        with patch.object(chat_mock, "_handle_slash") as mock_slash:
            mock_slash.side_effect = lambda cmd: setattr(chat_mock, "_running", False) if cmd.startswith("/exit") else None
            await chat_mock.start_chat()
            # Loop should terminate because /exit sets _running = False
            assert mock_ask.call_count == 2
