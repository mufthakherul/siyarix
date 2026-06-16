import pytest
import respx
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from siyarix.chat.openai_compat import (
    OpenAICompat,
    detect_compat,
    resolve_model,
    build_messages,
    make_client,
    _map_real_model,
    _gemini_build_contents,
    _gemini_generate,
    _gemini_stream,
    openai_complete,
    openai_stream,
    make_openai_adapter,
)
from siyarix.exceptions import LLMProviderError

def test_detect_compat():
    c1 = detect_compat("openai", "")
    assert c1.thinking_format == "openai"
    assert c1.supports_reasoning_effort is True
    
    c2 = detect_compat("deepseek", "https://api.deepseek.com")
    assert c2.thinking_format == "deepseek"
    assert c2.requires_reasoning_content_on_assistant is True
    
    c3 = detect_compat("zai", "")
    assert c3.thinking_format == "zai"
    assert c3.supports_reasoning_effort is False
    assert c3.zai_tool_stream is True

    c4 = detect_compat("together", "")
    assert c4.thinking_format == "together"
    assert c4.supports_strict_mode is False

def test_resolve_model():
    class DummySettings:
        def get(self, key):
            if key == "openai_model":
                return "custom-gpt"
            return None
    
    settings = DummySettings()
    assert resolve_model("openai", settings) == "custom-gpt"
    assert resolve_model("gemini", settings) == "gemini-3.5-flash" # fallback to default
    assert resolve_model("unknown", None) == "unknown"

def test_build_messages():
    compat = OpenAICompat(supports_developer_role=True)
    msgs = build_messages("sys", "usr", history=[{"role": "assistant", "content": "hello"}], compat=compat)
    assert msgs[0] == {"role": "developer", "content": "sys"}
    assert msgs[1] == {"role": "assistant", "content": "hello"}
    assert msgs[2] == {"role": "user", "content": "usr"}

    compat2 = OpenAICompat(supports_developer_role=False)
    msgs2 = build_messages("sys", "usr", history=None, compat=compat2)
    assert msgs2[0] == {"role": "system", "content": "sys"}

def test_map_real_model():
    assert _map_real_model("gemini-3.5-flash") == "gemini-2.0-flash"
    assert _map_real_model("gpt-5.5-mini") == "gpt-4o-mini"
    assert _map_real_model("claude-sonnet-4") == "claude-3-5-sonnet-latest"
    assert _map_real_model("other") == "other"

def test_gemini_build_contents():
    contents = _gemini_build_contents("sys", "usr", [{"role": "assistant", "content": "hi"}])
    assert len(contents) == 2
    assert contents[0]["role"] == "model"
    assert contents[0]["parts"][0]["text"] == "hi"
    assert contents[1]["role"] == "user"
    assert contents[1]["parts"][0]["text"] == "usr"

@pytest.mark.asyncio
@respx.mock
async def test_gemini_generate():
    respx.post("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent").mock(
        return_value=httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": "response"}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}
        })
    )
    res = await _gemini_generate("key", "gemini-2.0-flash", "sys", "usr")
    assert res["content"] == "response"
    assert res["input_tokens"] == 10
    assert res["output_tokens"] == 5

@pytest.mark.asyncio
@respx.mock
async def test_gemini_generate_blocked():
    respx.post("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent").mock(
        return_value=httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}})
    )
    with pytest.raises(LLMProviderError, match="Gemini request blocked"):
        await _gemini_generate("key", "gemini-2.0-flash", "", "bad")

@pytest.mark.asyncio
@respx.mock
async def test_gemini_stream():
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent"
    
    def mock_stream(_request):
        content = b'data: {"candidates": [{"content": {"parts": [{"text": "chunk1"}]}}]}\ndata: {"candidates": [{"content": {"parts": [{"text": "chunk2"}]}}]}\ndata: [DONE]\n'
        return httpx.Response(200, content=content)
    
    respx.post(url).mock(side_effect=mock_stream)
    chunks = []
    async for chunk in _gemini_stream("key", "gemini-2.0-flash", "", "usr"):
        chunks.append(chunk)
    assert chunks == ["chunk1", "chunk2"]

@pytest.mark.asyncio
@patch("openai.AsyncOpenAI")
async def test_openai_complete(_mock_client_class):
    mock_client = AsyncMock()
    
    class MockChoice:
        def __init__(self):
            self.message = MagicMock()
            self.message.content = "openai_resp"
            self.message.tool_calls = None
            
    class MockUsage:
        prompt_tokens = 5
        completion_tokens = 10
        
    class MockResponse:
        choices = [MockChoice()]
        usage = MockUsage()
        model = "gpt-4o"
        
    mock_client.chat.completions.create.return_value = MockResponse()
    
    res = await openai_complete(mock_client, "gpt-4o", "sys", "usr")
    assert res["content"] == "openai_resp"
    assert res["input_tokens"] == 5
    assert res["output_tokens"] == 10

@pytest.mark.asyncio
@patch("openai.AsyncOpenAI")
async def test_openai_complete_error(_mock_client_class):
    mock_client = AsyncMock()
    mock_client.chat.completions.create.side_effect = Exception("API down")
    
    with pytest.raises(LLMProviderError, match="API call failed"):
        await openai_complete(mock_client, "gpt-4o", "", "usr")

@pytest.mark.asyncio
@patch("openai.AsyncOpenAI")
async def test_openai_stream(_mock_client_class):
    mock_client = AsyncMock()
    
    class MockDelta:
        def __init__(self, content):
            self.content = content
            
    class MockChunk:
        def __init__(self, content):
            self.choices = [MagicMock(delta=MockDelta(content))]

    async def async_gen():
        yield MockChunk("stream")
        yield MockChunk(" chunk")

    mock_client.chat.completions.create.return_value = async_gen()
    
    chunks = []
    async for chunk in openai_stream(mock_client, "gpt-4o", "", "usr"):
        chunks.append(chunk)
        
    assert chunks == ["stream", " chunk"]

@pytest.mark.asyncio
@patch("siyarix.chat.openai_compat.openai_complete")
@patch("siyarix.chat.openai_compat.make_client")
async def test_make_openai_adapter_openai(mock_make_client, mock_complete):
    mock_complete.return_value = {"content": "ok"}
    adapter = make_openai_adapter("openai", "key")
    res = await adapter("sys", "usr")
    assert res == {"content": "ok"}
    mock_complete.assert_called_once()

@pytest.mark.asyncio
@patch("siyarix.chat.openai_compat._gemini_generate")
async def test_make_openai_adapter_gemini(mock_gemini_generate):
    mock_gemini_generate.return_value = {"content": "gemini_ok"}
    adapter = make_openai_adapter("gemini", "key")
    res = await adapter("sys", "usr")
    assert res == {"content": "gemini_ok"}
    mock_gemini_generate.assert_called_once()

@patch("subprocess.run")
def test_make_client_no_openai(mock_run):
    import sys
    # Mocking ImportError for openai inside make_client
    with patch.dict('sys.modules', {'openai': None}):
        with pytest.raises(ImportError):
            make_client("openai", "key")

@pytest.mark.asyncio
@patch("siyarix.chat.openai_compat.make_client")
async def test_make_openai_adapter_compaction(mock_make_client):
    from siyarix.chat.openai_compat import make_openai_adapter
    from siyarix.exceptions import LLMProviderError
    
    mock_client = AsyncMock()
    # first call raises context length error, second call succeeds
    mock_client.chat.completions.create.side_effect = [
        Exception("Context length exceeded"),
        AsyncMock(choices=[MagicMock(message=MagicMock(content="compacted ok", tool_calls=None))], usage=MagicMock(prompt_tokens=10, completion_tokens=5), model="gpt-4o")
    ]
    mock_make_client.return_value = mock_client
    
    class MockProviderManager:
        def resolve_model_id(self, provider, model):
            return model
            
        def classify_error(self, provider, _exc, _http_status):
            class MockClassified:
                should_compress = True
                retryable = True
                reason = "context"
            return MockClassified()
            
        def record_failure(self, provider, reason):
            pass

    manager = MockProviderManager()
    adapter = make_openai_adapter("openai", "key", provider_manager=manager)
    
    # mock CompactionEngine
    with patch("siyarix.compaction.CompactionEngine") as mock_compactor:
        instance = mock_compactor.return_value
        class MockResult:
            summary = "compacted history summary"
        instance.compact = AsyncMock(return_value=MockResult())
        
        history = [{"role": "user", "content": "long message"}]
        res = await adapter("sys", "usr", history=history)
        
        assert res["content"] == "compacted ok"
        instance.compact.assert_called_once()
        mock_client.chat.completions.create.assert_called()

@pytest.mark.asyncio
@patch("siyarix.chat.openai_compat.make_client")
async def test_make_openai_adapter_retryable(mock_make_client):
    from siyarix.chat.openai_compat import make_openai_adapter
    
    mock_client = AsyncMock()
    mock_client.chat.completions.create.side_effect = [
        Exception("Rate limit"),
        AsyncMock(choices=[MagicMock(message=MagicMock(content="retry ok", tool_calls=None))], usage=MagicMock(prompt_tokens=0, completion_tokens=0), model="gpt-4o")
    ]
    mock_make_client.return_value = mock_client
    
    class MockProviderManager:
        def resolve_model_id(self, provider, model): return model
        def classify_error(self, provider, _exc, _http_status):
            class MockClassified:
                should_compress = False
                retryable = True
                reason = "rate_limit"
            return MockClassified()
        def record_failure(self, provider, reason): pass

    manager = MockProviderManager()
    adapter = make_openai_adapter("openai", "key", provider_manager=manager)
    
    # mock asyncio.sleep to not actually sleep
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        res = await adapter("sys", "usr")
        assert res["content"] == "retry ok"
        mock_sleep.assert_called_once()
