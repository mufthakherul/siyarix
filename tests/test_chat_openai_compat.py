from __future__ import annotations

from siyarix.chat.openai_compat import (
    detect_compat,
    make_openai_adapter,
    resolve_model,
)
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import pytest


from siyarix.chat.openai_compat import _gemini_build_contents, _gemini_stream, _map_real_model, make_client, openai_complete, openai_stream
class TestOpenAICompatCore:
    """Cover remaining openai_compat.py lines."""

    def test_detect_compat_openrouter_thinking(self):
        compat = detect_compat("openrouter", "https://openrouter.ai/api/v1")
        assert compat.thinking_format == "openrouter"

    def test_detect_compat_default_openai(self):
        compat = detect_compat("unknown", "https://unknown.example.com")
        assert compat.thinking_format == "openai"

    def test_resolve_model_settings_dict(self):
        with patch("siyarix.chat.openai_compat.MODEL_KEYS", {"test": "test_model"}):
            with patch("siyarix.chat.openai_compat.PROVIDER_CONFIG", {"test": ("", "default-model", "")}):
                result = resolve_model("test", {"test_model": "custom"})
                assert result == "custom"

    def test_resolve_model_settings_dict_no_key(self):
        with patch("siyarix.chat.openai_compat.MODEL_KEYS", {"test": "test_model"}):
            with patch("siyarix.chat.openai_compat.PROVIDER_CONFIG", {"test": ("", "default-model", "")}):
                result = resolve_model("test", {})
                assert result == "default-model"

    def test_resolve_model_no_settings_provider_manager(self):
        mgr = MagicMock()
        mgr.resolve_model_id.return_value = "resolved-model"
        result = resolve_model("openai", {}, provider_manager=mgr)
        assert result is not None

    def test_make_client_basic_happy_path(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            mock_oai.return_value = "client"
            result = make_client("openai", "key")
            assert result == "client"

    def test_make_client_resolved_base_url_set(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            result = make_client("openai", "key", base_url="https://custom.url/v1")
            mock_oai.assert_called_once_with(api_key="key", base_url="https://custom.url/v1")

    def test_make_client_resolved_base_url_empty(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            with patch("siyarix.chat.openai_compat.PROVIDER_CONFIG", {"openai": ("https://openai.com", "gpt-5.5", "OPENAI_API_KEY")}):
                result = make_client("openai", "key", base_url="")
                mock_oai.assert_called_once_with(api_key="key", base_url="https://openai.com")

    def test_make_client_no_base_url(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            with patch("siyarix.chat.openai_compat.PROVIDER_CONFIG", {"openai": ("", "gpt-5.5", "OPENAI_API_KEY")}):
                result = make_client("openai", "key", base_url=None)
                mock_oai.assert_called_once_with(api_key="key")

    def test_make_client_api_key_none_uses_placeholder(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            result = make_client("ollama", None, base_url="http://localhost:11434/v1")
            mock_oai.assert_called_once_with(api_key="local", base_url="http://localhost:11434/v1")

    def test_gemini_build_contents(self):
        contents = _gemini_build_contents("sys", "user query", [{"role": "user", "content": "prev"}, {"role": "assistant", "content": "resp"}])
        assert len(contents) == 3
        assert contents[0]["role"] == "user"

    def test_gemini_build_contents_skips_system(self):
        contents = _gemini_build_contents("sys", "user query", [{"role": "system", "content": "skip"}])
        assert len(contents) == 1

    def test_gemini_stream_iterates_chunks(self):
        async def _test():
            lines = [
                "data: {\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"hello\"}]}}]}",
                "data: [DONE]",
            ]
            async def _aiter_lines():
                for l in lines:
                    yield l
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = MagicMock()
                mock_client_cls.return_value.__aenter__.return_value = mock_client
                mock_resp = MagicMock()
                mock_resp.aiter_lines = _aiter_lines
                mock_stream_cm = MagicMock()
                mock_stream_cm.__aenter__.return_value = mock_resp
                mock_client.stream.return_value = mock_stream_cm
                result = []
                async for token in _gemini_stream("key", "model", "sys", "user"):
                    result.append(token)
                assert result == ["hello"]

        asyncio.run(_test())

    def test_gemini_stream_skips_bad_json(self):
        async def _test():
            lines = ["data: invalid json", "data: [DONE]"]
            async def _aiter_lines():
                for l in lines:
                    yield l
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = MagicMock()
                mock_client_cls.return_value.__aenter__.return_value = mock_client
                mock_resp = MagicMock()
                mock_resp.aiter_lines = _aiter_lines
                mock_stream_cm = MagicMock()
                mock_stream_cm.__aenter__.return_value = mock_resp
                mock_client.stream.return_value = mock_stream_cm
                result = []
                async for token in _gemini_stream("key", "model", "sys", "user"):
                    result.append(token)
                assert result == []

        asyncio.run(_test())

    def test_openai_stream_includes_tools(self):
        async def _test():
            mock_client = MagicMock()
            mock_chunk = MagicMock()
            mock_chunk.choices = [MagicMock()]
            mock_chunk.choices[0].delta.content = "hello"
            mock_stream = AsyncMock()
            mock_stream.__aiter__.return_value = iter([mock_chunk])
            mock_client.chat.completions.create = AsyncMock(return_value=mock_stream)
            result = []
            async for token in openai_stream(mock_client, "model", "sys", "user", tools=[{"name": "test"}]):
                result.append(token)
            assert result == ["hello"]

        asyncio.run(_test())

    def test_openai_complete_includes_tools(self):
        async def _test():
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_choice = MagicMock()
            mock_choice.message.content = "response"
            mock_response.choices = [mock_choice]
            mock_response.usage.prompt_tokens = 10
            mock_response.usage.completion_tokens = 20
            mock_response.model = "gpt-4"
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            result = await openai_complete(mock_client, "model", "sys", "user", tools=[{"name": "test"}])
            assert result["content"] == "response"

        asyncio.run(_test())

    def test_openai_complete_exception_raises_llm_error(self):
        async def _test():
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("API error"))
            with pytest.raises(Exception, match="API call failed"):
                await openai_complete(mock_client, "model", "sys", "user")

        asyncio.run(_test())

    def test_map_real_model_gemini_flash(self):
        assert _map_real_model("gemini-3.5-flash") == "gemini-3.5-flash"

    def test_map_real_model_gemini_lite(self):
        assert _map_real_model("gemini-3.5-flash-lite") == "gemini-3.5-flash-lite"

    def test_map_real_model_gemini_pro(self):
        assert _map_real_model("gemini-4.0-pro") == "gemini-4.0-pro"

    def test_map_real_model_gpt_mini(self):
        assert _map_real_model("gpt-5.1-mini") == "gpt-5.1-mini"

    def test_map_real_model_gpt_nano(self):
        assert _map_real_model("gpt-5.0-nano") == "gpt-5.0-nano"

    def test_map_real_model_gpt_default(self):
        assert _map_real_model("gpt-5.5") == "gpt-5.5"

    def test_map_real_model_claude_sonnet(self):
        assert _map_real_model("claude-sonnet-4") == "claude-sonnet-4"

    def test_map_real_model_claude_opus(self):
        assert _map_real_model("claude-opus-4") == "claude-opus-4"

    def test_map_real_model_claude_haiku(self):
        assert _map_real_model("claude-haiku-4") == "claude-haiku-4"

    def test_map_real_model_unknown_returns_original(self):
        assert _map_real_model("some-other-model") == "some-other-model"

    def test_make_openai_adapter_gemini(self):
        result = make_openai_adapter("gemini", "key")
        assert callable(result)

    def test_make_openai_adapter_non_gemini_returns_adapter(self):
        with patch("openai.AsyncOpenAI") as mock_oai:
            mock_oai.return_value = MagicMock()
            result = make_openai_adapter("openai", "key", base_url="https://api.openai.com/v1")
            assert callable(result)


# ═══════════════════════════════════════════════════════════════════
# 5. chat/session.py (97% - missing 48->52, 82->84, 110->exit)
# ═══════════════════════════════════════════════════════════════════
