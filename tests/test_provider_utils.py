from __future__ import annotations

import respx
import httpx
from unittest.mock import patch, MagicMock
from siyarix.provider_utils import (
    _is_safe_url,
    safe_http_get,
    safe_http_post,
    safe_http_get_raw,
    resolve_provider_url,
    is_reasoning_model,
    build_model_definition,
    list_provider_models,
    enrich_model,
    discover_provider_models,
    pull_model,
    ensure_model_pulled,
    check_provider_health,
)

def test_is_safe_url():
    assert _is_safe_url("http://localhost:11434") is True
    assert _is_safe_url("http://127.0.0.1:8000") is True
    assert _is_safe_url("http://[::1]:8080") is True
    assert _is_safe_url("http://192.168.1.100") is True
    assert _is_safe_url("http://10.0.0.5") is True
    assert _is_safe_url("http://example.com") is False
    assert _is_safe_url("https://8.8.8.8") is False
    assert _is_safe_url("ftp://localhost") is False
    assert _is_safe_url("invalid_url") is False

@respx.mock
def test_safe_http_get():
    url = "http://localhost:11434/api/tags"
    respx.get(url).mock(return_value=httpx.Response(200, json={"models": []}))
    res = safe_http_get(url)
    assert res == {"models": []}

    # Test unsafe URL
    assert safe_http_get("http://example.com/api") is None

    # Test error
    respx.get("http://localhost:9999").mock(side_effect=httpx.ConnectError("Connection refused"))
    assert safe_http_get("http://localhost:9999") is None

@respx.mock
def test_safe_http_post():
    url = "http://localhost:11434/api/show"
    respx.post(url).mock(return_value=httpx.Response(200, json={"info": "test"}))
    res = safe_http_post(url, payload={"name": "llama2"})
    assert res is not None
    assert res.json() == {"info": "test"}

    assert safe_http_post("http://example.com", {}) is None

@respx.mock
def test_safe_http_get_raw():
    url = "http://localhost:11434/api/tags"
    respx.get(url).mock(return_value=httpx.Response(200, json={"test": "ok"}))
    res = safe_http_get_raw(url)
    assert res is not None
    assert res.status_code == 200

    assert safe_http_get_raw("http://example.com") is None

def test_resolve_provider_url():
    assert resolve_provider_url("ollama") == "http://localhost:11434"
    assert resolve_provider_url("ollama", "http://127.0.0.1:11434/") == "http://127.0.0.1:11434"
    assert resolve_provider_url("unknown", "http://localhost:9999") == "http://localhost:9999"
    assert resolve_provider_url("unknown") == ""

def test_is_reasoning_model():
    assert is_reasoning_model("deepseek-r1") is True
    assert is_reasoning_model("qwq-32b") is True
    assert is_reasoning_model("llama3-reasoning") is True
    assert is_reasoning_model("llama-3-8b") is False

def test_build_model_definition():
    defn = build_model_definition("llama3", context_window=8192, capabilities=["vision", "tools"])
    assert defn["name"] == "llama3"
    assert defn["supports_vision"] is True
    assert defn["supports_tools"] is True
    assert defn["context_window"] == 8192

    defn2 = build_model_definition("deepseek-r1")
    assert defn2["reasoning"] is True
    assert defn2["supports_tools"] is True
    assert defn2["supports_vision"] is False

@respx.mock
def test_list_provider_models():
    respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "llama3:latest"}]}))
    models = list_provider_models("ollama")
    assert len(models) == 1
    assert models[0]["name"] == "llama3:latest"

    respx.get("http://localhost:1234/v1/models").mock(return_value=httpx.Response(200, json={"data": [{"id": "gpt-local"}]}))
    lm_models = list_provider_models("lmstudio")
    assert len(lm_models) == 1
    assert lm_models[0]["name"] == "gpt-local"

    # Unknown provider
    assert list_provider_models("unknown") == []

@respx.mock
def test_enrich_model():
    respx.post("http://localhost:11434/api/show").mock(return_value=httpx.Response(200, json={
        "model_info": {"llama.context_length": 8192, "llama.max_tokens": 4096},
        "capabilities": ["tools"]
    }))
    enriched = enrich_model("ollama", "llama3:latest")
    assert enriched["context_window"] == 8192
    assert enriched["max_tokens"] == 4096
    assert enriched["supports_tools"] is True

    # LMStudio enrichment
    lm_entry = {
        "loaded_instances": [{"context_length": 4096}],
        "metadata": {"vision": True, "reasoning": False, "tools": True, "max_tokens": 2048}
    }
    enriched_lm = enrich_model("lmstudio", "gpt-local", model_entry=lm_entry)
    assert enriched_lm["context_window"] == 4096
    assert enriched_lm["supports_vision"] is True
    assert enriched_lm["max_tokens"] == 2048

    # vLLM enrichment
    vllm_entry = {"max_model_len": 16384}
    enriched_vllm = enrich_model("vllm", "vllm-model", model_entry=vllm_entry)
    assert enriched_vllm["context_window"] == 16384

@respx.mock
def test_discover_provider_models():
    respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "llama3:latest"}]}))
    respx.post("http://localhost:11434/api/show").mock(return_value=httpx.Response(200, json={
        "model_info": {"llama.context_length": 8192}
    }))
    
    models = discover_provider_models("ollama")
    assert len(models) == 1
    assert models[0]["context_window"] == 8192

    # Without enrichment
    models_no_enrich = discover_provider_models("ollama", enrich=False)
    assert len(models_no_enrich) == 1

@respx.mock
def test_pull_model():
    url = "http://localhost:11434/api/pull"
    
    # Successful stream
    def mock_stream(_request):
        content = b'{"status": "pulling", "total": 100, "completed": 50}\n{"status": "success"}\n'
        return httpx.Response(200, content=content)
    
    respx.post(url).mock(side_effect=mock_stream)
    
    statuses = []
    def on_status(status, pct):
        statuses.append((status, pct))
        
    ok, msg = pull_model("ollama", "llama3:latest", on_status=on_status)
    assert ok is True
    assert "Downloaded" in msg
    assert statuses == [("pulling", 50), ("success", None)]

    # Unsupported provider
    ok, msg = pull_model("lmstudio", "model")
    assert ok is False

@patch("siyarix.provider_utils.pull_model")
@patch("siyarix.provider_utils.list_provider_models")
def test_ensure_model_pulled(mock_list, mock_pull):
    mock_list.return_value = [{"name": "llama3:latest"}]
    
    console = MagicMock()
    # Already installed
    assert ensure_model_pulled("ollama", "llama3", console=console) is True
    
    # Not installed, needs pull
    mock_list.return_value = []
    mock_pull.return_value = (True, "Downloaded")
    assert ensure_model_pulled("ollama", "llama3", console=console) is True
    mock_pull.assert_called_once()
    
    # Not installed, non-ollama
    assert ensure_model_pulled("lmstudio", "gpt-local", console=console) is False

@respx.mock
def test_check_provider_health():
    respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200))
    assert check_provider_health("ollama") is True

    respx.get("http://localhost:1234/v1/models").mock(side_effect=httpx.ConnectError("error"))
    assert check_provider_health("lmstudio") is False
    
    assert check_provider_health("unknown") is False




from unittest.mock import patch

import respx

from siyarix.provider_utils import (
    _list_ollama_models,
    _list_openai_compat_models,
    _enrich_ollama_model,
    _enrich_lmstudio_model,
    _enrich_vllm_model,
    enrich_all_models,
    _enrich_ollama_models_batch,
    _parse_num_ctx,
)


# ── _is_safe_url ──────────────────────────────────────────────────────────

class TestIsSafeUrl:
    def test_127_prefix(self):
        assert _is_safe_url("http://127.0.0.1") is True

    def test_private_ip(self):
        assert _is_safe_url("http://172.16.0.1") is True
        assert _is_safe_url("http://192.168.1.1") is True
        assert _is_safe_url("http://10.0.0.1") is True

    def test_exception_handling(self):
        with patch("urllib.parse.urlparse", side_effect=ValueError("bad url")):
            assert _is_safe_url("http://bad") is False

    def test_non_http_scheme(self):
        assert _is_safe_url("ftp://localhost") is False

    def test_invalid_host(self):
        assert _is_safe_url("http://") is False


# ── safe_http_get ─────────────────────────────────────────────────────────

class TestSafeHttpGet:
    @respx.mock
    def test_http_exception(self):
        respx.get("http://localhost:11434/test").mock(side_effect=httpx.TimeoutException("timeout"))
        result = safe_http_get("http://localhost:11434/test")
        assert result is None

    def test_unsafe_url_returns_none(self):
        result = safe_http_get("http://evil.com/api")
        assert result is None


# ── safe_http_post ────────────────────────────────────────────────────────

class TestSafeHttpPost:
    @respx.mock
    def test_post_exception(self):
        respx.post("http://localhost:11434/test").mock(side_effect=httpx.TimeoutException("timeout"))
        result = safe_http_post("http://localhost:11434/test", {"key": "val"})
        assert result is None

    def test_unsafe_url_returns_none(self):
        result = safe_http_post("http://evil.com", {})
        assert result is None


# ── safe_http_get_raw ─────────────────────────────────────────────────────

class TestSafeHttpGetRaw:
    @respx.mock
    def test_get_raw_exception(self):
        respx.get("http://localhost:11434/test").mock(side_effect=httpx.TimeoutException("timeout"))
        result = safe_http_get_raw("http://localhost:11434/test")
        assert result is None

    def test_unsafe_url_returns_none(self):
        result = safe_http_get_raw("http://evil.com/api")
        assert result is None


# ── resolve_provider_url ──────────────────────────────────────────────────

class TestResolveProviderUrl:
    def test_provider_with_defaults(self):
        assert resolve_provider_url("ollama") == "http://localhost:11434"

    def test_unknown_provider_no_base(self):
        assert resolve_provider_url("unknown") == ""

    def test_unknown_provider_with_base(self):
        assert resolve_provider_url("unknown", "http://custom:8080") == "http://custom:8080"


# ── is_reasoning_model ────────────────────────────────────────────────────

class TestIsReasoningModel:
    def test_reasoning_variants(self):
        assert is_reasoning_model("deepseek-r1") is True
        assert is_reasoning_model("qwq-32b") is True
        assert is_reasoning_model("thinking-llm") is True
        assert is_reasoning_model("reason-anything") is True

    def test_non_reasoning(self):
        assert is_reasoning_model("llama-3-8b") is False
        assert is_reasoning_model("gpt-4") is False


# ── build_model_definition ────────────────────────────────────────────────

class TestBuildModelDefinition:
    def test_defaults(self):
        defn = build_model_definition("test-model")
        assert defn["name"] == "test-model"
        assert defn["context_window"] == 128_000
        assert defn["max_tokens"] == 8192
        assert defn["supports_vision"] is False
        assert defn["supports_tools"] is True
        assert defn["reasoning"] is False

    def test_capabilities_vision_tools(self):
        defn = build_model_definition("test", capabilities=["vision", "tools"])
        assert defn["supports_vision"] is True
        assert defn["supports_tools"] is True
        assert defn["reasoning"] is False

    def test_reasoning_from_name_and_caps(self):
        defn = build_model_definition("test-r1", capabilities=["thinking"])
        assert defn["reasoning"] is True

    def test_explicit_values(self):
        defn = build_model_definition("m", context_window=4096, max_tokens=2048, capabilities=[])
        assert defn["context_window"] == 4096
        assert defn["max_tokens"] == 2048
        assert defn["supports_tools"] is False


# ── _list_ollama_models ───────────────────────────────────────────────────

class TestListOllamaModels:
    @respx.mock
    def test_not_dict_response(self):
        respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200, json=[]))
        assert _list_ollama_models("http://localhost:11434") == []

    @respx.mock
    def test_none_response(self):
        respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200, json=None))
        assert _list_ollama_models("http://localhost:11434") == []

    @respx.mock
    def test_empty_models_key(self):
        respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200, json={}))
        assert _list_ollama_models("http://localhost:11434") == []


# ── _list_openai_compat_models ────────────────────────────────────────────

class TestListOpenaiCompatModels:
    @respx.mock
    def test_none_or_non_dict(self):
        respx.get("http://localhost:8000/v1/models").mock(return_value=httpx.Response(200, json=None))
        assert _list_openai_compat_models("http://localhost:8000") == []

    @respx.mock
    def test_data_key_absent(self):
        respx.get("http://localhost:8000/v1/models").mock(return_value=httpx.Response(200, json={}))
        assert _list_openai_compat_models("http://localhost:8000") == []

    @respx.mock
    def test_data_is_not_list(self):
        respx.get("http://localhost:8000/v1/models").mock(return_value=httpx.Response(200, json={"data": "notlist"}))
        assert _list_openai_compat_models("http://localhost:8000") == []

    @respx.mock
    def test_fallback_models_key(self):
        respx.get("http://localhost:8000/v1/models").mock(return_value=httpx.Response(200, json={"models": [{"id": "m1"}]}))
        result = _list_openai_compat_models("http://localhost:8000")
        assert len(result) == 1


# ── list_provider_models ─────────────────────────────────────────────────

class TestListProviderModels:
    @respx.mock
    def test_lmstudio(self):
        respx.get("http://localhost:1234/v1/models").mock(
            return_value=httpx.Response(200, json={"data": [{"id": "lm-model"}]})
        )
        models = list_provider_models("lmstudio")
        assert len(models) == 1
        assert models[0]["name"] == "lm-model"

    @respx.mock
    def test_llamacpp(self):
        respx.get("http://localhost:18080/v1/models").mock(
            return_value=httpx.Response(200, json={"data": [{"id": "cpp-model"}]})
        )
        models = list_provider_models("llamacpp")
        assert len(models) == 1
        assert models[0]["name"] == "cpp-model"

    @respx.mock
    def test_vllm(self):
        respx.get("http://localhost:8000/v1/models").mock(
            return_value=httpx.Response(200, json={"data": [{"id": "vllm-model"}]})
        )
        models = list_provider_models("vllm")
        assert len(models) == 1
        assert models[0]["name"] == "vllm-model"

    @respx.mock
    def test_localai(self):
        respx.get("http://localhost:8080/v1/models").mock(
            return_value=httpx.Response(200, json={"data": [{"id": "localai-model"}]})
        )
        models = list_provider_models("localai")
        assert len(models) == 1
        assert models[0]["name"] == "localai-model"

    def test_unknown_provider(self):
        assert list_provider_models("unknown") == []


# ── _enrich_ollama_model ─────────────────────────────────────────────────

class TestEnrichOllamaModel:
    @respx.mock
    def test_resp_is_none(self):
        with patch("siyarix.provider_utils.safe_http_post", return_value=None):
            assert _enrich_ollama_model("test", "http://localhost:11434") == (None, None, None)

    @respx.mock
    def test_json_parse_exception(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.json.side_effect = ValueError("bad json")
        with patch("siyarix.provider_utils.safe_http_post", return_value=mock_resp):
            assert _enrich_ollama_model("test", "http://localhost:11434") == (None, None, None)

    @respx.mock
    def test_context_length_extraction(self):
        info = {
            "model_info": {
                "llama.context_length": 16384,
                "llama.max_tokens": 4096,
            },
            "capabilities": ["vision", "tools"],
        }
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.json.return_value = info
        with patch("siyarix.provider_utils.safe_http_post", return_value=mock_resp):
            ctx, caps, max_tok = _enrich_ollama_model("test", "http://localhost:11434")
            assert ctx == 16384
            assert caps == ["vision", "tools"]
            assert max_tok == 4096

    @respx.mock
    def test_param_ctx_overrides(self):
        info = {
            "model_info": {"llama.context_length": 4096},
            "parameters": "num_ctx 8192",
            "capabilities": ["tools"],
        }
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.json.return_value = info
        with patch("siyarix.provider_utils.safe_http_post", return_value=mock_resp):
            ctx, caps, max_tok = _enrich_ollama_model("test", "http://localhost:11434")
            assert ctx == 8192


# ── _enrich_lmstudio_model ───────────────────────────────────────────────

class TestEnrichLmstudioModel:
    def test_full_enrichment(self):
        entry = {
            "loaded_instances": [{"context_length": 4096}],
            "metadata": {
                "vision": True,
                "reasoning": True,
                "tools": True,
                "max_tokens": 2048,
            },
        }
        ctx, caps, max_tok = _enrich_lmstudio_model(entry)
        assert ctx == 4096
        assert "vision" in caps
        assert "thinking" in caps
        assert "tools" in caps
        assert max_tok == 2048

    def test_no_loaded_instances(self):
        entry = {"metadata": {"vision": True}}
        ctx, caps, max_tok = _enrich_lmstudio_model(entry)
        assert ctx is None
        assert caps == ["vision"]
        assert max_tok is None

    def test_invalid_context_length(self):
        entry = {"loaded_instances": [{"context_length": 0}]}
        ctx, caps, _ = _enrich_lmstudio_model(entry)
        assert ctx is None

    def test_missing_metadata(self):
        entry = {"loaded_instances": [{"context_length": 2048}]}
        ctx, caps, _ = _enrich_lmstudio_model(entry)
        assert ctx == 2048
        assert caps is None

    def test_invalid_max_tokens(self):
        entry = {"metadata": {"max_tokens": 0}}
        ctx, caps, max_tok = _enrich_lmstudio_model(entry)
        assert max_tok is None


# ── _enrich_vllm_model ──────────────────────────────────────────────────

class TestEnrichVllmModel:
    def test_max_model_len_found(self):
        entry = {"max_model_len": 32768}
        ctx, caps, max_tok = _enrich_vllm_model(entry)
        assert ctx == 32768
        assert caps is None
        assert max_tok is None

    def test_no_max_model_len(self):
        entry = {"other_key": 123}
        ctx, _, _ = _enrich_vllm_model(entry)
        assert ctx is None

    def test_invalid_value_type(self):
        entry = {"max_model_len": "string"}
        ctx, _, _ = _enrich_vllm_model(entry)
        assert ctx is None

    def test_zero_value(self):
        entry = {"max_model_len": 0}
        ctx, _, _ = _enrich_vllm_model(entry)
        assert ctx is None


# ── enrich_model ─────────────────────────────────────────────────────────

class TestEnrichModel:
    def test_llamacpp_enrichment(self):
        entry = {"context_length": 8192}
        defn = enrich_model("llamacpp", "test", model_entry=entry)
        assert defn["context_window"] == 8192

    def test_localai_enrichment(self):
        entry = {"context_length": 4096}
        defn = enrich_model("localai", "test", model_entry=entry)
        assert defn["context_window"] == 4096

    def test_llamacpp_no_entry(self):
        defn = enrich_model("llamacpp", "test", model_entry=None)
        assert defn["context_window"] == 128_000

    def test_ollama_no_entry(self):
        with patch("siyarix.provider_utils._enrich_ollama_model", return_value=(None, None, None)):
            defn = enrich_model("ollama", "test")
            assert defn["context_window"] == 128_000


# ── enrich_all_models ────────────────────────────────────────────────────

class TestEnrichAllModels:
    def test_non_ollama_enrichment(self):
        models = [
            {"name": "model1", "context_length": 4096},
            {"name": "model2", "context_length": 8192},
            {"name": "model3"},  # no context_length in entry, uses defaults
        ]
        enriched = enrich_all_models("llamacpp", models)
        assert len(enriched) == 3
        assert enriched[0]["context_window"] == 4096
        assert enriched[1]["context_window"] == 8192
        assert enriched[2]["context_window"] == 128_000

    def test_limit_respected(self):
        models = [{"name": f"m{i}"} for i in range(50)]
        enriched = enrich_all_models("llamacpp", models, limit=10)
        assert len(enriched) == 10

    def test_ollama_batch_delegation(self):
        models = [{"name": "llama3"}]
        with patch("siyarix.provider_utils._enrich_ollama_models_batch", return_value=[{"name": "llama3", "context_window": 8192}]):
            enriched = enrich_all_models("ollama", models)
            assert enriched[0]["context_window"] == 8192


# ── _enrich_ollama_models_batch ──────────────────────────────────────────

class TestEnrichOllamaModelsBatch:
    def test_basic_batch(self):
        models = [{"name": "llama3"}, {"name": "mistral"}]
        with patch("siyarix.provider_utils._enrich_ollama_model", return_value=(8192, ["tools"], 4096)):
            result = _enrich_ollama_models_batch(models, base_url="http://localhost:11434", concurrency=2, limit=5)
            assert len(result) == 2
            assert result[0]["context_window"] == 8192

    def test_limit_cutoff(self):
        models = [{"name": f"m{i}"} for i in range(10)]
        with patch("siyarix.provider_utils._enrich_ollama_model", return_value=(None, None, None)):
            result = _enrich_ollama_models_batch(models, limit=3, concurrency=2)
            assert len(result) == 3

    def test_exception_in_gather(self):
        models = [{"name": "bad"}, {"name": "good"}]
        def mock_enrich(name, base):
            if name == "bad":
                raise RuntimeError("fail")
            return (8192, None, None)
        with patch("siyarix.provider_utils._enrich_ollama_model", side_effect=mock_enrich):
            result = _enrich_ollama_models_batch(models)
            assert len(result) == 1

    def test_already_in_async_context_skips(self):
        models = [{"name": "llama3"}]
        with patch("asyncio.get_running_loop", return_value="fake_loop"):
            with patch("siyarix.provider_utils._enrich_ollama_model") as mock_enrich:
                result = _enrich_ollama_models_batch(models)
                # When already in async context, enrichment is skipped
                assert len(result) == 0
                mock_enrich.assert_not_called()


# ── discover_provider_models ─────────────────────────────────────────────

class TestDiscoverProviderModels:
    @respx.mock
    def test_empty_models(self):
        with patch("siyarix.provider_utils.list_provider_models", return_value=[]):
            assert discover_provider_models("ollama") == []

    @respx.mock
    def test_enrich_returns_empty(self):
        with patch("siyarix.provider_utils.list_provider_models", return_value=[{"name": "m1"}]):
            with patch("siyarix.provider_utils.enrich_all_models", return_value=[]):
                result = discover_provider_models("ollama")
                assert len(result) == 1
                assert result[0]["name"] == "m1"

    @respx.mock
    def test_no_enrich_with_enrich_false(self):
        with patch("siyarix.provider_utils.list_provider_models", return_value=[{"name": "m1"}]):
            result = discover_provider_models("ollama", enrich=False)
            assert len(result) == 1
            assert result[0]["name"] == "m1"
            assert result[0]["context_window"] == 128_000


# ── _parse_num_ctx ───────────────────────────────────────────────────────

class TestParseNumCtx:
    def test_non_string_returns_none(self):
        assert _parse_num_ctx(123) is None

    def test_empty_string_returns_none(self):
        assert _parse_num_ctx("") is None

    def test_multiple_matches_last_value(self):
        params = "num_ctx 2048\nnum_ctx 4096\nsomething else"
        assert _parse_num_ctx(params) == 4096

    def test_no_match_returns_none(self):
        assert _parse_num_ctx("param1 value1") is None

    def test_zero_value_skipped(self):
        assert _parse_num_ctx("num_ctx 0\nnum_ctx 4096") == 4096


# ── pull_model ───────────────────────────────────────────────────────────

class TestPullModel:
    @respx.mock
    def test_unsupported_provider(self):
        ok, msg = pull_model("lmstudio", "test")
        assert ok is False
        assert "not supported" in msg

    @respx.mock
    def test_unsafe_url(self):
        with patch("siyarix.provider_utils._is_safe_url", return_value=False):
            ok, msg = pull_model("ollama", "test", base_url="http://evil:11434")
            assert ok is False
            assert "unsafe" in msg.lower()

    @respx.mock
    def test_http_error_status(self):
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(500))
        ok, msg = pull_model("ollama", "test")
        assert ok is False
        assert "HTTP 500" in msg

    @respx.mock
    def test_json_decode_error_and_error_key(self):
        content = b"not json\n{\"error\": \"model not found\"}\n"
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        ok, msg = pull_model("ollama", "ghost")
        assert ok is False
        assert "Download failed" in msg

    @respx.mock
    def test_empty_line_and_empty_status_skipped(self):
        content = b"\n\n{\"status\": \"\", \"total\": 0, \"completed\": 0}\n{\"status\": \"success\"}\n"
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        ok, msg = pull_model("ollama", "test")
        assert ok is True
        assert "Downloaded" in msg

    @respx.mock
    def test_on_status_with_percentage(self):
        content = b'{"status": "pulling", "total": 100, "completed": 50}\n{"status": "done"}\n'
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        statuses = []
        ok, msg = pull_model("ollama", "test", on_status=lambda s, p: statuses.append((s, p)))
        assert ok is True
        assert ("pulling", 50) in statuses

    @respx.mock
    def test_timeout_exception(self):
        respx.post("http://localhost:11434/api/pull").mock(side_effect=httpx.TimeoutException("timeout"))
        ok, msg = pull_model("ollama", "test")
        assert ok is False
        assert "Timed out" in msg

    @respx.mock
    def test_general_exception(self):
        respx.post("http://localhost:11434/api/pull").mock(side_effect=ConnectionError("conn failed"))
        ok, msg = pull_model("ollama", "test")
        assert ok is False
        assert "Failed to pull" in msg

    @respx.mock
    def test_trailing_buffer_with_error(self):
        content = b'{"status": "done"}\n{"error": "corrupted download"}'
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        ok, msg = pull_model("ollama", "test")
        assert ok is False
        assert "Download failed" in msg

    @respx.mock
    def test_trailing_buffer_json_decode_error(self):
        content = b'{"status": "done"}\nnotjson'
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        ok, msg = pull_model("ollama", "test")
        assert ok is True

    @respx.mock
    def test_on_status_without_pct(self):
        content = b'{"status": "processing"}\n{"status": "done"}\n'
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        statuses = []
        ok, msg = pull_model("ollama", "test", on_status=lambda s, p: statuses.append((s, p)))
        assert ok is True
        assert ("processing", None) in statuses

    @respx.mock
    def test_no_on_status_callback(self):
        content = b'{"status": "done"}\n'
        respx.post("http://localhost:11434/api/pull").mock(return_value=httpx.Response(200, content=content))
        ok, msg = pull_model("ollama", "test")
        assert ok is True


# ── ensure_model_pulled ──────────────────────────────────────────────────

class TestEnsureModelPulled:
    @patch("siyarix.provider_utils.list_provider_models")
    def test_already_installed(self, mock_list):
        mock_list.return_value = [{"name": "llama3:latest"}]
        assert ensure_model_pulled("ollama", "llama3") is True
        assert ensure_model_pulled("ollama", "llama3:latest") is True

    @patch("siyarix.provider_utils.list_provider_models")
    def test_non_ollama_not_found_with_console(self, mock_list):
        mock_list.return_value = []
        console = MagicMock()
        result = ensure_model_pulled("lmstudio", "missing", console=console)
        assert result is False
        console.print.assert_called_once()

    @patch("siyarix.provider_utils.list_provider_models")
    def test_pull_success_with_console(self, mock_list):
        mock_list.return_value = []
        with patch("siyarix.provider_utils.pull_model", return_value=(True, "Downloaded OK")):
            console = MagicMock()
            result = ensure_model_pulled("ollama", "llama3", console=console)
            assert result is True
            console.print.assert_any_call(
                "[dim]Model llama3 not found locally — pulling...[/dim]"
            )

    @patch("siyarix.provider_utils.list_provider_models")
    def test_pull_failure_with_console(self, mock_list):
        mock_list.return_value = []
        with patch("siyarix.provider_utils.pull_model", return_value=(False, "Failed")):
            console = MagicMock()
            result = ensure_model_pulled("ollama", "llama3", console=console)
            assert result is False

    @patch("siyarix.provider_utils.list_provider_models")
    def test_ollama_not_found_no_console(self, mock_list):
        mock_list.return_value = []
        with patch("siyarix.provider_utils.pull_model", return_value=(True, "OK")):
            assert ensure_model_pulled("ollama", "llama3") is True

    @patch("siyarix.provider_utils.list_provider_models")
    def test_non_ollama_no_console(self, mock_list):
        mock_list.return_value = []
        result = ensure_model_pulled("lmstudio", "missing")
        assert result is False


# ── check_provider_health ───────────────────────────────────────────────

class TestCheckProviderHealth:
    @respx.mock
    def test_ollama_healthy(self):
        respx.get("http://localhost:11434/api/tags").mock(return_value=httpx.Response(200))
        assert check_provider_health("ollama") is True

    @respx.mock
    def test_lmstudio_unhealthy(self):
        respx.get("http://localhost:1234/v1/models").mock(side_effect=httpx.ConnectError("fail"))
        assert check_provider_health("lmstudio") is False

    def test_unknown_provider(self):
        assert check_provider_health("unknown") is False

    @respx.mock
    def test_llamacpp(self):
        respx.get("http://localhost:18080/health").mock(return_value=httpx.Response(200))
        assert check_provider_health("llamacpp") is True

    @respx.mock
    def test_localai(self):
        respx.get("http://localhost:8080/readyz").mock(return_value=httpx.Response(200))
        assert check_provider_health("localai") is True


# ── Edge cases: safe_http_post returns response object ───────────────────

@respx.mock
def test_safe_http_post_returns_raw_response():
    respx.post("http://localhost:11434/api/show").mock(
        return_value=httpx.Response(200, json={"modelfile": "test"})
    )
    resp = safe_http_post("http://localhost:11434/api/show", {"name": "test"})
    assert resp is not None
    assert resp.json() == {"modelfile": "test"}