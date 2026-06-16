import pytest
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
