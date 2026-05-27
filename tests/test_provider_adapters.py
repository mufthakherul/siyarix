"""Tests for siyarix.provider_adapters — backward-compatible re-exports."""

from __future__ import annotations

from siyarix.provider_adapters import (
    AnthropicAdapter,
    CloudAdapter,
    CustomAdapter,
    GeminiAdapter,
    GroqAdapter,
    LMStudioAdapter,
    OllamaAdapter,
    OpenAIAdapter,
    TogetherAdapter,
    __all__ as adapter_all,
)
from siyarix.providers import (
    AnthropicAdapter as ProvidersAnthropicAdapter,
    CloudAdapter as ProvidersCloudAdapter,
    CustomAdapter as ProvidersCustomAdapter,
    GeminiAdapter as ProvidersGeminiAdapter,
    GroqAdapter as ProvidersGroqAdapter,
    LMStudioAdapter as ProvidersLMStudioAdapter,
    OllamaAdapter as ProvidersOllamaAdapter,
    OpenAIAdapter as ProvidersOpenAIAdapter,
    TogetherAdapter as ProvidersTogetherAdapter,
)


def test_all_exports_match_providers() -> None:
    assert OpenAIAdapter is ProvidersOpenAIAdapter
    assert GeminiAdapter is ProvidersGeminiAdapter
    assert AnthropicAdapter is ProvidersAnthropicAdapter
    assert CloudAdapter is ProvidersCloudAdapter
    assert GroqAdapter is ProvidersGroqAdapter
    assert TogetherAdapter is ProvidersTogetherAdapter
    assert LMStudioAdapter is ProvidersLMStudioAdapter
    assert CustomAdapter is ProvidersCustomAdapter
    assert OllamaAdapter is ProvidersOllamaAdapter


def test_all_matches_public_api() -> None:
    expected = {
        "OpenAIAdapter",
        "GeminiAdapter",
        "OllamaAdapter",
        "CloudAdapter",
        "GroqAdapter",
        "TogetherAdapter",
        "LMStudioAdapter",
        "CustomAdapter",
        "AnthropicAdapter",
    }
    assert set(adapter_all) == expected


def test_all_exports_are_classes() -> None:
    for cls in adapter_all:
        assert isinstance(cls, str)


def test_adapter_can_be_instantiated() -> None:
    oai = OpenAIAdapter()
    assert oai is not None
