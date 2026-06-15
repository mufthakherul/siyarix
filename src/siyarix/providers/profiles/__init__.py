from __future__ import annotations

from ..manager import ProviderManager
from .openai import register_profile as register_openai
from .anthropic import register_profile as register_anthropic
from .gemini import register_profile as register_gemini
from .groq import register_profile as register_groq
from .together import register_profile as register_together
from .openrouter import register_profile as register_openrouter
from .deepseek import register_profile as register_deepseek
from .xai import register_profile as register_xai
from .mistral import register_profile as register_mistral
from .perplexity import register_profile as register_perplexity
from .cerebras import register_profile as register_cerebras
from .fireworks import register_profile as register_fireworks
from .zai import register_profile as register_zai
from .minimax import register_profile as register_minimax
from .moonshot import register_profile as register_moonshot
from .nvidia import register_profile as register_nvidia
from .opencode_go import register_profile as register_opencode_go
from .huggingface import register_profile as register_huggingface
from .azure import register_profile as register_azure
from .ollama import register_profile as register_ollama
from .lmstudio import register_profile as register_lmstudio
from .llamacpp import register_profile as register_llamacpp
from .vllm import register_profile as register_vllm
from .localai import register_profile as register_localai
from .registry import register_profile as register_registry


def register_all_profiles(manager: ProviderManager) -> None:
    register_openai(manager)
    register_anthropic(manager)
    register_gemini(manager)
    register_groq(manager)
    register_together(manager)
    register_openrouter(manager)
    register_deepseek(manager)
    register_xai(manager)
    register_mistral(manager)
    register_perplexity(manager)
    register_cerebras(manager)
    register_fireworks(manager)
    register_zai(manager)
    register_minimax(manager)
    register_moonshot(manager)
    register_nvidia(manager)
    register_opencode_go(manager)
    register_huggingface(manager)
    register_azure(manager)
    register_ollama(manager)
    register_lmstudio(manager)
    register_llamacpp(manager)
    register_vllm(manager)
    register_localai(manager)
    register_registry(manager)
