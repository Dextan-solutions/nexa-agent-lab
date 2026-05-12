from __future__ import annotations

from config.settings import settings
from llm.anthropic_provider import AnthropicProvider
from llm.base_provider import BaseLLMProvider
from llm.errors import LLMProviderConfigError
from llm.gemini_provider import GeminiProvider
from llm.mock_provider import MockProvider
from llm.ollama_provider import OllamaProvider
from llm.openai_provider import OpenAIProvider


def get_llm_provider() -> BaseLLMProvider:
    provider = (settings.llm_provider or "").strip().lower()
    if provider == "openai":
        if not settings.openai_api_key:
            raise LLMProviderConfigError("OPENAI_API_KEY is required for LLM_PROVIDER=openai")
        return OpenAIProvider(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            model=settings.openai_model,
            timeout_s=settings.llm_timeout_s,
        )
    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise LLMProviderConfigError(
                "ANTHROPIC_API_KEY is required for LLM_PROVIDER=anthropic"
            )
        return AnthropicProvider(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
            model=settings.anthropic_model,
            timeout_s=settings.llm_timeout_s,
        )
    if provider == "gemini":
        if not settings.gemini_api_key:
            raise LLMProviderConfigError("GEMINI_API_KEY is required for LLM_PROVIDER=gemini")
        return GeminiProvider(
            api_key=settings.gemini_api_key,
            base_url=settings.gemini_base_url,
            model=settings.gemini_model,
            timeout_s=settings.llm_timeout_s,
        )
    if provider == "ollama":
        return OllamaProvider(
            base_url=(settings.ollama_base_url or None),
            model=settings.ollama_model,
            timeout_s=settings.llm_timeout_s,
        )
    if provider == "mock":
        return MockProvider(model="mock")

    raise LLMProviderConfigError(
        f"Unknown LLM_PROVIDER={settings.llm_provider!r}. "
        "Expected one of: openai|anthropic|gemini|ollama|mock"
    )

