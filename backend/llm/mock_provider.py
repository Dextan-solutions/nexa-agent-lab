from __future__ import annotations

import re
from typing import Sequence

from llm.base_provider import (
    BaseLLMProvider,
    EmbeddingResponse,
    LLMMessage,
    LLMResponse,
    TokenUsage,
    ToolCall,
    ToolSpec,
)


class MockProvider(BaseLLMProvider):
    """Deterministic local provider for development/testing.

    This is not meant for production, but it unblocks local demos when no real LLM
    is available (e.g., while Ollama image/models are downloading).
    """

    def __init__(self, *, model: str = "mock") -> None:
        self._model = model

    @property
    def provider_slug(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embedding_model_name(self) -> str:
        return "mock-embed"

    async def generate(
        self,
        *,
        messages: Sequence[LLMMessage],
        tools: Sequence[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        _ = (temperature, max_tokens)

        # Extract last user message.
        user = ""
        for m in reversed(messages):
            if m.role == "user":
                user = m.content
                break

        # Naive tool calling: if tools are available and user asks to look up an account,
        # choose the first matching tool.
        if tools:
            m_acc = re.search(r"\bACC-\d{4}\b", user)
            if m_acc:
                account_id = m_acc.group(0)
                for t in tools:
                    if t.name == "account_lookup":
                        return LLMResponse(
                            content="",
                            provider=self.provider_slug,
                            model=self._model,
                            tool_calls=[
                                ToolCall(id="mock_call_1", name="account_lookup", arguments={"account_id": account_id})
                            ],
                            usage=TokenUsage(prompt_tokens=8, completion_tokens=2, total_tokens=10),
                        )

        # Plain text reply
        text = "OK" if "say ok" in user.lower() else "OK"
        return LLMResponse(
            content=text,
            provider=self.provider_slug,
            model=self._model,
            tool_calls=[],
            usage=TokenUsage(prompt_tokens=8, completion_tokens=2, total_tokens=10),
        )

    async def embed(self, *, text: str) -> EmbeddingResponse:
        # Deterministic tiny vector for local dev.
        seed = sum(ord(c) for c in text) % 997
        vec = [((seed + i * 31) % 1000) / 1000.0 for i in range(16)]
        return EmbeddingResponse(
            vector=vec,
            provider=self.provider_slug,
            model=self.embedding_model_name,
            token_count=max(1, len(text.split())),
            )

