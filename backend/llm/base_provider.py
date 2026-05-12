from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal, Sequence


Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: Role
    content: str
    # For tool result messages — associates result with the request
    tool_call_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool invocation decision returned by the LLM."""

    id: str  # provider-assigned call id
    name: str  # tool name the LLM chose
    arguments: dict[str, Any]  # parsed arguments


@dataclass(frozen=True, slots=True)
class TokenUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """
    Represents a single LLM turn.
    Exactly one of `content` or `tool_calls` will be populated.
    When the LLM decides to call a tool: tool_calls is non-empty, content is "".
    When the LLM produces a text reply: content is non-empty, tool_calls is empty.
    """

    content: str
    provider: str
    model: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: TokenUsage | None = None

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


@dataclass(frozen=True, slots=True)
class EmbeddingResponse:
    """Result of a single embed() call."""

    vector: list[float]
    provider: str
    model: str
    token_count: int


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """
    Provider-agnostic tool definition passed to generate().
    Each provider adapter converts this into its native format.
    """

    name: str
    description: str
    parameters_schema: dict[str, Any]  # JSON Schema


class LLMProviderError(Exception):
    """Base error for all provider failures.

    Catch this in agent code — never catch provider-specific exceptions.
    """

    def __init__(
        self,
        message: str,
        provider: str,
        retryable: bool = False,
        original: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.retryable = retryable
        self.original = original


class BaseLLMProvider(ABC):
    """Provider-agnostic LLM interface.

    Concrete adapters: OpenAIProvider, AnthropicProvider,
    GeminiProvider, OllamaProvider.

    All agent code must depend only on this interface.
    No agent may import from a concrete provider module.
    """

    @property
    @abstractmethod
    def provider_slug(self) -> str:
        """Short identifier: 'openai' | 'anthropic' | 'gemini' | 'ollama'"""
        raise NotImplementedError

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The specific model being used e.g. 'gpt-4o', 'claude-opus-4-6'"""
        raise NotImplementedError

    @property
    @abstractmethod
    def embedding_model_name(self) -> str:
        """The embedding model for this provider."""
        raise NotImplementedError

    @abstractmethod
    async def generate(
        self,
        *,
        messages: Sequence[LLMMessage],
        tools: Sequence[ToolSpec] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response, optionally with tool calling enabled.

        When tools are provided and the LLM decides to call one,
        LLMResponse.has_tool_calls is True and tool_calls is populated.
        The caller is responsible for executing the tool and continuing
        the conversation with a tool result message.

        Raises:
            LLMProviderError: on any provider failure.
                Check .retryable to decide whether to retry.
        """
        raise NotImplementedError

    @abstractmethod
    async def embed(
        self,
        *,
        text: str,
    ) -> EmbeddingResponse:
        """Produce an embedding vector for the given text.

        Used by Vera and Finn's RAG pipeline.
        Each provider uses its own embedding model.

        Raises:
            LLMProviderError: on any provider failure.
        """
        raise NotImplementedError


