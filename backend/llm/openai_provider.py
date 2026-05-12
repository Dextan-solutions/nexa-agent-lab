from __future__ import annotations

import json
from typing import Any, Sequence

import httpx

from llm.base_provider import (
    BaseLLMProvider,
    EmbeddingResponse,
    LLMMessage,
    LLMProviderError,
    LLMResponse,
    TokenUsage,
    ToolCall,
    ToolSpec,
)


class OpenAIProvider(BaseLLMProvider):
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout_s: float) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s

    @property
    def provider_slug(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embedding_model_name(self) -> str:
        return "text-embedding-3-small"

    def _tools_payload(self, tools: Sequence[ToolSpec] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        out: list[dict[str, Any]] = []
        for t in tools:
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters_schema,
                    },
                }
            )
        return out

    def _classify_http_status(self, status_code: int) -> bool:
        # retryable?
        if status_code in {408, 409, 429, 500, 502, 503, 504}:
            return True
        return False

    async def generate(
        self,
        *,
        messages: Sequence[LLMMessage],
        tools: Sequence[ToolSpec] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        url = f"{self._base_url}/chat/completions"
        payload = {
            "model": self._model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        tools_payload = self._tools_payload(tools)
        if tools_payload is not None:
            payload["tools"] = tools_payload
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            retryable = self._classify_http_status(e.response.status_code)
            raise LLMProviderError(
                f"OpenAI request failed: HTTP {e.response.status_code}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"OpenAI request failed: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            ) from e

        try:
            choice0 = data["choices"][0]
            msg = choice0["message"]
            usage_raw = data.get("usage") or {}
            usage = TokenUsage(
                prompt_tokens=int(usage_raw.get("prompt_tokens", 0) or 0),
                completion_tokens=int(usage_raw.get("completion_tokens", 0) or 0),
                total_tokens=int(usage_raw.get("total_tokens", 0) or 0),
            )

            tool_calls_raw = msg.get("tool_calls") or []
            if tool_calls_raw:
                tool_calls: list[ToolCall] = []
                for tc in tool_calls_raw:
                    fn = tc.get("function") or {}
                    args_s = fn.get("arguments") or "{}"
                    tool_calls.append(
                        ToolCall(
                            id=str(tc.get("id") or ""),
                            name=str(fn.get("name") or ""),
                            arguments=json.loads(args_s) if isinstance(args_s, str) else dict(args_s),
                        )
                    )
                return LLMResponse(
                    content="",
                    provider=self.provider_slug,
                    model=self._model,
                    tool_calls=tool_calls,
                    usage=usage,
                )

            content = msg.get("content") or ""
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"OpenAI response parse failed: {e}",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

        return LLMResponse(
            content=content,
            provider=self.provider_slug,
            model=self._model,
            tool_calls=[],
            usage=usage,
        )

    async def embed(self, *, text: str) -> EmbeddingResponse:
        url = f"{self._base_url}/embeddings"
        payload = {"model": self.embedding_model_name, "input": text}
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            retryable = self._classify_http_status(e.response.status_code)
            raise LLMProviderError(
                f"OpenAI embed failed: HTTP {e.response.status_code}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"OpenAI embed failed: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            ) from e

        try:
            vec = data["data"][0]["embedding"]
            usage_raw = data.get("usage") or {}
            tok = int(usage_raw.get("total_tokens", 0) or 0)
            return EmbeddingResponse(
                vector=list(vec),
                provider=self.provider_slug,
                model=self.embedding_model_name,
                token_count=tok,
            )
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"OpenAI embed parse failed: {e}",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

