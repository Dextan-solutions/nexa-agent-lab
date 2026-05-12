from __future__ import annotations

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


class AnthropicProvider(BaseLLMProvider):
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout_s: float) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s

    @property
    def provider_slug(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embedding_model_name(self) -> str:
        # As requested: embeddings via Voyage (voyage-3) for Anthropic.
        return "voyage-3"

    def _tools_payload(self, tools: Sequence[ToolSpec] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        out: list[dict[str, Any]] = []
        for t in tools:
            out.append({"name": t.name, "description": t.description, "input_schema": t.parameters_schema})
        return out

    def _classify_http_status(self, status_code: int) -> bool:
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
        # Anthropic Messages API: system is separate; messages are user/assistant.
        system_parts: list[str] = [m.content for m in messages if m.role == "system"]
        non_system = [m for m in messages if m.role != "system" and m.role != "tool"]

        url = f"{self._base_url}/v1/messages"
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": "\n\n".join(system_parts) if system_parts else None,
            "messages": [{"role": m.role, "content": m.content} for m in non_system],
        }
        tools_payload = self._tools_payload(tools)
        if tools_payload is not None:
            payload["tools"] = tools_payload
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            retryable = self._classify_http_status(e.response.status_code)
            raise LLMProviderError(
                f"Anthropic request failed: HTTP {e.response.status_code}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Anthropic request failed: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            ) from e

        try:
            usage_raw = data.get("usage") or {}
            usage = TokenUsage(
                prompt_tokens=int(usage_raw.get("input_tokens", 0) or 0),
                completion_tokens=int(usage_raw.get("output_tokens", 0) or 0),
                total_tokens=int((usage_raw.get("input_tokens", 0) or 0) + (usage_raw.get("output_tokens", 0) or 0)),
            )

            blocks = data["content"]
            tool_calls: list[ToolCall] = []
            text_parts: list[str] = []
            for b in blocks:
                if b.get("type") == "tool_use":
                    tool_calls.append(
                        ToolCall(
                            id=str(b.get("id") or ""),
                            name=str(b.get("name") or ""),
                            arguments=dict(b.get("input") or {}),
                        )
                    )
                elif b.get("type") == "text":
                    text_parts.append(str(b.get("text") or ""))

            if tool_calls:
                return LLMResponse(
                    content="",
                    provider=self.provider_slug,
                    model=self._model,
                    tool_calls=tool_calls,
                    usage=usage,
                )

            text = "".join(text_parts)
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Anthropic response parse failed: {e}",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

        return LLMResponse(
            content=text,
            provider=self.provider_slug,
            model=self._model,
            tool_calls=[],
            usage=usage,
        )

    async def embed(self, *, text: str) -> EmbeddingResponse:
        # As requested: use voyageai client for Anthropic embeddings (voyage-3).
        try:
            import voyageai  # type: ignore
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                "Anthropic embed requires 'voyageai' package installed",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

        try:
            client = voyageai.Client(api_key=self._api_key)
            res = client.embed([text], model=self.embedding_model_name)
            vec = res.embeddings[0]
            tok = int(getattr(res, "total_tokens", 0) or 0)
            return EmbeddingResponse(
                vector=list(vec),
                provider=self.provider_slug,
                model=self.embedding_model_name,
                token_count=tok,
            )
        except Exception as e:  # noqa: BLE001
            # Voyage errors don't have stable types here; treat as non-retryable unless it's rate-limiting-ish.
            msg = str(e).lower()
            retryable = "rate" in msg or "429" in msg or "timeout" in msg
            raise LLMProviderError(
                f"Anthropic(Voyage) embed failed: {e}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e

