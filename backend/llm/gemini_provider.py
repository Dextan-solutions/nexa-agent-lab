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


class GeminiProvider(BaseLLMProvider):
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout_s: float) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s

    @property
    def provider_slug(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embedding_model_name(self) -> str:
        return "text-embedding-004"

    def _classify_http_status(self, status_code: int) -> bool:
        if status_code in {408, 409, 429, 500, 502, 503, 504}:
            return True
        return False

    def _tools_payload(self, tools: Sequence[ToolSpec] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        decls: list[dict[str, Any]] = []
        for t in tools:
            decls.append(
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters_schema,
                }
            )
        return [{"function_declarations": decls}]

    async def generate(
        self,
        *,
        messages: Sequence[LLMMessage],
        tools: Sequence[ToolSpec] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        # Gemini generateContent expects "contents": [{role, parts:[{text}]}]
        # Map system + user/assistant into a single stream; treat system as first user-like part.
        contents = []
        for m in messages:
            if m.role == "tool":
                continue
            role = "model" if m.role == "assistant" else "user"
            if m.role == "system":
                role = "user"
            contents.append({"role": role, "parts": [{"text": m.content}]})

        url = f"{self._base_url}/v1beta/models/{self._model}:generateContent"
        params = {"key": self._api_key}
        payload = {
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        tools_payload = self._tools_payload(tools)
        if tools_payload is not None:
            payload["tools"] = tools_payload
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                resp = await client.post(url, params=params, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise LLMProviderError(
                    "Gemini rate limit exceeded. "
                    "Free tier allows 15 requests/minute. "
                    "Wait 60 seconds and retry, or use a paid API key. "
                    "Alternatively switch to Ollama: LLM_PROVIDER=ollama",
                    provider="gemini",
                    retryable=True,
                    original=e,
                ) from e
            retryable = self._classify_http_status(e.response.status_code)
            raise LLMProviderError(
                f"Gemini request failed: HTTP {e.response.status_code}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Gemini request failed: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            ) from e

        try:
            usage_raw = data.get("usageMetadata") or {}
            usage = TokenUsage(
                prompt_tokens=int(usage_raw.get("promptTokenCount", 0) or 0),
                completion_tokens=int(usage_raw.get("candidatesTokenCount", 0) or 0),
                total_tokens=int(usage_raw.get("totalTokenCount", 0) or 0),
            )

            parts = data["candidates"][0]["content"]["parts"]
            tool_calls: list[ToolCall] = []
            text_parts: list[str] = []
            for p in parts:
                if "functionCall" in p:
                    fc = p["functionCall"] or {}
                    tool_calls.append(
                        ToolCall(
                            id=str(fc.get("name") or ""),
                            name=str(fc.get("name") or ""),
                            arguments=dict(fc.get("args") or {}),
                        )
                    )
                elif "text" in p:
                    text_parts.append(str(p.get("text") or ""))

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
                f"Gemini response parse failed: {e}",
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
        url = f"{self._base_url}/v1beta/models/{self.embedding_model_name}:embedContent"
        params = {"key": self._api_key}
        payload = {"content": {"parts": [{"text": text}]}}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                resp = await client.post(url, params=params, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise LLMProviderError(
                    "Gemini rate limit exceeded. "
                    "Free tier allows 15 requests/minute. "
                    "Wait 60 seconds and retry, or use a paid API key. "
                    "Alternatively switch to Ollama: LLM_PROVIDER=ollama",
                    provider="gemini",
                    retryable=True,
                    original=e,
                ) from e
            retryable = self._classify_http_status(e.response.status_code)
            raise LLMProviderError(
                f"Gemini embed failed: HTTP {e.response.status_code}",
                provider=self.provider_slug,
                retryable=retryable,
                original=e,
            ) from e
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Gemini embed failed: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            ) from e

        try:
            vec = data["embedding"]["values"]
            usage_raw = data.get("usageMetadata") or {}
            tok = int(usage_raw.get("totalTokenCount", 0) or 0)
            return EmbeddingResponse(
                vector=list(vec),
                provider=self.provider_slug,
                model=self.embedding_model_name,
                token_count=tok,
            )
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Gemini embed parse failed: {e}",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

