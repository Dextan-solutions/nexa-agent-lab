from __future__ import annotations

import asyncio
import json
import logging
import os
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

# Local Ollama inference can be slow; keep all httpx calls in this module aligned.
_OLLAMA_HTTP_TIMEOUT_S = 900.0

_DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"
_DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text"

CANDIDATE_URLS = [
    os.getenv("OLLAMA_BASE_URL"),  # explicit override
    "http://host.docker.internal:11434",  # host machine
    "http://ollama:11434",  # docker service
]

_RESOLVED_OLLAMA_URL: str | None = None

_log = logging.getLogger(__name__)


async def resolve_ollama_url() -> str:
    """Resolve an Ollama base URL with preference order:

    1) OLLAMA_BASE_URL env var (explicit override)
    2) host.docker.internal:11434 (host machine)
    3) ollama:11434 (docker service)
    """

    global _RESOLVED_OLLAMA_URL  # noqa: PLW0603
    if _RESOLVED_OLLAMA_URL:
        return _RESOLVED_OLLAMA_URL

    for url in CANDIDATE_URLS:
        if not url:
            continue
        base = str(url).rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=_OLLAMA_HTTP_TIMEOUT_S) as client:
                resp = await client.get(f"{base}/api/tags")
                if resp.status_code == 200:
                    _log.info("Ollama: connected to %s", base)
                    _RESOLVED_OLLAMA_URL = base
                    return base
        except Exception:
            continue

    raise RuntimeError(
        "Ollama not found. Options:\n"
        "  1. Install Ollama on your machine: https://ollama.ai\n"
        f"     Then run: ollama pull {_DEFAULT_OLLAMA_MODEL} && ollama pull {_DEFAULT_OLLAMA_EMBED_MODEL}\n"
        "  2. Or use Docker Ollama: docker compose --profile ollama up\n"
        "  3. Or use a different provider: set LLM_PROVIDER=openai|anthropic|gemini"
    )


def _ollama_tags_include_model(*, available_names: list[str], requested: str) -> bool:
    """Match OLLAMA_MODEL / OLLAMA_EMBEDDING_MODEL against /api/tags names (handles :tags, @digest, library/ prefix, qwen2.5 variants)."""
    req = (requested or "").strip()
    if not req:
        return False
    for raw in available_names:
        base = (raw or "").strip().split("@", 1)[0].strip()
        if not base:
            continue
        candidates = [base]
        if "/" in base:
            candidates.append(base.rsplit("/", 1)[-1])
        for cand in candidates:
            if cand == req or cand.startswith(req + ":") or cand.startswith(req + "-"):
                return True
    return False


async def validate_ollama_models(base_url: str) -> None:
    required = {
        "generation": os.getenv("OLLAMA_MODEL", _DEFAULT_OLLAMA_MODEL),
        "embedding": os.getenv("OLLAMA_EMBEDDING_MODEL", _DEFAULT_OLLAMA_EMBED_MODEL),
    }

    async with httpx.AsyncClient(timeout=_OLLAMA_HTTP_TIMEOUT_S) as client:
        resp = await client.get(f"{base_url.rstrip('/')}/api/tags")
        resp.raise_for_status()
        available = [m["name"] for m in resp.json().get("models", [])]

    missing: list[tuple[str, str]] = []
    for purpose, model in required.items():
        model_found = _ollama_tags_include_model(available_names=available, requested=model)
        if model_found:
            _log.info("Ollama model present (%s): %s", purpose, model)
        else:
            missing.append((purpose, model))
            _log.error("Ollama model missing (%s): %s", purpose, model)

    if missing:
        missing_names = [m[1] for m in missing]
        raise RuntimeError(
            f"Missing Ollama models: {missing_names}\n"
            "Run these commands on your HOST machine:\n"
            + "\n".join(f"  ollama pull {m}" for m in missing_names)
        )


class OllamaProvider(BaseLLMProvider):
    def __init__(self, *, base_url: str | None, model: str, timeout_s: float) -> None:
        # base_url may be blank/None to allow auto-detection.
        self._base_url = (base_url or "").rstrip("/")
        self._model = (model or os.getenv("OLLAMA_MODEL", _DEFAULT_OLLAMA_MODEL)).strip() or _DEFAULT_OLLAMA_MODEL
        # Ollama local calls need a long ceiling; ignore factory default if lower.
        self._timeout_s = max(_OLLAMA_HTTP_TIMEOUT_S, float(timeout_s))
        self._validated = False

    @property
    def provider_slug(self) -> str:
        return "ollama"

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embedding_model_name(self) -> str:
        return (os.getenv("OLLAMA_EMBEDDING_MODEL", _DEFAULT_OLLAMA_EMBED_MODEL) or _DEFAULT_OLLAMA_EMBED_MODEL).strip()

    async def _ensure_ready(self) -> None:
        if not self._base_url:
            self._base_url = (await resolve_ollama_url()).rstrip("/")
        if not self._validated:
            await validate_ollama_models(self._base_url)
            self._validated = True

    def _classify_http_status(self, status_code: int) -> bool:
        if status_code in {408, 409, 429, 500, 502, 503, 504}:
            return True
        return False

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

    async def _post_json_retryable(self, *, url: str, body: dict[str, Any], err_label: str) -> dict[str, Any]:
        """POST JSON to Ollama; one retry after 5s when LLMProviderError.retryable is True."""

        def _map_exc(e: Exception) -> LLMProviderError:
            if isinstance(e, httpx.HTTPStatusError):
                retryable = self._classify_http_status(e.response.status_code)
                return LLMProviderError(
                    f"{err_label}: HTTP {e.response.status_code}",
                    provider=self.provider_slug,
                    retryable=retryable,
                    original=e,
                )
            return LLMProviderError(
                f"{err_label}: {e}",
                provider=self.provider_slug,
                retryable=True,
                original=e,
            )

        for attempt in range(2):
            last: LLMProviderError | None = None
            try:
                async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                    resp = await client.post(url, json=body)
                    resp.raise_for_status()
                    return resp.json()
            except LLMProviderError:
                raise
            except httpx.HTTPStatusError as e:
                last = _map_exc(e)
            except Exception as e:  # noqa: BLE001
                last = _map_exc(e)
            assert last is not None
            if last.retryable and attempt == 0:
                await asyncio.sleep(5.0)
                continue
            raise last

    async def generate(
        self,
        *,
        messages: Sequence[LLMMessage],
        tools: Sequence[ToolSpec] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        await self._ensure_ready()
        # Prefer /api/chat for role-based history.
        url = f"{self._base_url}/api/chat"
        payload = {
            "model": self._model,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [{"role": m.role, "content": m.content} for m in messages if m.role != "tool"],
        }
        tools_payload = self._tools_payload(tools)
        if tools_payload is not None:
            payload["tools"] = tools_payload
        data = await self._post_json_retryable(url=url, body=payload, err_label="Ollama request failed")

        try:
            usage = TokenUsage(
                prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
                completion_tokens=int(data.get("eval_count", 0) or 0),
                total_tokens=int((data.get("prompt_eval_count", 0) or 0) + (data.get("eval_count", 0) or 0)),
            )

            msg = data["message"]
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
                f"Ollama response parse failed: {e}",
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
        await self._ensure_ready()
        url = f"{self._base_url}/api/embeddings"
        payload = {"model": self.embedding_model_name, "prompt": text}
        data = await self._post_json_retryable(url=url, body=payload, err_label="Ollama embed failed")

        try:
            vec = data.get("embedding") or data.get("vector")
            if vec is None:
                raise KeyError("embedding missing")
            token_count = int(data.get("prompt_eval_count", 0) or 0)
            return EmbeddingResponse(
                vector=list(vec),
                provider=self.provider_slug,
                model=self.embedding_model_name,
                token_count=token_count,
            )
        except Exception as e:  # noqa: BLE001
            raise LLMProviderError(
                f"Ollama embed parse failed: {e}",
                provider=self.provider_slug,
                retryable=False,
                original=e,
            ) from e

