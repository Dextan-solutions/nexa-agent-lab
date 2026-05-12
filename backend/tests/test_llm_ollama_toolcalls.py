from __future__ import annotations

import httpx
import pytest

from llm.base_provider import LLMMessage, ToolSpec
from llm.ollama_provider import OllamaProvider


class _Resp:
    def __init__(self, data: dict, status_code: int = 200) -> None:
        self._data = data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            req = httpx.Request("POST", "http://x")
            resp = httpx.Response(self.status_code, request=req)
            raise httpx.HTTPStatusError("bad", request=req, response=resp)

    def json(self) -> dict:
        return self._data


class _Client:
    def __init__(self, resp: _Resp):
        self._resp = resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        return self._resp


@pytest.mark.asyncio
async def test_ollama_generate_tool_call(monkeypatch):
    tool = ToolSpec(
        name="account_lookup",
        description="Lookup account",
        parameters_schema={"type": "object", "properties": {"account_id": {"type": "string"}}, "required": ["account_id"]},
    )
    fake = _Resp(
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "id": "tc_1",
                        "type": "function",
                        "function": {"name": "account_lookup", "arguments": '{"account_id":"acc_55"}'},
                    }
                ],
            },
            "prompt_eval_count": 1,
            "eval_count": 1,
        }
    )
    monkeypatch.setattr("llm.ollama_provider.httpx.AsyncClient", lambda timeout=None: _Client(fake))

    p = OllamaProvider(base_url="http://x", model="llama-x", timeout_s=5)
    out = await p.generate(messages=[LLMMessage(role="user", content="hi")], tools=[tool])

    assert out.has_tool_calls is True
    assert out.content == ""
    assert out.tool_calls[0].name == "account_lookup"
    assert out.tool_calls[0].arguments == {"account_id": "acc_55"}

