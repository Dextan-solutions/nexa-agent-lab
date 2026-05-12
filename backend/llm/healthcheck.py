from __future__ import annotations

import asyncio

from llm import get_llm_provider
from llm.base_provider import LLMMessage, ToolSpec


async def run() -> None:
    all_ok = True
    provider = get_llm_provider()
    print(f"  Provider: {provider.provider_slug}")
    print(f"  Model: {provider.model_name}")
    if provider.provider_slug == "ollama":
        print("  Ollama URL: (resolving...)")

    # Test 1: basic generation
    try:
        await provider.generate(
            messages=[
                LLMMessage(role="system", content="Say OK"),
                LLMMessage(role="user", content="Say OK"),
            ],
            temperature=0.0,
        )
        print("  PASS  Text generation")
        if provider.provider_slug == "ollama":
            base_url = getattr(provider, "base_url", "")
            print(f"  Ollama URL: {base_url}")
            print(f"  Source: {'host' if 'host.docker.internal' in str(base_url) else 'docker'}")
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  Text generation: {e}")
        all_ok = False

    # Test 2: tool calling
    try:
        resp = await provider.generate(
            messages=[
                LLMMessage(role="system", content="Use the lookup tool."),
                LLMMessage(role="user", content="Look up account ACC-0047"),
            ],
            tools=[
                ToolSpec(
                    name="account_lookup",
                    description="Look up an account.",
                    parameters_schema={
                        "type": "object",
                        "properties": {"account_id": {"type": "string"}},
                        "required": ["account_id"],
                    },
                )
            ],
            temperature=0.0,
        )
        if resp.has_tool_calls:
            print("  PASS  Tool calling")
            print(f"        Tool: {resp.tool_calls[0].name}")
            print(f"        Args: {resp.tool_calls[0].arguments}")
        else:
            print("  FAIL  Tool calling: no tool call in response")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  Tool calling: {e}")
        all_ok = False

    # Test 3: embeddings
    try:
        emb = await provider.embed(text="NexaBank KYC policy")
        if len(emb.vector) > 0:
            print("  PASS  Embeddings")
            print(f"        Dimensions: {len(emb.vector)}")
        else:
            print("  FAIL  Embeddings: empty vector")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  Embeddings: {e}")
        all_ok = False

    print()
    if all_ok:
        print("LLM Provider: PASS")
    else:
        print("LLM Provider: FAIL")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(run())

