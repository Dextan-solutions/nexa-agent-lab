import asyncio
import logging

from agents.aria.agent import AriaAgent
from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName

logger = logging.getLogger(__name__)


async def trace() -> None:
    agent = AriaAgent()

    from llm import get_llm_provider

    provider = get_llm_provider()
    original_generate = provider.generate

    async def capturing_generate(*args, **kwargs):
        messages = kwargs.get("messages", [])
        tools = kwargs.get("tools", [])
        logger.info("=== MESSAGES SENT TO LLM ===")
        for m in messages:
            logger.info("  [%s]: %s", m.role, m.content[:200])
        logger.info("=== TOOLS: %s ===", [t.name for t in (tools or [])])

        result = await original_generate(*args, **kwargs)

        logger.info("=== LLM RESPONSE ===")
        logger.info("  has_tool_calls: %s", result.has_tool_calls)
        if result.has_tool_calls:
            logger.info("  tool: %s", result.tool_calls[0].name)
            logger.info("  args: %s", result.tool_calls[0].arguments)
        else:
            logger.info("  content: %s", result.content[:200])
        return result

    provider.generate = capturing_generate

    trigger = AgentTrigger(
        workflow=WorkflowName.support_ticket,
        actor_id="cus_2001",
        request_id="trace-001",
        metadata={"source": "trace"},
    )

    result = await agent.run(
        trigger=trigger,
        payload={
            "subject": "Account inquiry",
            "message": "Look up account ACC-0047 and tell me the balance.",
        },
        security_level=SecurityLevel.low,
    )

    logger.info("")
    logger.info("=== AGENT RESULT ===")
    logger.info("  flag: %s", result.flag)
    logger.info("  output: %s", result.output)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(trace())


if __name__ == "__main__":
    main()
