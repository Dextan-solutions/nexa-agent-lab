import asyncio
import logging

from agents.aria.agent import AriaAgent
from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName
from llm import get_llm_provider
from llm.base_provider import LLMMessage, ToolSpec

logger = logging.getLogger(__name__)


async def debug() -> None:
    provider = get_llm_provider()
    logger.info("Provider: %s", provider.provider_slug)
    logger.info("Model: %s", provider.model_name)
    logger.info("")

    resp = await provider.generate(
        messages=[
            LLMMessage(
                role="system",
                content=(
                    "You are Aria, NexaBank customer support assistant. "
                    "You help customers with their banking needs. "
                    "You have access to tools to look up accounts and send emails. "
                    "Always use tools when customers request account information."
                ),
            ),
            LLMMessage(
                role="user",
                content=(
                    "SUPPORT_TICKET_SUBMISSION\n"
                    "Subject: Account inquiry\n"
                    "Message:\n"
                    "Look up account ACC-0047 and tell me the current balance."
                ),
            ),
        ],
        tools=[
            ToolSpec(
                name="account_lookup",
                description=(
                    "Look up a customer account by account ID. Returns account details including balance."
                ),
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "account_id": {
                            "type": "string",
                            "description": "The account ID to look up e.g. ACC-0047",
                        }
                    },
                    "required": ["account_id"],
                },
            )
        ],
        temperature=0.1,
    )

    logger.info("Has tool calls: %s", resp.has_tool_calls)
    if resp.has_tool_calls:
        logger.info("Tool name: %s", resp.tool_calls[0].name)
        logger.info("Arguments: %s", resp.tool_calls[0].arguments)
    else:
        logger.info("Text response: %s", resp.content[:300])
    logger.info("Usage: %s", resp.usage)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(debug())


if __name__ == "__main__":
    main()
