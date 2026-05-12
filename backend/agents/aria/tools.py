from __future__ import annotations

import re
from typing import Any, Callable, Mapping

from agents.base_agent import AgentTrigger
from tools.banking_client import http_create_ticket, http_get_account, resolve_requester_account_number
from tools.email_tool import EmailSenderTool


def _resolve_nuban_for_ticket(*, llm_customer_id: str, trigger: AgentTrigger | None) -> str | None:
    """Resolve a 10-digit NUBAN; never trust raw LLM output alone."""
    raw = (llm_customer_id or "").strip()
    nuban = resolve_requester_account_number(raw)
    if nuban and re.fullmatch(r"\d{10}", nuban):
        return nuban
    if trigger:
        aid = (trigger.actor_id or "").strip()
        nuban2 = resolve_requester_account_number(aid)
        if nuban2 and re.fullmatch(r"\d{10}", nuban2):
            return nuban2
    return None


def build_aria_tools(
    *,
    trigger: AgentTrigger | None = None,
) -> tuple[Mapping[str, Callable[..., Any]], dict[str, Any]]:
    email_sender = EmailSenderTool()

    def ticket_create(**kwargs: Any) -> dict[str, Any]:
        nuban = _resolve_nuban_for_ticket(
            llm_customer_id=str(kwargs.get("customer_id", "")),
            trigger=trigger,
        )
        if not nuban:
            return {
                "created": False,
                "error": "invalid_customer_account",
                "message": "customer_account must be a 10-digit NUBAN tied to the requester or tool arguments.",
            }
        # Internal agent path: persist for audit only — do not enqueue aria_process_support_ticket (see tickets API).
        return http_create_ticket(
            customer_id=nuban,
            subject=str(kwargs.get("subject", "")),
            message=str(kwargs.get("message", "")),
            skip_aria_queue=True,
        )

    tools: Mapping[str, Callable[..., Any]] = {
        "account_lookup": lambda **kwargs: http_get_account(
            account_id=str(kwargs.get("account_id", "")),
            requester_customer_id=str(kwargs.get("requester_customer_id", "")),
        ),
        "ticket_create": ticket_create,
        "email_send": lambda **kwargs: email_sender.send(**kwargs),
    }

    deps = {
        "email_sender": email_sender,
    }
    return tools, deps
