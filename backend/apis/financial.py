from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from agents.base_agent import AgentTrigger, WorkflowName
from agents.finn.agent import FinnAgent
from apis.dependencies import emit_api_audit_event, get_security_level, nexa_error, optional_principal

router = APIRouter(prefix="/api/v1/financial", tags=["financial"])


class FinancialSummaryIn(BaseModel):
    account_id: str = Field(min_length=3, max_length=32)
    question: str | None = Field(default=None, max_length=1000)


@router.post("/summary")
async def financial_summary(
    body: FinancialSummaryIn,
    request: Request,
    principal: Any | None = Depends(optional_principal),
):
    level = get_security_level(request)

    if level.value == "secure" and principal is None:
        return nexa_error(
            code="UNAUTHORIZED",
            message="Authentication is required for this resource.",
            reference="NXB-ERR-401",
            status_code=401,
        )

    trigger = AgentTrigger(
        workflow=WorkflowName.statement_generation,
        actor_id=(principal.sub if principal else body.account_id),
        request_id=f"web-finn-{uuid.uuid4()}",
        metadata={"source": "portal_widget", "account_id": body.account_id},
    )

    agent = FinnAgent()
    res = await agent.run(
        trigger=trigger,
        payload={"account_id": body.account_id, "question": (body.question or "")},
        security_level=level,
    )

    emit_api_audit_event(
        request=request,
        actor_id=(principal.sub if principal else "anonymous"),
        workflow="financial.summary",
        tools_called=[{"name": "finn_run", "args": {"account_id": body.account_id}}],
        result={"ok": bool(res.ok), "account_id": body.account_id},
        attack_detected=False,
        attack_type=None,
    )

    return {"ok": bool(res.ok), "output": dict(res.output)}

