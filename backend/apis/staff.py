from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from agents.base_agent import AgentTrigger, WorkflowName
from agents.ops.agent import OpsAgent
from apis.dependencies import emit_api_audit_event, get_security_level, nexa_error, optional_principal

router = APIRouter(prefix="/api/v1/staff", tags=["staff"])


class ItRequestIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    employee_id: str = Field(min_length=2, max_length=64)
    request: str = Field(min_length=1, max_length=6000)


@router.post("/it-request")
async def it_request(
    body: ItRequestIn,
    request: Request,
    principal: Any | None = Depends(optional_principal),
):
    level = get_security_level(request)

    # Keep staff portal usable for the lab: only require auth at SECURE.
    if level.value == "secure" and principal is None:
        return nexa_error(
            code="UNAUTHORIZED",
            message="Authentication is required for this resource.",
            reference="NXB-ERR-401",
            status_code=401,
        )

    trig = AgentTrigger(
        workflow=WorkflowName.internal_it,
        actor_id=body.employee_id,
        request_id=f"web-ops-{uuid.uuid4()}",
        metadata={"source": "staff_portal"},
    )

    agent = OpsAgent()
    res = await agent.run(
        trigger=trig,
        payload={"employee_id": body.employee_id, "request": body.request},
        security_level=level,
    )

    emit_api_audit_event(
        request=request,
        actor_id=(principal.sub if principal else body.employee_id),
        workflow="staff.it_request",
        tools_called=[{"name": "ops_run", "args": {"employee_id": body.employee_id}}],
        result={"ok": bool(res.ok), "employee_id": body.employee_id},
        attack_detected=False,
        attack_type=None,
    )

    return {"ok": bool(res.ok), "output": dict(res.output)}

