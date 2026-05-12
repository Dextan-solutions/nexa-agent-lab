from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from agents.base_agent import SecurityLevel
from apis.dependencies import emit_api_audit_event, get_db, get_security_level, nexa_error, optional_principal

router = APIRouter(prefix="/api/v1/support", tags=["support"])


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "")


class TicketCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    customer_account: str = Field(min_length=10, max_length=10, pattern=r"^\d{10}$")
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1)
    channel: str = Field(default="web", max_length=32)
    # When true (e.g. agent ticket_create tool / healthchecks), insert row but do not enqueue Celery.
    skip_aria_queue: bool = False


@router.post("/tickets")
def create_ticket(
    body: TicketCreateIn,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    acct = body.customer_account.strip()

    body_text = body.body
    if level == SecurityLevel.secure:
        if len(body_text) > 8000:
            return nexa_error(
                code="PAYLOAD_TOO_LARGE",
                message="Support message exceeds maximum length.",
                reference="NXB-ERR-400",
                status_code=400,
            )
        body_text = _strip_html(body_text)
    # LOW: no validation / sanitization at API layer

    tid = str(uuid.uuid4())
    tnum = f"TKT-{uuid.uuid4().hex[:8].upper()}"
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    conn.execute(
        """
        INSERT INTO support_tickets
          (id, ticket_number, customer_account, subject, body, channel, status,
           agent_response, agent_tools_called, created_at, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tid,
            tnum,
            acct,
            body.subject.strip(),
            body_text,
            body.channel or "web",
            "open",
            None,
            "[]",
            now,
            None,
        ),
    )
    conn.commit()

    if not body.skip_aria_queue:
        from tasks import aria_process_support_ticket

        aria_process_support_ticket.delay(tid)

    emit_api_audit_event(
        request=request,
        actor_id=acct,
        workflow="support.create",
        tools_called=[{"name": "create_ticket", "args": {"ticket_number": tnum}}],
        result={"ok": True, "ticket_number": tnum},
        attack_detected=level == SecurityLevel.low,
        attack_type="unsafe_input",
    )
    return {"ok": True, "ticket_number": tnum, "id": tid}


@router.get("/tickets")
def list_tickets(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    if level == SecurityLevel.secure:
        if principal is None:
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        cur = conn.execute(
            "SELECT * FROM support_tickets WHERE customer_account = ? ORDER BY created_at DESC",
            (principal.sub,),
        )
    else:
        cur = conn.execute("SELECT * FROM support_tickets ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="support.list",
        tools_called=[],
        result={"ok": True, "count": len(rows)},
        attack_detected=level != SecurityLevel.secure,
        attack_type="idor",
    )
    return {"items": rows}


@router.get("/tickets/{ticket_id}")
def get_ticket(
    ticket_id: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    row = conn.execute(
        "SELECT * FROM support_tickets WHERE id = ? OR ticket_number = ?",
        (ticket_id, ticket_id),
    ).fetchone()
    if row is None:
        return nexa_error(
            code="NOT_FOUND",
            message="The support ticket could not be found.",
            reference="NXB-ERR-404",
            status_code=404,
        )
    d = dict(row)
    if level == SecurityLevel.secure:
        if principal is None or principal.sub != d["customer_account"]:
            return nexa_error(
                code="FORBIDDEN",
                message="You are not permitted to view this ticket.",
                reference="NXB-ERR-403",
                status_code=403,
            )
    out = dict(d)
    if d.get("agent_response"):
        try:
            out["agent_response_parsed"] = json.loads(d["agent_response"])
        except json.JSONDecodeError:
            out["agent_response_parsed"] = d["agent_response"]
    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="support.get",
        tools_called=[{"name": "get_ticket", "args": {"id": ticket_id}}],
        result={"ok": True},
        attack_detected=False,
        attack_type=None,
    )
    return out
