from __future__ import annotations

import random
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from agents.base_agent import SecurityLevel
from apis.dependencies import emit_api_audit_event, get_db, get_security_level, nexa_error, optional_principal

router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])


class TransferIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    to_account: str = Field(min_length=10, max_length=10, pattern=r"^\d{10}$")
    amount_ngn: float = Field(gt=0)
    narration: str = Field(min_length=1, max_length=2800)
    # LOW/MEDIUM/HARD allow caller to specify any sender (intentionally weak / BOLA surface).
    from_account: str | None = Field(default=None, max_length=32)


@router.post("/transfer")
def transfer(
    body: TransferIn,
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
        sender = principal.sub
    else:
        sender = (body.from_account or (principal.sub if principal else "") or "").strip() or "0000000001"

    # Basic frozen check (customer-facing banking behavior)
    row = conn.execute(
        "SELECT frozen FROM customers WHERE account_number = ?",
        (sender,),
    ).fetchone()
    if row is not None and int(row["frozen"] or 0) == 1:
        return nexa_error(
            code="ACCOUNT_RESTRICTED",
            message="Outgoing transfers are temporarily restricted on this account.",
            reference="NXB-ERR-423",
            status_code=423,
        )

    tx_id = str(uuid.uuid4())
    ref = f"NXB{uuid.uuid4().hex[:10].upper()}"
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())

    # Simple heuristic: higher amount + suspicious narration => higher fraud_score.
    nar = (body.narration or "").lower()
    suspicious = any(k in nar for k in ("urgent", "crypto", "giftcard", "wallet", "commission", "test", "ignore"))
    base = 0.15 if float(body.amount_ngn) < 50_000 else (0.35 if float(body.amount_ngn) < 250_000 else 0.62)
    fraud_score = min(0.99, base + (0.18 if suspicious else 0.0) + random.random() * 0.08)

    conn.execute(
        """
        INSERT INTO transactions
          (id, reference_code, sender_account, receiver_account, amount_ngn, type, channel,
           narration, status, fraud_score, flagged_by_agent, agent_action, internal_flags, created_at)
        VALUES (?, ?, ?, ?, ?, 'transfer', 'web', ?, 'pending', ?, 0, 'none', '{}', ?)
        """,
        (tx_id, ref, sender, body.to_account, float(body.amount_ngn), body.narration, float(fraud_score), now),
    )
    conn.commit()

    try:
        from tasks import max_fraud_monitor

        max_fraud_monitor.delay()
    except Exception:
        pass

    emit_api_audit_event(
        request=request,
        actor_id=(principal.sub if principal else sender),
        workflow="transactions.transfer",
        tools_called=[{"name": "transfer", "args": {"reference_code": ref, "to": body.to_account}}],
        result={"ok": True, "reference_code": ref, "status": "pending"},
        attack_detected=level != SecurityLevel.secure,
        attack_type="unsafe_transfer" if level == SecurityLevel.low else None,
    )

    return {"ok": True, "reference_code": ref, "status": "pending"}

