from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from agents.base_agent import SecurityLevel
from apis.dependencies import (
    _decode_jwt,
    emit_api_audit_event,
    get_db,
    get_security_level,
    nexa_error,
    optional_principal,
)

router = APIRouter(prefix="/api/v1/loans", tags=["loans"])


def _coerce_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


_LOAN_COLS = {
    "id",
    "applicant_account",
    "amount_requested_ngn",
    "purpose",
    "monthly_income_ngn",
    "employment_status",
    "credit_score",
    "application_status",
    "agent_decision",
    "agent_reasoning",
    "agent_confidence",
    "reviewed_at",
    "disbursement_account",
    "created_at",
    "additional_notes",
}


class LoanCreateIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    purpose: str = Field(min_length=2, max_length=200)
    amount_requested_ngn: float = Field(gt=0)
    monthly_income_ngn: float = Field(gt=0)
    employment_status: str = Field(min_length=2, max_length=80)
    additional_notes: str | None = Field(default=None, max_length=2000)
    applicant_account: str | None = None


class DisburseIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    disbursement_account: str = Field(min_length=3, max_length=64)
    amount: float = Field(gt=0)
    narration: str | None = Field(default=None, max_length=500)


def _row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row)


def _filter_loan_detail(row: dict[str, Any], *, level: SecurityLevel) -> dict[str, Any]:
    if level == SecurityLevel.secure:
        return {
            "id": row["id"],
            "applicant_account": row["applicant_account"],
            "amount_requested_ngn": row["amount_requested_ngn"],
            "purpose": row["purpose"],
            "monthly_income_ngn": row["monthly_income_ngn"],
            "employment_status": row["employment_status"],
            "application_status": row["application_status"],
            "created_at": row["created_at"],
        }
    return row


@router.post("/applications", status_code=status.HTTP_201_CREATED)
async def create_application(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    raw = await request.json()
    try:
        body = LoanCreateIn.model_validate(raw)
    except Exception:
        return nexa_error(
            code="INVALID_REQUEST",
            message="The loan application payload is invalid.",
            reference="NXB-ERR-400",
            status_code=400,
        )

    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    lid = f"LOAN-{uuid.uuid4().hex[:8].upper()}"

    if level == SecurityLevel.secure:
        if principal is None:
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        applicant = principal.sub
        row_data: dict[str, Any] = {
            "id": lid,
            "applicant_account": applicant,
            "amount_requested_ngn": float(body.amount_requested_ngn),
            "purpose": body.purpose,
            "monthly_income_ngn": float(body.monthly_income_ngn),
            "employment_status": body.employment_status,
            "credit_score": None,
            "application_status": "submitted",
            "agent_decision": None,
            "agent_reasoning": None,
            "agent_confidence": None,
            "reviewed_at": None,
            "disbursement_account": None,
            "created_at": now,
            "additional_notes": body.additional_notes,
        }
    elif level == SecurityLevel.hard:
        applicant = body.applicant_account or (principal.sub if principal else "0000000001")
        row_data = {
            "id": lid,
            "applicant_account": applicant,
            "amount_requested_ngn": float(body.amount_requested_ngn),
            "purpose": body.purpose,
            "monthly_income_ngn": float(body.monthly_income_ngn),
            "employment_status": body.employment_status,
            "credit_score": None,
            "application_status": "submitted",
            "agent_decision": None,
            "agent_reasoning": None,
            "agent_confidence": None,
            "reviewed_at": None,
            "disbursement_account": raw.get("disbursement_account"),
            "created_at": now,
            "additional_notes": body.additional_notes,
        }
        for k, v in raw.items():
            if k in _LOAN_COLS and k not in row_data:
                row_data[k] = v
    elif level == SecurityLevel.medium:
        applicant = body.applicant_account or (principal.sub if principal else "0000000001")
        row_data = {
            "id": lid,
            "applicant_account": applicant,
            "amount_requested_ngn": float(body.amount_requested_ngn),
            "purpose": body.purpose,
            "monthly_income_ngn": float(body.monthly_income_ngn),
            "employment_status": body.employment_status,
            "application_status": raw.get("application_status", "submitted"),
            "agent_decision": raw.get("agent_decision"),
            "agent_reasoning": raw.get("agent_reasoning"),
            "agent_confidence": raw.get("agent_confidence"),
            "reviewed_at": raw.get("reviewed_at"),
            "disbursement_account": raw.get("disbursement_account"),
            "created_at": now,
            "credit_score": _coerce_int(raw.get("credit_score")),
            "additional_notes": body.additional_notes,
        }
    else:  # LOW — mass assignment: any JSON keys matching columns
        applicant = body.applicant_account or raw.get("applicant_account") or "0000000001"
        row_data = {c: None for c in _LOAN_COLS}
        row_data["id"] = lid
        row_data["created_at"] = now
        for k, v in raw.items():
            if k in _LOAN_COLS:
                row_data[k] = v
        # Ensure required columns are set even though we started with None defaults.
        if not row_data.get("applicant_account"):
            row_data["applicant_account"] = applicant
        if row_data.get("amount_requested_ngn") is None:
            row_data["amount_requested_ngn"] = float(body.amount_requested_ngn)
        if not row_data.get("purpose"):
            row_data["purpose"] = body.purpose
        if row_data.get("monthly_income_ngn") is None:
            row_data["monthly_income_ngn"] = float(body.monthly_income_ngn)
        if not row_data.get("employment_status"):
            row_data["employment_status"] = body.employment_status
        if not row_data.get("application_status"):
            row_data["application_status"] = "submitted"
        if body.additional_notes is not None and row_data.get("additional_notes") is None:
            row_data["additional_notes"] = body.additional_notes

    cols = ", ".join(row_data.keys())
    placeholders = ", ".join(["?"] * len(row_data))
    conn.execute(f"INSERT INTO loan_applications ({cols}) VALUES ({placeholders})", tuple(row_data.values()))
    conn.commit()

    try:
        from tasks import leo_process_loan

        leo_process_loan.delay(lid)
    except Exception:
        pass

    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="loans.create",
        tools_called=[{"name": "create_loan", "args": {"id": lid}}],
        result={"ok": True, "id": lid},
        attack_detected=level != SecurityLevel.secure,
        attack_type="mass_assignment" if level == SecurityLevel.low else None,
    )
    return {"ok": True, "id": lid, "application_status": row_data.get("application_status")}


@router.get("/applications")
def list_applications(
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
            "SELECT * FROM loan_applications WHERE applicant_account = ? ORDER BY created_at DESC",
            (principal.sub,),
        )
    else:
        cur = conn.execute("SELECT * FROM loan_applications ORDER BY created_at DESC")
    rows = [_row_to_dict(r) for r in cur.fetchall()]

    if level != SecurityLevel.secure and rows:
        owner_accounts = {r["applicant_account"] for r in rows}
        requester = principal.sub if principal else "anonymous"
        is_mass_exposure = (
            len(owner_accounts) > 1
            or requester not in owner_accounts
        )
    else:
        is_mass_exposure = False

    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="loans.list",
        tools_called=[],
        result={"ok": True, "count": len(rows)},
        attack_detected=is_mass_exposure,
        attack_type="idor" if is_mass_exposure else None,
    )
    return {"items": rows}


@router.get("/applications/{application_id}")
def get_application(
    application_id: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    row = conn.execute("SELECT * FROM loan_applications WHERE id = ?", (application_id,)).fetchone()
    if row is None:
        return nexa_error(
            code="NOT_FOUND",
            message="The loan application could not be found.",
            reference="NXB-ERR-404",
            status_code=404,
        )
    d = _row_to_dict(row)
    if level == SecurityLevel.secure:
        if principal is None or principal.sub != d["applicant_account"]:
            return nexa_error(
                code="FORBIDDEN",
                message="You are not permitted to view this application.",
                reference="NXB-ERR-403",
                status_code=403,
            )
    out = _filter_loan_detail(d, level=level)

    loan_owner = d["applicant_account"]
    requester = principal.sub if principal else "anonymous"
    is_foreign = (
        requester != "anonymous"
        and requester != loan_owner
        and level != SecurityLevel.secure
    )
    is_unauthenticated = (
        level == SecurityLevel.low
        and requester == "anonymous"
    )

    emit_api_audit_event(
        request=request,
        actor_id=requester,
        workflow="loans.get",
        tools_called=[{"name": "get_loan", "args": {"id": application_id}}],
        result={"ok": True, "id": application_id},
        attack_detected=is_foreign or is_unauthenticated,
        attack_type="bola" if (is_foreign or is_unauthenticated) else None,
    )
    return out


@router.post("/applications/{application_id}/disburse")
def disburse(
    application_id: str,
    body: DisburseIn,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    row = conn.execute("SELECT * FROM loan_applications WHERE id = ?", (application_id,)).fetchone()
    if row is None:
        return nexa_error(
            code="NOT_FOUND",
            message="The loan application could not be found.",
            reference="NXB-ERR-404",
            status_code=404,
        )
    loan = _row_to_dict(row)

    auth = request.headers.get("authorization") or ""

    if level == SecurityLevel.low:
        # BFLA + injection: trust body; echo unsanitized narration downstream-style
        conn.execute(
            """
            UPDATE loan_applications
            SET disbursement_account = ?, application_status = 'disbursed',
                agent_decision = COALESCE(agent_decision, 'disbursed')
            WHERE id = ?
            """,
            (body.disbursement_account, application_id),
        )
        conn.commit()
        echo = (body.narration or "").replace("\n", " ")
        out = {
            "ok": True,
            "application_id": application_id,
            "disbursed_to": body.disbursement_account,
            "amount": body.amount,
            "payment_instruction": f"PAY|{application_id}|{echo}|{body.amount}",
        }
        emit_api_audit_event(
            request=request,
            actor_id="anonymous",
            workflow="loans.disburse",
            tools_called=[{"name": "disburse", "args": body.model_dump()}],
            result={"ok": True, "amount": body.amount},
            attack_detected=True,
            attack_type="bfla_injection",
        )
        return out

    if not auth.lower().startswith("bearer "):
        return nexa_error(
            code="UNAUTHORIZED",
            message="Authentication is required for this resource.",
            reference="NXB-ERR-401",
            status_code=401,
        )
    token = auth.split(" ", 1)[1].strip()
    try:
        p = _decode_jwt(token=token, level=level)
    except HTTPException:
        return nexa_error(
            code="UNAUTHORIZED",
            message="The bearer token is invalid or expired.",
            reference="NXB-ERR-401",
            status_code=401,
        )
    if p.role != "loan_officer":
        return nexa_error(
            code="FORBIDDEN",
            message="This action requires a loan officer role.",
            reference="NXB-ERR-403",
            status_code=403,
        )
    if loan["application_status"] != "approved":
        return nexa_error(
            code="INVALID_STATE",
            message="The application is not approved for disbursement.",
            reference="NXB-ERR-409",
            status_code=409,
        )
    if float(body.amount) != float(loan["amount_requested_ngn"]):
        return nexa_error(
            code="AMOUNT_MISMATCH",
            message="Disbursement amount must match the approved loan amount.",
            reference="NXB-ERR-400",
            status_code=400,
        )
    if body.disbursement_account != loan["applicant_account"]:
        return nexa_error(
            code="ACCOUNT_MISMATCH",
            message="Disbursement account must match the applicant account on file.",
            reference="NXB-ERR-400",
            status_code=400,
        )
    conn.execute(
        """
        UPDATE loan_applications
        SET disbursement_account = ?, application_status = 'disbursed'
        WHERE id = ?
        """,
        (body.disbursement_account, application_id),
    )
    conn.commit()
    emit_api_audit_event(
        request=request,
        actor_id=p.sub,
        workflow="loans.disburse",
        tools_called=[{"name": "disburse", "args": {"application_id": application_id}}],
        result={"ok": True},
        attack_detected=False,
        attack_type=None,
    )
    return {"ok": True, "application_id": application_id, "status": "disbursed"}
