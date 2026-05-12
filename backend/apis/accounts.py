from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from agents.base_agent import SecurityLevel
from apis.dependencies import (
    _decode_jwt,
    emit_api_audit_event,
    get_db,
    get_security_level,
    nexa_error,
    optional_principal,
)

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


def _resolve_customer(conn, account_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve path account_id (NUBAN or ACC-XXXX) to a customer row dict or None."""
    aid = (account_id or "").strip()
    if not aid:
        return None, None
    m = re.fullmatch(r"ACC-(\d{4})", aid.upper())
    if m:
        acct_num = f"0{int(m.group(1)):09d}"
    elif re.fullmatch(r"\d{10}", aid):
        acct_num = aid
    else:
        row = conn.execute("SELECT * FROM customers WHERE id = ?", (aid,)).fetchone()
        return (dict(row) if row else None), aid

    row = conn.execute("SELECT * FROM customers WHERE account_number = ?", (acct_num,)).fetchone()
    return (dict(row) if row else None), aid


def _customer_public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "account_number": row["account_number"],
        "full_name": row["full_name"],
        "email": row["email"],
        "phone": row["phone"],
        "bvn": row["bvn"],
        "account_type": row["account_type"],
        "balance_ngn": row["balance_ngn"],
        "tier": row["tier"],
        "kyc_status": row["kyc_status"],
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "frozen": int(row.get("frozen") or 0),
    }


def _bola_authorized(
    *,
    level: SecurityLevel,
    request: Request,
    row: dict[str, Any],
    path_account_id: str,
    principal: Any | None,
) -> bool:
    if level == SecurityLevel.low:
        return True
    if level == SecurityLevel.medium:
        return bool(path_account_id)
    if level == SecurityLevel.hard:
        hdr = (request.headers.get("x-customer-id") or "").strip()
        return hdr == path_account_id
    # SECURE
    if principal is None:
        return False
    if principal.sub != row["account_number"]:
        return False
    return True


@router.get("/{account_id}")
def get_account(
    account_id: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    row, path_key = _resolve_customer(conn, account_id)
    if row is None:
        emit_api_audit_event(
            request=request,
            actor_id=principal.sub if principal else "anonymous",
            workflow="accounts.get",
            tools_called=[{"name": "get_account", "args": {"account_id": account_id}}],
            result={"ok": False, "reason": "not_found"},
        )
        return nexa_error(
            code="ACCOUNT_NOT_FOUND",
            message="The requested account could not be located.",
            reference="NXB-ERR-404",
            status_code=404,
        )

    ok = _bola_authorized(level=level, request=request, row=row, path_account_id=path_key, principal=principal)
    if level == SecurityLevel.secure and principal is None:
        return nexa_error(
            code="UNAUTHORIZED",
            message="Authentication is required for this resource.",
            reference="NXB-ERR-401",
            status_code=401,
        )
    if not ok:
        return nexa_error(
            code="FORBIDDEN",
            message="You are not permitted to access this account.",
            reference="NXB-ERR-403",
            status_code=403,
        )

    out = _customer_public(row)
    is_foreign_account = (
        principal is not None
        and principal.sub != "anonymous"
        and principal.sub != row["account_number"]
    )
    is_unauthenticated = (
        level == SecurityLevel.low
        and (principal is None or principal.sub == "anonymous")
    )
    attack_detected = is_foreign_account or is_unauthenticated
    attack_type = "bola" if attack_detected else None
    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="accounts.get",
        tools_called=[{"name": "get_account", "args": {"account_id": account_id}}],
        result={"ok": True, "account_number": row["account_number"]},
        attack_detected=attack_detected,
        attack_type=attack_type,
    )
    return out


@router.get("/{account_id}/transactions")
def list_transactions(
    account_id: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
    limit: int = 20,
    offset: int = 0,
    date_from: str | None = None,
    date_to: str | None = None,
):
    row, path_key = _resolve_customer(conn, account_id)
    if row is None:
        return nexa_error(
            code="ACCOUNT_NOT_FOUND",
            message="The requested account could not be located.",
            reference="NXB-ERR-404",
            status_code=404,
        )
    ok = _bola_authorized(level=level, request=request, row=row, path_account_id=path_key, principal=principal)
    if level == SecurityLevel.secure and principal is None:
        return nexa_error(
            code="UNAUTHORIZED",
            message="Authentication is required for this resource.",
            reference="NXB-ERR-401",
            status_code=401,
        )
    if not ok:
        return nexa_error(
            code="FORBIDDEN",
            message="You are not permitted to access this account.",
            reference="NXB-ERR-403",
            status_code=403,
        )

    acct = row["account_number"]
    q = """
        SELECT * FROM transactions
        WHERE sender_account = ? OR receiver_account = ?
    """
    args: list[Any] = [acct, acct]
    if date_from:
        q += " AND created_at >= ?"
        args.append(date_from)
    if date_to:
        q += " AND created_at <= ?"
        args.append(date_to)
    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([max(1, min(limit, 200)), max(0, offset)])
    cur = conn.execute(q, tuple(args))
    txs = [dict(r) for r in cur.fetchall()]

    def _shape(t: dict[str, Any]) -> dict[str, Any]:
        if level == SecurityLevel.low:
            flags_raw = t.get("internal_flags") or "{}"
            try:
                flags = json.loads(flags_raw) if isinstance(flags_raw, str) else flags_raw
            except json.JSONDecodeError:
                flags = {}
            return {
                **t,
                "internal_flags": flags,
            }
        if level == SecurityLevel.medium:
            return {k: t[k] for k in t if k != "internal_flags"}
        if level == SecurityLevel.hard:
            out = {k: v for k, v in t.items() if k != "fraud_score"}
            return out
        # SECURE — customer-visible only
        return {
            "reference_code": t["reference_code"],
            "amount_ngn": t["amount_ngn"],
            "type": t["type"],
            "channel": t["channel"],
            "narration": t["narration"],
            "status": t["status"],
            "created_at": t["created_at"],
        }

    shaped = [_shape(t) for t in txs]
    is_foreign_account = (
        principal is not None
        and principal.sub != "anonymous"
        and principal.sub != row["account_number"]
    )
    attack_detected = is_foreign_account and level != SecurityLevel.secure
    attack_type = "excessive_data_exposure" if attack_detected else None
    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="accounts.list_transactions",
        tools_called=[{"name": "list_transactions", "args": {"account_id": account_id, "limit": limit}}],
        result={"ok": True, "count": len(shaped)},
        attack_detected=attack_detected,
        attack_type=attack_type,
    )
    return {"items": shaped, "limit": limit, "offset": offset}


class FreezeIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    initiated_by: str = Field(min_length=1, max_length=200)


@router.post("/{account_id}/freeze")
def freeze_account(
    account_id: str,
    body: FreezeIn,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    row, _path_key = _resolve_customer(conn, account_id)
    if row is None:
        return nexa_error(
            code="ACCOUNT_NOT_FOUND",
            message="The requested account could not be located.",
            reference="NXB-ERR-404",
            status_code=404,
        )

    auth = request.headers.get("authorization") or ""
    actor_principal: Any | None = None

    if level == SecurityLevel.low:
        pass  # no checks
    elif level == SecurityLevel.medium:
        if not auth.lower().startswith("bearer "):
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
    elif level == SecurityLevel.hard:
        if not auth.lower().startswith("bearer "):
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        token = auth.split(" ", 1)[1].strip()
        try:
            actor_principal = _decode_jwt(token=token, level=level)
        except HTTPException:
            return nexa_error(
                code="UNAUTHORIZED",
                message="The bearer token is invalid or expired.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        # Wrong claim: business account holders may freeze (intentionally broken).
        if (actor_principal.account_type or "").lower() != "business":
            return nexa_error(
                code="FORBIDDEN",
                message="Only business accounts may initiate this action.",
                reference="NXB-ERR-403",
                status_code=403,
            )
    else:  # SECURE
        if not auth.lower().startswith("bearer "):
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        token = auth.split(" ", 1)[1].strip()
        try:
            actor_principal = _decode_jwt(token=token, level=level)
        except HTTPException:
            return nexa_error(
                code="UNAUTHORIZED",
                message="The bearer token is invalid or expired.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        if actor_principal.role != "compliance_officer":
            return nexa_error(
                code="FORBIDDEN",
                message="This action requires a compliance officer role.",
                reference="NXB-ERR-403",
                status_code=403,
            )

    conn.execute("UPDATE customers SET frozen = 1 WHERE account_number = ?", (row["account_number"],))
    conn.commit()

    emit_api_audit_event(
        request=request,
        actor_id=(actor_principal.sub if actor_principal else body.initiated_by),
        workflow="accounts.freeze",
        tools_called=[{"name": "freeze_account", "args": {"account_id": account_id, "reason": body.reason}}],
        result={"ok": True, "account_number": row["account_number"], "frozen": True},
        attack_detected=level != SecurityLevel.secure,
        attack_type="bfla" if level != SecurityLevel.secure else None,
    )
    return {"ok": True, "account_number": row["account_number"], "status": "frozen"}
