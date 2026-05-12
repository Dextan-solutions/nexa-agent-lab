from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from agents.base_agent import SecurityLevel
from apis.dependencies import (
    _decode_jwt,
    emit_api_audit_event,
    get_db,
    get_security_level,
    nexa_error,
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/employees")
def list_employees(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    auth = request.headers.get("authorization") or ""
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

    if level == SecurityLevel.secure:
        if p.role not in {"hr_officer", "admin"}:
            return nexa_error(
                code="FORBIDDEN",
                message="This resource requires HR or administrator privileges.",
                reference="NXB-ERR-403",
                status_code=403,
            )

    cur = conn.execute("SELECT * FROM employees ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    emit_api_audit_event(
        request=request,
        actor_id=p.sub,
        workflow="admin.list_employees",
        tools_called=[],
        result={"ok": True, "count": len(rows)},
        attack_detected=level != SecurityLevel.secure,
        attack_type="bfla",
    )
    return {"items": rows}


@router.get("/secrets")
def list_vault_secrets(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    """Privileged vault listing (vulnerable at LOW with weak JWT secret in lab)."""
    auth = request.headers.get("authorization") or ""
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

    if p.role not in {"admin", "hr_officer"}:
        return nexa_error(
            code="FORBIDDEN",
            message="This resource requires administrator privileges.",
            reference="NXB-ERR-403",
            status_code=403,
        )

    cur = conn.execute(
        """
        SELECT id, secret_name, secret_value, classification, owner_system, accessible_by_agents
        FROM secrets_vault
        ORDER BY secret_name ASC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]

    secrets: list[dict[str, Any]]
    if level == SecurityLevel.low:
        secrets = rows
    elif level == SecurityLevel.medium:
        secrets = [{k: v for k, v in r.items() if k != "secret_value"} for r in rows]
    else:
        secrets = [
            {"secret_name": r["secret_name"], "classification": r["classification"], "owner_system": r["owner_system"]}
            for r in rows
        ]

    emit_api_audit_event(
        request=request,
        actor_id=p.sub,
        workflow="admin.list_secrets",
        tools_called=[],
        result={"ok": True, "count": len(secrets)},
        attack_detected=level != SecurityLevel.secure,
        attack_type="bfla",
    )
    return {"secrets": secrets, "count": len(secrets)}
