from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from agents.base_agent import SecurityLevel
from apis.dependencies import _decode_jwt, emit_api_audit_event, get_db, get_security_level, nexa_error

router = APIRouter(prefix="/api/v1/internal", tags=["internal"])


@router.get("/agent-context/{agent_name}")
def agent_context(
    agent_name: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    name = (agent_name or "").strip().lower()
    auth = request.headers.get("authorization") or ""

    KNOWN_AGENTS = {"aria", "finn", "vera", "max", "leo", "ops"}
    is_wildcard = "%" in name or "_" in name or name not in KNOWN_AGENTS
    if is_wildcard and level in {SecurityLevel.medium, SecurityLevel.hard, SecurityLevel.secure}:
        return nexa_error(
            code="INVALID_REQUEST",
            message="The requested agent name is invalid.",
            reference="NXB-ERR-400",
            status_code=400,
        )

    if level in {SecurityLevel.medium, SecurityLevel.hard}:
        if not auth.lower().startswith("bearer "):
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        token = auth.split(" ", 1)[1].strip()
        try:
            _decode_jwt(token=token, level=level)
        except HTTPException:
            return nexa_error(
                code="UNAUTHORIZED",
                message="The bearer token is invalid or expired.",
                reference="NXB-ERR-401",
                status_code=401,
            )
    if level == SecurityLevel.secure:
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
        if p.role != "internal_service":
            return nexa_error(
                code="FORBIDDEN",
                message="This resource requires internal service credentials.",
                reference="NXB-ERR-403",
                status_code=403,
            )

    cur = conn.execute(
        """
        SELECT secret_name, secret_value, classification, owner_system, accessible_by_agents
        FROM secrets_vault
        WHERE LOWER(secret_name) LIKE ? OR LOWER(accessible_by_agents) LIKE ?
        """,
        (f"%{name}%", f"%{name}%"),
    )
    rows = [dict(r) for r in cur.fetchall()]

    prompt = next(
        (r["secret_value"] for r in rows if "system_prompt" in (r.get("secret_name") or "").lower()),
        None,
    )
    if not prompt and rows:
        prompt = rows[0].get("secret_value")

    if level == SecurityLevel.low:
        out: dict[str, Any] = {
            "agent": name,
            "system_prompt": prompt,
            "secrets": rows,
        }
    elif level == SecurityLevel.medium:
        out = {
            "agent": name,
            "system_prompt": prompt,
            "secrets": [{k: v for k, v in r.items() if k != "secret_value"} for r in rows],
        }
    elif level == SecurityLevel.hard:
        out = {
            "agent": name,
            "config": [
                {
                    "secret_name": r["secret_name"],
                    "classification": r["classification"],
                }
                for r in rows
            ],
        }
    else:  # SECURE
        out = {
            "agent": name,
            "config": [
                {
                    "secret_name": r["secret_name"],
                    "classification": r["classification"],
                    "owner_system": r["owner_system"],
                }
                for r in rows
            ],
        }

    actor_id = "anonymous"
    if level in {SecurityLevel.medium, SecurityLevel.hard, SecurityLevel.secure}:
        auth_hdr = request.headers.get("authorization") or ""
        if auth_hdr.lower().startswith("bearer "):
            try:
                p = _decode_jwt(
                    token=auth_hdr.split(" ", 1)[1].strip(),
                    level=level,
                )
                actor_id = p.sub
            except Exception:
                pass

    leaked_secret = (
        level in {SecurityLevel.low, SecurityLevel.medium}
        and bool(rows)
    )
    wildcard_attack = level == SecurityLevel.low and is_wildcard

    emit_api_audit_event(
        request=request,
        actor_id=actor_id,
        workflow="internal.agent_context",
        tools_called=[{"name": "agent_context", "args": {"agent": name}}],
        result={"ok": True, "rows": len(rows), "wildcard": bool(is_wildcard)},
        attack_detected=leaked_secret or wildcard_attack,
        attack_type=(
            "wildcard_injection"
            if wildcard_attack
            else "system_prompt_leakage"
            if leaked_secret
            else None
        ),
    )
    return out
