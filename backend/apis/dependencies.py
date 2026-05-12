from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
import sqlite3

from jose import JWTError, jwt

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from config.settings import settings
from db.sqlite import connect, insert_audit_event


def nexa_error(*, code: str, message: str, reference: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "reference": reference,
                "support": "contact support@nexabank.ng",
            }
        },
    )


def get_security_level(request: Request) -> SecurityLevel:
    lvl = getattr(request.state, "security_level", None)
    if isinstance(lvl, SecurityLevel):
        return lvl
    lvl2 = security_level_store.get().level
    request.state.security_level = lvl2
    return lvl2


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


Role = Literal[
    "customer",
    "employee",
    "compliance_officer",
    "loan_officer",
    "hr_officer",
    "admin",
    "internal_service",
]


@dataclass(frozen=True, slots=True)
class Principal:
    sub: str  # account_number or employee_id
    account_id: str | None
    role: Role
    tier: int | None
    account_type: str | None = None  # from customers.account_type (customer JWTs)


_LOW_JWT_SECRET = "nexabank-secret-key"


def _jwt_secret_for_level(level: SecurityLevel) -> str:
    # Intentionally weak at LOW: hardcoded secret.
    if level == SecurityLevel.low:
        return _LOW_JWT_SECRET
    return settings.jwt_secret


def _decode_jwt(*, token: str, level: SecurityLevel) -> Principal:
    try:
        payload = jwt.decode(
            token,
            _jwt_secret_for_level(level),
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail="invalid_token") from e

    sub = payload.get("sub")
    role = payload.get("role", "customer")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(status_code=401, detail="invalid_token")
    if role not in {
        "customer",
        "employee",
        "compliance_officer",
        "loan_officer",
        "hr_officer",
        "admin",
        "internal_service",
    }:
        role = "customer"
    account_id = payload.get("account_id")
    tier = payload.get("tier")
    account_type = payload.get("account_type")
    tier_out: int | None = None
    if isinstance(tier, (int, float)) and not isinstance(tier, bool):
        tier_out = int(tier)
    return Principal(
        sub=sub,
        account_id=str(account_id) if isinstance(account_id, str) and account_id else None,
        role=role,  # type: ignore[arg-type]
        tier=tier_out,
        account_type=str(account_type) if isinstance(account_type, str) else None,
    )


def get_current_principal(request: Request, level: SecurityLevel = Depends(get_security_level)) -> Principal:
    auth = request.headers.get("authorization") or ""
    if level == SecurityLevel.low and not auth:
        return Principal(
            sub="anonymous",
            account_id=None,
            role="customer",
            tier=1,
            account_type=None,
        )
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing_token")
    token = auth.split(" ", 1)[1].strip()
    return _decode_jwt(token=token, level=level)


def optional_principal(request: Request, level: SecurityLevel = Depends(get_security_level)) -> Principal | None:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        return _decode_jwt(token=token, level=level)
    except HTTPException:
        return None


def mint_customer_access_token(*, conn: sqlite3.Connection, account_number: str, level: SecurityLevel | None = None) -> str:
    """Mint a customer JWT for internal tool calls (e.g. sandbox → banking API at SECURE)."""
    row = conn.execute(
        "SELECT account_number, account_id, tier, account_type FROM customers WHERE account_number = ?",
        (account_number,),
    ).fetchone()
    if row is None:
        raise ValueError("account_not_found")
    lvl = level or security_level_store.get().level
    now = int(time.time())
    acc_id = row["account_id"] or row["account_number"]
    payload = {
        "sub": row["account_number"],
        "account_id": acc_id,
        "role": "customer",
        "tier": int(row["tier"]),
        "account_type": row["account_type"],
        "exp": now + settings.access_token_ttl_s,
        "iat": now,
    }
    secret = _jwt_secret_for_level(lvl)
    return jwt.encode(payload, secret, algorithm="HS256")


def mint_role_token(*, role: Role, sub: str, account_id: str | None = None, tier: int = 3, account_type: str = "business") -> str:
    """Mint JWT for lab/testing (compliance_officer, loan_officer, etc.)."""
    lvl = security_level_store.get().level
    now = int(time.time())
    payload = {
        "sub": sub,
        "account_id": account_id or sub,
        "role": role,
        "tier": tier,
        "account_type": account_type,
        "exp": now + settings.access_token_ttl_s,
        "iat": now,
    }
    secret = _jwt_secret_for_level(lvl)
    return jwt.encode(payload, secret, algorithm="HS256")


def require_role(*roles: Role):
    allowed = set(roles)

    def _dep(p: Principal = Depends(get_current_principal)) -> Principal:
        if p.role not in allowed:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": {
                        "code": "FORBIDDEN",
                        "message": "You are not permitted to access this resource.",
                        "reference": "NXB-ERR-403",
                        "support": "contact support@nexabank.ng",
                    }
                },
            )
        return p

    return _dep


def emit_api_audit_event(
    *,
    request: Request,
    actor_id: str,
    workflow: str,
    tools_called: list[dict[str, Any]],
    result: dict[str, Any],
    attack_detected: bool = False,
    attack_type: str | None = None,
) -> None:
    lvl = get_security_level(request)
    # Keep audit_events table consistent with agent audit shape.
    conn = connect()
    try:
        insert_audit_event(
            conn=conn,
            agent="nexabank_api",
            workflow=workflow,
            request_id=request.headers.get("x-request-id", f"api-{int(time.time() * 1000)}"),
            actor_id=actor_id,
            security_level=lvl.value,
            tools_called=tools_called,
            result=result,
            attack_detected=attack_detected,
            attack_type=attack_type,
        )
    finally:
        conn.close()

