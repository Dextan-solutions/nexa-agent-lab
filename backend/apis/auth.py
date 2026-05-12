from __future__ import annotations

import hmac
import time
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from jose import jwt
from pydantic import BaseModel, Field

from agents.base_agent import SecurityLevel
from apis.dependencies import (
    _LOW_JWT_SECRET,
    emit_api_audit_event,
    get_db,
    get_security_level,
    nexa_error,
)
from config.settings import settings


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginIn(BaseModel):
    account_number: str = Field(min_length=4, max_length=32)
    pin: str = Field(min_length=4, max_length=12)


@dataclass(frozen=True, slots=True)
class _CustomerRow:
    account_number: str
    account_id: str
    tier: int
    pin_hash: str | None
    account_type: str


def _get_customer(conn, account_number: str) -> _CustomerRow | None:
    row = conn.execute(
        "SELECT account_number, account_id, tier, pin_hash, account_type FROM customers WHERE account_number = ?",
        (account_number,),
    ).fetchone()
    if row is None:
        return None
    return _CustomerRow(
        account_number=row["account_number"],
        account_id=row["account_id"] or row["account_number"],
        tier=int(row["tier"]),
        pin_hash=row["pin_hash"],
        account_type=row["account_type"] or "current",
    )


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _jwt_secret(level: SecurityLevel) -> str:
    return _LOW_JWT_SECRET if level == SecurityLevel.low else settings.jwt_secret


@router.post("/login")
def login(
    body: LoginIn,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
) -> dict:
    acct = body.account_number.strip()

    cust = _get_customer(conn, acct)

    # --- Level-specific behaviors ---
    if level == SecurityLevel.low:
        # Accept any PIN for any account number (even non-existent accounts).
        tier = cust.tier if cust else 1
        acct_type = cust.account_type if cust else "current"
    elif level == SecurityLevel.medium:
        # Account must exist, but PIN is not validated.
        if cust is None:
            return nexa_error(
                code="ACCOUNT_NOT_FOUND",
                message="The requested account could not be located.",
                reference="NXB-ERR-404",
                status_code=404,
            )
        tier = cust.tier
        acct_type = cust.account_type
    elif level == SecurityLevel.hard:
        # Account must exist and PIN must match, but uses == (timing attack possible).
        # Same error for wrong account and wrong PIN.
        if cust is None or cust.pin_hash is None or _sha256(body.pin) != cust.pin_hash:
            return nexa_error(
                code="INVALID_CREDENTIALS",
                message="The credentials provided are invalid.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        tier = cust.tier
        acct_type = cust.account_type
    else:  # SECURE
        # Account must exist and PIN must match with constant-time comparison.
        # Same error for wrong account and wrong PIN.
        if cust is None or cust.pin_hash is None:
            return nexa_error(
                code="INVALID_CREDENTIALS",
                message="The credentials provided are invalid.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        pin_ok = hmac.compare_digest(_sha256(body.pin), cust.pin_hash)
        if not pin_ok:
            return nexa_error(
                code="INVALID_CREDENTIALS",
                message="The credentials provided are invalid.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        tier = cust.tier
        acct_type = cust.account_type

    now = int(time.time())
    payload = {
        "sub": acct,
        "account_id": cust.account_id if cust else acct,
        "role": "customer",
        "tier": tier,
        "account_type": acct_type,
        "exp": now + settings.access_token_ttl_s,
        "iat": now,
    }
    token = jwt.encode(payload, _jwt_secret(level), algorithm="HS256")

    # Attack detection: flag only when PIN would fail at SECURE level.
    would_fail_secure = (
        cust is None
        or cust.pin_hash is None
        or _sha256(body.pin) != cust.pin_hash
    )
    is_attack = level != SecurityLevel.secure and would_fail_secure

    emit_api_audit_event(
        request=request,
        actor_id=acct,
        workflow="auth.login",
        tools_called=[],
        result={"ok": True, "account_number": acct, "tier": tier},
        attack_detected=is_attack,
        attack_type="weak_auth" if is_attack else None,
    )

    return {"ok": True, "access_token": token, "token_type": "bearer"}

