from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, HTTPException, Request
from jose import JWTError, jwt

from config.security_level_store import security_level_store
from config.settings import settings


Scope = Literal["customer", "staff", "admin"]


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    scope: Scope


def _verify_jwt(token: str) -> Principal:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"verify_aud": True},
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail="invalid_token") from e

    sub = payload.get("sub")
    scope = payload.get("scope", "customer")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(status_code=401, detail="invalid_token")
    if scope not in {"customer", "staff", "admin"}:
        scope = "customer"
    return Principal(subject=sub, scope=scope)  # type: ignore[arg-type]


def get_principal(request: Request) -> Principal:
    lvl = getattr(request.state, "security_level", security_level_store.get().level)
    level = (lvl.value.upper() if hasattr(lvl, "value") else str(lvl).upper())

    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    else:
        token = ""

    if level == "LOW":
        # Intentionally weak: accept missing/invalid JWT and fall back to header-provided identity.
        header_sub = request.headers.get("x-customer-id") or request.headers.get("x-actor-id") or "anonymous"
        try:
            return _verify_jwt(token) if token else Principal(subject=header_sub, scope="customer")
        except HTTPException:
            return Principal(subject=header_sub, scope="customer")

    # MEDIUM/HARD/SECURE: require JWT
    if not token:
        raise HTTPException(status_code=401, detail="missing_token")
    return _verify_jwt(token)


def require_customer(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.scope not in {"customer", "admin"}:
        raise HTTPException(status_code=403, detail="forbidden")
    return principal


