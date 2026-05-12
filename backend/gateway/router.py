from fastapi import APIRouter, Depends

from gateway.auth import Principal, require_customer


router = APIRouter()


@router.get("/gateway/ping")
def ping() -> dict:
    return {"ok": True}


@router.get("/gateway/me")
def me(principal: Principal = Depends(require_customer)) -> dict:
    return {"ok": True, "sub": principal.subject, "scope": principal.scope}

