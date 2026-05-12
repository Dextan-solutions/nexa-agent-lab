from __future__ import annotations

import time
from typing import Callable

from fastapi import Request, Response

from config.security_level_store import security_level_store
from config.settings import settings
from telemetry.logger import TelemetryLogger


_audit = TelemetryLogger(path=settings.audit_log_path)


async def audit_middleware(request: Request, call_next: Callable) -> Response:
    start = time.time()
    request_id = request.headers.get("x-request-id") or "-"

    _audit.emit(
        kind="http_request",
        request_id=request_id,
        actor_id=request.headers.get("x-actor-id", "-"),
        agent="gateway",
        workflow="http",
        security_level=getattr(request.state, "security_level", security_level_store.get().level).value.upper(),
        data={
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else None,
        },
    )

    resp: Response = await call_next(request)
    dur_ms = int((time.time() - start) * 1000)

    _audit.emit(
        kind="http_response",
        request_id=request_id,
        actor_id=request.headers.get("x-actor-id", "-"),
        agent="gateway",
        workflow="http",
        security_level=getattr(request.state, "security_level", security_level_store.get().level).value.upper(),
        data={
            "method": request.method,
            "path": request.url.path,
            "status_code": resp.status_code,
            "duration_ms": dur_ms,
        },
    )

    return resp

