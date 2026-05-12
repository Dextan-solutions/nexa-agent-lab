from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Query

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from config.settings import settings
from lab.log_tail import tail_lines
from lab.objectives_registry import list_objectives


router = APIRouter(prefix="/api/lab", tags=["lab"])


@router.get("/security-level")
def get_security_level() -> dict:
    state = security_level_store.get()
    return {"ok": True, "level": state.level.value.upper(), "updated_at_ms": state.updated_at_ms}


@router.put("/security-level")
def set_security_level(level: Literal["LOW", "MEDIUM", "HARD", "SECURE"]) -> dict:
    state = security_level_store.set(SecurityLevel(level.lower()))
    return {"ok": True, "level": state.level.value.upper(), "updated_at_ms": state.updated_at_ms}


@router.get("/objectives")
def objectives() -> dict:
    return {"ok": True, "objectives": list_objectives()}


@router.get("/telemetry")
def telemetry(
    source: Literal["telemetry", "audit"] = "telemetry",
    tail: int = Query(default=200, ge=1, le=2000),
) -> dict:
    path = "/data/telemetry.jsonl" if source == "telemetry" else settings.audit_log_path
    lines = tail_lines(path, tail)
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except Exception:
            continue
    return {"ok": True, "source": source, "events": events}

