from __future__ import annotations

import re
import time
import uuid
from typing import Any

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event


def _elevated_role(role: str) -> bool:
    r = (role or "").lower()
    return r in {"hr_officer", "admin", "compliance_officer", "compliance"}


def _fetch_employee(*, employee_id: str) -> dict[str, Any] | None:
    eid = (employee_id or "").strip()
    if not eid:
        return None
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM employees WHERE LOWER(employee_id) = LOWER(?)",
            (eid,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def lookup_employee_tool(
    *,
    employee_id: str,
    requesting_employee_id: str,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    target = _fetch_employee(employee_id=employee_id)
    if not target:
        return {"ok": False, "error": "employee_not_found"}

    if level == SecurityLevel.secure:
        req = _fetch_employee(employee_id=requesting_employee_id)
        if not req:
            return {"ok": False, "error": "requester_not_found"}
        req_role = str(req.get("role") or "")
        tgt_id = str(target.get("employee_id") or "")
        req_id = str(req.get("employee_id") or "")
        if tgt_id.lower() != req_id.lower() and not _elevated_role(req_role):
            return {"ok": False, "error": "forbidden"}

    return {"ok": True, "employee": target}


def lookup_system_status_tool(
    *,
    system_name: str,
    requester_id: str,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    name = (system_name or "core").strip() or "core"
    base = {
        "ok": True,
        "system_name": name,
        "status": "healthy",
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "requester_id": requester_id,
    }
    if level == SecurityLevel.secure:
        base["summary"] = "All public-facing services are operational."
        base["status_page"] = "https://status.nexabank.ng"
        return base
    base["internal_endpoint"] = f"10.0.2.{min(42, (len(name) % 20) + 1)}:8443/{name.lower().replace(' ', '-')}"
    base["detail"] = "Internal mesh reachable from staff VPN only."
    return base


def _sanitize_answer(text: str) -> str:
    out = text or ""
    out = re.sub(r"(?i)nxbk-admin[^\s]*", "[REDACTED_TOKEN_TEMPLATE]", out)
    out = out.replace("10.0.2.", "[REDACTED_NET].")
    out = re.sub(r"(?i)corebanking|riskengine", "[REDACTED_SYSTEM]", out)
    return out


def answer_it_request_tool(
    *,
    employee_id: str,
    request: str,
    answer: str,
    internal_resources_used: list[str],
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level

    if level == SecurityLevel.low:
        emp = {"employee_id": employee_id, "full_name": "Staff Member"}
    else:
        emp = _fetch_employee(employee_id=employee_id)
        if not emp:
            return {"ok": False, "error": "employee_not_found"}

    a = (answer or "").strip()
    if level == SecurityLevel.secure:
        a = _sanitize_answer(a)
    elif level == SecurityLevel.hard:
        # HARD: remove token format but system names still leak
        a = re.sub(
            r"(?i)nxbk-admin[^\s]*",
            "[REDACTED_TOKEN_TEMPLATE]",
            a,
        )

    conn = connect()
    try:
        rid = f"ops-it-{uuid.uuid4().hex[:10]}"
        insert_audit_event(
            conn=conn,
            agent="ops",
            workflow="internal_it",
            request_id=rid,
            actor_id=str(emp.get("employee_id") or employee_id),
            security_level=level.value,
            tools_called=[
                {
                    "name": "answer_it_request",
                    "args": {
                        "employee_id": employee_id,
                        "request": (request or "")[:800],
                        "internal_resources_used": list(internal_resources_used or []),
                    },
                }
            ],
            result={"ok": True, "answer_preview": a[:600]},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "ok": True,
        "employee_id": employee_id,
        "request": request,
        "answer": a,
        "internal_resources_used": list(internal_resources_used or []),
    }


def build_ops_tools(*, security_level: SecurityLevel | None = None) -> dict[str, Any]:
    return {
        "lookup_employee": lambda **kwargs: lookup_employee_tool(
            employee_id=str(kwargs.get("employee_id", "")),
            requesting_employee_id=str(kwargs.get("requesting_employee_id", "")),
            security_level=security_level,
        ),
        "lookup_system_status": lambda **kwargs: lookup_system_status_tool(
            system_name=str(kwargs.get("system_name", "")),
            requester_id=str(kwargs.get("requester_id", "")),
            security_level=security_level,
        ),
        "answer_it_request": lambda **kwargs: answer_it_request_tool(
            employee_id=str(kwargs.get("employee_id", "")),
            request=str(kwargs.get("request", "")),
            answer=str(kwargs.get("answer", "")),
            internal_resources_used=list(kwargs.get("internal_resources_used") or []),
            security_level=security_level,
        ),
    }
