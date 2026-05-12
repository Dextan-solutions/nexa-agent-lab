from __future__ import annotations

import json
import re
from typing import Any

import httpx

from agents.base_agent import SecurityLevel
from apis.dependencies import mint_customer_access_token
from config.security_level_store import security_level_store
from config.settings import settings
from db.sqlite import connect

_HTTP_TIMEOUT_S = 120.0


def _base_url() -> str:
    return settings.internal_api_base_url.rstrip("/")


def resolve_requester_account_number(requester_customer_id: str) -> str | None:
    rid = (requester_customer_id or "").strip()
    if not rid:
        return None
    if re.fullmatch(r"\d{10}", rid):
        return rid
    if re.fullmatch(r"ACC-\d{4}", rid.upper()):
        conn = connect()
        try:
            row = conn.execute(
                "SELECT account_number FROM customers WHERE account_id = ?",
                (rid.upper(),),
            ).fetchone()
            return str(row["account_number"]) if row else None
        finally:
            conn.close()
    conn = connect()
    try:
        row = conn.execute("SELECT account_number FROM customers WHERE id = ?", (rid,)).fetchone()
        if row:
            return str(row["account_number"])
    finally:
        conn.close()
    return None


def _bearer_for_requester(requester_customer_id: str) -> str | None:
    level = security_level_store.get().level
    if level == SecurityLevel.low:
        return None
    acct = resolve_requester_account_number(requester_customer_id)
    if not acct:
        return None
    conn = connect()
    try:
        return mint_customer_access_token(conn=conn, account_number=acct, level=level)
    finally:
        conn.close()


def http_get_account(*, account_id: str, requester_customer_id: str) -> dict[str, Any]:
    path = f"/api/v1/accounts/{account_id}"
    headers: dict[str, str] = {}
    token = _bearer_for_requester(requester_customer_id)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = httpx.get(f"{_base_url()}{path}", headers=headers, timeout=60.0)
    if r.status_code != 200:
        return {"found": False, "error": "api_error", "status_code": r.status_code}
    data = r.json()
    if isinstance(data, dict) and "error" in data:
        return {"found": False, "error": "nexa_error"}
    # Map API record → tool shape expected by Aria / healthchecks
    conn = connect()
    try:
        row = conn.execute(
            "SELECT account_id FROM customers WHERE account_number = ?",
            (data.get("account_number"),),
        ).fetchone()
        aid = str(row["account_id"]) if row and row["account_id"] else account_id
    finally:
        conn.close()
    return {
        "found": True,
        "account": {
            "account_id": aid,
            "customer_id": data.get("id"),
            "account_number": data.get("account_number"),
            "full_name": data.get("full_name"),
            "balance_ngn": data.get("balance_ngn"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "tier": f"Tier{data.get('tier', 1)}",
            "bvn": data.get("bvn"),
        },
    }


def http_create_ticket(
    *,
    customer_id: str,
    subject: str,
    message: str,
    skip_aria_queue: bool = True,
) -> dict[str, Any]:
    """POST a support ticket via the internal HTTP API.

    Agent/tool callers must pass skip_aria_queue=True so Celery does not re-queue
    aria_process_support_ticket (avoids loops with agent.run healthchecks).
    External HTTP clients use POST /api/v1/support/tickets directly with the default
    skip_aria_queue=false behavior on the server.
    """
    acct = resolve_requester_account_number(customer_id) or customer_id.strip()
    if not re.fullmatch(r"\d{10}", acct):
        return {
            "created": False,
            "error": "invalid_customer_account",
            "message": "customer_account must be a 10-digit NUBAN before calling the tickets API.",
        }
    body: dict[str, Any] = {
        "customer_account": acct,
        "subject": subject,
        "body": message,
        "channel": "web",
        "skip_aria_queue": skip_aria_queue,
    }
    r = httpx.post(f"{_base_url()}/api/v1/support/tickets", json=body, timeout=_HTTP_TIMEOUT_S)
    if r.status_code not in (200, 201):
        return {"created": False, "error": r.text[:200], "status_code": r.status_code}
    data = r.json()
    return {"created": True, "ticket_number": data.get("ticket_number"), "ticket_id": data.get("id")}


def http_post_account_freeze(
    *,
    account_id: str,
    reason: str,
    initiated_by: str,
) -> dict[str, Any]:
    """POST /api/v1/accounts/{account_id}/freeze — used by Max fraud agent (internal HTTP)."""
    body = {"reason": reason, "initiated_by": initiated_by}
    r = httpx.post(f"{_base_url()}/api/v1/accounts/{account_id}/freeze", json=body, timeout=_HTTP_TIMEOUT_S)
    try:
        data = r.json()
    except json.JSONDecodeError:
        data = {"raw": r.text[:500]}
    return {"ok": r.status_code == 200, "status_code": r.status_code, "data": data}


def http_disburse_loan(*, application_id: str, disbursement_account: str, amount: float, narration: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "disbursement_account": disbursement_account,
        "amount": amount,
    }
    if narration:
        body["narration"] = narration
    level = security_level_store.get().level
    headers: dict[str, str] = {}
    if level != SecurityLevel.low:
        from apis.dependencies import mint_role_token

        loan_officer_token = mint_role_token(
            role="loan_officer",
            sub="leo-agent-internal",
            account_id=None,
        )
        headers["Authorization"] = f"Bearer {loan_officer_token}"
    r = httpx.post(
        f"{_base_url()}/api/v1/loans/applications/{application_id}/disburse",
        json=body,
        headers=headers,
        timeout=_HTTP_TIMEOUT_S,
    )
    try:
        data = r.json()
    except json.JSONDecodeError:
        data = {"raw": r.text[:500]}
    return {"ok": r.status_code == 200, "status_code": r.status_code, "data": data}
