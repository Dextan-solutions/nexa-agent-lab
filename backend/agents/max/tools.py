from __future__ import annotations

import json
import time
import uuid
from typing import Any

from db.sqlite import connect
from tools.banking_client import http_post_account_freeze


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def insert_compliance_alert(
    *,
    alert_type: str,
    account_id: str,
    transaction_id: str | None,
    reason: str,
    created_by_agent: str,
    security_level: str,
) -> dict[str, Any]:
    aid = f"alert-{uuid.uuid4().hex[:16]}"
    conn = connect()
    try:
        conn.execute(
            """
            INSERT INTO compliance_alerts
              (id, alert_type, account_id, transaction_id, reason,
               created_by_agent, security_level, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (aid, alert_type, account_id, transaction_id, reason, created_by_agent, security_level, _iso_now()),
        )
        conn.commit()
        return {"ok": True, "alert_id": aid}
    finally:
        conn.close()


def transaction_mark_reviewed(*, transaction_id: str, outcome: str, reasoning: str) -> dict[str, Any]:
    conn = connect()
    try:
        conn.execute(
            "UPDATE transactions SET agent_action = ?, flagged_by_agent = ? WHERE id = ?",
            (outcome, 1 if outcome in {"suspicious", "fraudulent"} else 0, transaction_id),
        )
        conn.commit()
        return {"ok": True, "transaction_id": transaction_id, "outcome": outcome, "reasoning": reasoning}
    finally:
        conn.close()


def account_freeze_tool(
    *,
    account_id: str,
    reason: str,
    fraud_score: float,
    initiated_by: str,
    security_level: str,
    require_human_approval_for_freeze: bool,
    escalate_freeze_to_alert: bool,
    transaction_id: str | None = None,
) -> dict[str, Any]:
    aid = (account_id or "").strip()
    conn = connect()
    try:
        row = conn.execute(
            "SELECT account_number FROM customers WHERE account_id = ? OR account_number = ?",
            (aid, aid),
        ).fetchone()
        account_exists = row is not None
    finally:
        conn.close()

    if not account_exists:
        return {
            "ok": False,
            "error": "account_not_found",
            "account_id": aid,
        }

    if (
        escalate_freeze_to_alert
        or require_human_approval_for_freeze
        or (security_level or "").lower() == "secure"
    ):
        return insert_compliance_alert(
            alert_type="pending_freeze",
            account_id=aid,
            transaction_id=transaction_id,
            reason=f"{reason} (fraud_score={fraud_score})",
            created_by_agent="max",
            security_level=security_level,
        )
    return http_post_account_freeze(account_id=aid, reason=reason, initiated_by=initiated_by)


def account_review_flag_tool(
    *,
    account_id: str,
    reason: str,
    transaction_id: str,
    security_level: str,
) -> dict[str, Any]:
    return insert_compliance_alert(
        alert_type="manual_review",
        account_id=account_id,
        transaction_id=transaction_id,
        reason=reason,
        created_by_agent="max",
        security_level=security_level,
    )


def parse_internal_memo(row: dict[str, Any]) -> str:
    raw = row.get("internal_flags") or "{}"
    try:
        d = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except json.JSONDecodeError:
        return ""
    return str(d.get("memo") or "")
