from __future__ import annotations

import time
import uuid
from typing import Any

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def document_verify_tool(
    *,
    document_id: str,
    customer_account: str,
    decision: str,
    reasoning: str,
    tier_upgrade: int | None,
    compliance_notes: str,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    dec = (decision or "").strip().lower()
    tier_out: int | None = None
    if isinstance(tier_upgrade, (int, float)) and not isinstance(tier_upgrade, bool):
        tier_out = int(tier_upgrade)
        if tier_out not in {1, 2, 3}:
            tier_out = None

    conn = connect()
    try:
        row = conn.execute("SELECT * FROM kyc_documents WHERE id = ?", (document_id,)).fetchone()
        if row is None:
            return {"ok": False, "error": "document_not_found"}

        status = "pending"
        if dec in {"verified", "approved"}:
            status = "verified"
        elif dec == "flagged":
            status = "flagged"
        elif dec == "rejected":
            status = "rejected"
        elif dec in {"needs_more_info", "more_info_needed"}:
            status = "needs_more_info"

        conn.execute(
            "UPDATE kyc_documents SET verification_status = ?, agent_notes = ?, verified_at = ? WHERE id = ?",
            (status, (compliance_notes or reasoning or "")[:4000], _iso_now(), document_id),
        )

        if status == "verified" and tier_out is not None:
            conn.execute(
                "UPDATE customers SET tier = ?, kyc_status = 'verified' WHERE account_number = ?",
                (tier_out, str(customer_account)),
            )

        insert_audit_event(
            conn=conn,
            agent="vera",
            workflow="kyc_verification",
            request_id=str(document_id),
            actor_id=str(customer_account),
            security_level=level.value,
            tools_called=[
                {
                    "name": "document_verify",
                    "args": {
                        "document_id": document_id,
                        "customer_account": customer_account,
                        "decision": dec,
                        "tier_upgrade": tier_out,
                    },
                    "result": {"ok": True, "status": status},
                }
            ],
            result={"ok": True, "document_id": document_id, "verification_status": status, "tier_upgrade": tier_out},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "ok": True,
        "document_id": document_id,
        "customer_account": customer_account,
        "decision": dec,
        "verification_status": status,
        "tier_upgrade": tier_out,
    }


def compliance_flag_tool(
    *,
    document_id: str,
    customer_account: str,
    reason: str,
    risk_level: str,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    conn = connect()
    try:
        # Mark KYC doc as flagged.
        conn.execute(
            "UPDATE kyc_documents SET verification_status = 'flagged', agent_notes = ?, verified_at = ? WHERE id = ?",
            ((reason or "")[:4000], _iso_now(), document_id),
        )
        # Create compliance alert.
        alert_id = f"CA-{uuid.uuid4().hex[:10]}"
        conn.execute(
            """
            INSERT INTO compliance_alerts
              (id, alert_type, account_id, transaction_id, reason, created_by_agent, security_level, status, created_at)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                alert_id,
                "kyc_flag",
                str(customer_account),
                str(document_id),
                f"[{risk_level}] {(reason or '').strip()}"[:4000],
                "vera",
                level.value,
                _iso_now(),
            ),
        )

        insert_audit_event(
            conn=conn,
            agent="vera",
            workflow="kyc_verification",
            request_id=str(document_id),
            actor_id=str(customer_account),
            security_level=level.value,
            tools_called=[
                {
                    "name": "compliance_flag",
                    "args": {
                        "document_id": document_id,
                        "customer_account": customer_account,
                        "reason": reason,
                        "risk_level": risk_level,
                    },
                }
            ],
            result={"ok": True, "alert_id": alert_id, "document_id": document_id},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "document_id": document_id, "status": "flagged"}


def build_vera_tools(
    *,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    return {
        "document_verify": lambda **kwargs: document_verify_tool(
            document_id=str(kwargs.get("document_id", "")),
            customer_account=str(kwargs.get("customer_account", "")),
            decision=str(kwargs.get("decision", "")),
            reasoning=str(kwargs.get("reasoning", "")),
            tier_upgrade=(kwargs.get("tier_upgrade") if kwargs.get("tier_upgrade") is not None else None),
            compliance_notes=str(kwargs.get("compliance_notes", "")),
            security_level=security_level,
        ),
        "compliance_flag": lambda **kwargs: compliance_flag_tool(
            document_id=str(kwargs.get("document_id", "")),
            customer_account=str(kwargs.get("customer_account", "")),
            reason=str(kwargs.get("reason", "")),
            risk_level=str(kwargs.get("risk_level", "medium")),
            security_level=security_level,
        ),
    }

