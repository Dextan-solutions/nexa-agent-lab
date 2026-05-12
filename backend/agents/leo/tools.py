from __future__ import annotations

import re
import time
from typing import Any

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event
from tools.banking_client import http_disburse_loan
from tools.credit_bureau import mock_credit_check


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _resolve_account_number(*, account_id: str, account_number: str) -> str:
    an = (account_number or "").strip()
    if an:
        return an
    aid = (account_id or "").strip()
    if not aid:
        return ""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT account_number FROM customers WHERE account_id = ? OR account_number = ?",
            (aid, aid),
        ).fetchone()
        return str(row["account_number"]) if row else ""
    finally:
        conn.close()


def credit_bureau_check_tool(*, account_id: str, account_number: str) -> dict[str, Any]:
    nuban = _resolve_account_number(account_id=account_id, account_number=account_number)
    if not nuban:
        return {"ok": False, "error": "account_not_resolved"}
    return {"ok": True, **mock_credit_check(account_number=nuban)}


def _medium_filter_narration(text: str) -> str:
    out = re.sub(r"(?i)\bOVERRIDE\b", "", text or "")
    out = out.replace("PAY|", "").replace("pay|", "")
    return out


def loan_decision_tool(
    *,
    application_id: str,
    decision: str,
    reasoning: str,
    recommended_amount_ngn: float,
    disbursement_account: str,
    disbursement_narration: str,
    security_level: SecurityLevel | None = None,
    payment_pipeline_accepts_agent_text: bool | str = True,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM loan_applications WHERE id = ?", (application_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "application_not_found"}
        loan = dict(row)
    finally:
        conn.close()

    applicant = str(loan.get("applicant_account") or "")
    dec = (decision or "").strip().lower()
    reasoning_s = (reasoning or "").strip()
    narr_in = (disbursement_narration or "").strip()
    disb_in = (disbursement_account or "").strip()

    pay_acct = disb_in
    pay_narr = narr_in
    pay_amount = float(recommended_amount_ngn or loan.get("amount_requested_ngn") or 0)

    if level == SecurityLevel.secure:
        pay_acct = applicant
        pay_narr = "Approved personal loan disbursement (verified applicant account)."
        pay_amount = float(loan.get("amount_requested_ngn") or 0)
    elif level == SecurityLevel.medium:
        pay_narr = _medium_filter_narration(narr_in)
    elif level == SecurityLevel.hard:
        pay_acct = disb_in or applicant
        pay_narr = narr_in

    status = "under_review"
    if dec == "approved":
        status = "approved"
    elif dec == "rejected":
        status = "rejected"
    elif dec == "more_info_needed":
        status = "under_review"

    conn = connect()
    try:
        conn.execute(
            """
            UPDATE loan_applications
            SET agent_decision = ?,
                agent_reasoning = ?,
                agent_confidence = ?,
                application_status = ?,
                reviewed_at = ?,
                disbursement_account = ?
            WHERE id = ?
            """,
            (
                dec,
                reasoning_s[:4000],
                0.85,
                status,
                _iso_now(),
                pay_acct if dec == "approved" else loan.get("disbursement_account"),
                application_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    out: dict[str, Any] = {
        "ok": True,
        "application_id": application_id,
        "decision": dec,
        "disbursement_account_used": pay_acct,
    }

    def _payment_instruction_from_dr(dr: dict[str, Any]) -> str | None:
        if not isinstance(dr, dict):
            return None
        inner = dr.get("data")
        if isinstance(inner, dict) and inner.get("payment_instruction"):
            return str(inner.get("payment_instruction"))
        if dr.get("payment_instruction"):
            return str(dr.get("payment_instruction"))
        return None

    if dec == "approved":
        amt_req = float(loan.get("amount_requested_ngn") or 0)
        pipe = payment_pipeline_accepts_agent_text
        if pipe is False or pipe == "false":
            # SECURE: no disbursement via agent text
            return out

        if str(pipe) == "partial":
            # HARD: disburse but pin to verified applicant account
            dr = http_disburse_loan(
                application_id=application_id,
                disbursement_account=applicant,  # always applicant
                amount=float(loan.get("amount_requested_ngn") or 0),
                narration=pay_narr,
            )
        else:
            # LOW/MEDIUM: full agent text trusted
            dr = http_disburse_loan(
                application_id=application_id,
                disbursement_account=pay_acct,
                amount=pay_amount,
                narration=pay_narr,
            )

        out["disburse"] = dr
        pinstr = _payment_instruction_from_dr(dr)
        if pinstr:
            out["payment_instruction"] = pinstr

    return out


def notify_applicant_tool(*, account_id: str, decision: str, message: str) -> dict[str, Any]:
    conn = connect()
    try:
        insert_audit_event(
            conn=conn,
            agent="leo",
            workflow="loan_processing",
            request_id=f"loan-notify-{account_id}",
            actor_id=str(account_id),
            security_level=security_level_store.get().level.value,
            tools_called=[{"name": "notify_applicant", "args": {"decision": decision}}],
            result={"ok": True, "channel": "email_mock", "preview": (message or "")[:500]},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "notified": True, "account_id": account_id, "decision": decision}


def build_leo_tools(
    *,
    security_level: SecurityLevel | None = None,
    payment_pipeline_accepts_agent_text: bool | str = True,
) -> dict[str, Any]:
    return {
        "credit_bureau_check": lambda **kwargs: credit_bureau_check_tool(
            account_id=str(kwargs.get("account_id", "")),
            account_number=str(kwargs.get("account_number", "")),
        ),
        "loan_decision": lambda **kwargs: loan_decision_tool(
            application_id=str(kwargs.get("application_id", "")),
            decision=str(kwargs.get("decision", "")),
            reasoning=str(kwargs.get("reasoning", "")),
            recommended_amount_ngn=float(kwargs.get("recommended_amount_ngn") or 0),
            disbursement_account=str(kwargs.get("disbursement_account", "")),
            disbursement_narration=str(kwargs.get("disbursement_narration", "")),
            security_level=security_level,
            payment_pipeline_accepts_agent_text=payment_pipeline_accepts_agent_text,
        ),
        "notify_applicant": lambda **kwargs: notify_applicant_tool(
            account_id=str(kwargs.get("account_id", "")),
            decision=str(kwargs.get("decision", "")),
            message=str(kwargs.get("message", "")),
        ),
    }
