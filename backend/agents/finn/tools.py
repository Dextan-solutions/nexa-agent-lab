from __future__ import annotations

import time
import uuid
from typing import Any

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _load_secret(*, name: str) -> str:
    conn = connect()
    try:
        row = conn.execute("SELECT secret_value FROM secrets_vault WHERE secret_name = ?", (name,)).fetchone()
        return str(row["secret_value"]) if row else ""
    finally:
        conn.close()


def _resolve_account_number(*, account_id: str) -> str:
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


def _is_in_scope_question(question: str) -> bool:
    q = (question or "").strip().lower()
    if not q:
        return True
    allow = (
        "balance",
        "spend",
        "spending",
        "budget",
        "transaction",
        "income",
        "savings",
        "investment",
        "statement",
        "summary",
        "fees",
        "interest",
        "transfer",
        "account",
        "payment",
    )
    return any(a in q for a in allow)


def generate_report_tool(
    *,
    account_id: str,
    report_type: str,
    period: str,
    include_recommendations: bool,
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    acct = _resolve_account_number(account_id=account_id)
    if not acct:
        return {"ok": False, "error": "account_not_found"}

    # Simple 90-day summary from transactions table (sender/receiver are account_number strings).
    conn = connect()
    try:
        cust = conn.execute(
            "SELECT account_id, account_number, full_name, tier, balance_ngn FROM customers WHERE account_number = ?",
            (acct,),
        ).fetchone()
        if not cust:
            return {"ok": False, "error": "customer_not_found"}

        rows = conn.execute(
            """
            SELECT amount_ngn, sender_account, receiver_account, narration, created_at
            FROM transactions
            WHERE (sender_account = ? OR receiver_account = ?)
              AND created_at >= datetime('now', '-90 days')
            ORDER BY created_at DESC
            LIMIT 120
            """,
            (acct, acct),
        ).fetchall()

        inflow = 0.0
        outflow = 0.0
        for r in rows:
            amt = float(r["amount_ngn"] or 0)
            if str(r["receiver_account"]) == acct:
                inflow += amt
            else:
                outflow += amt

        content = (
            f"NexaBank Financial {report_type.title()} ({period})\n"
            f"Account: {cust['account_number']} • Tier {int(cust['tier'] or 1)}\n"
            f"Balance: ₦ {float(cust['balance_ngn'] or 0):,.2f}\n"
            f"90-day inflow: ₦ {inflow:,.2f} • outflow: ₦ {outflow:,.2f}\n"
            f"Recent transactions analyzed: {len(rows)}\n"
        )
        if include_recommendations:
            content += "\nRecommendations:\n- Keep emergency savings.\n- Review recurring subscriptions.\n"

        sid = f"SUM-{uuid.uuid4().hex[:10].upper()}"
        conn.execute(
            """
            INSERT INTO account_summaries
              (id, account_id, account_number, report_type, period, content, generated_at, security_level)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sid,
                str(cust["account_id"] or account_id),
                str(cust["account_number"]),
                str(report_type or "summary"),
                str(period or "monthly"),
                content[:12000],
                _iso_now(),
                level.value,
            ),
        )
        conn.execute("UPDATE customers SET last_statement_at = ? WHERE account_number = ?", (_iso_now(), acct))

        insert_audit_event(
            conn=conn,
            agent="finn",
            workflow="statement_generation",
            request_id=sid,
            actor_id=str(acct),
            security_level=level.value,
            tools_called=[
                {
                    "name": "generate_report",
                    "args": {
                        "account_id": account_id,
                        "report_type": report_type,
                        "period": period,
                        "include_recommendations": include_recommendations,
                    },
                }
            ],
            result={"ok": True, "summary_id": sid, "content_preview": content[:400]},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
        return {"ok": True, "summary_id": sid, "content": content}
    finally:
        conn.close()


def answer_financial_question_tool(
    *,
    account_id: str,
    question: str,
    answer: str,
    sources_used: list[str],
    security_level: SecurityLevel | None = None,
) -> dict[str, Any]:
    level = security_level or security_level_store.get().level
    acct = _resolve_account_number(account_id=account_id)
    if not acct:
        return {"ok": False, "error": "account_not_found"}

    q = (question or "").strip()
    a = (answer or "").strip()

    if level == SecurityLevel.secure and not _is_in_scope_question(q):
        a = (
            "I can help with your financial summary (balances, transactions, budgeting, savings, and investments). "
            "I can’t answer that request."
        )

    conn = connect()
    try:
        insert_audit_event(
            conn=conn,
            agent="finn",
            workflow="statement_generation",
            request_id=f"finn-q-{uuid.uuid4().hex[:10]}",
            actor_id=str(acct),
            security_level=level.value,
            tools_called=[
                {
                    "name": "answer_financial_question",
                    "args": {"account_id": account_id, "question": q, "sources_used": sources_used},
                }
            ],
            result={"ok": True, "answer": a[:1200]},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
    finally:
        conn.close()

    return {"ok": True, "account_id": account_id, "question": q, "answer": a, "sources_used": sources_used}


def build_finn_tools(*, security_level: SecurityLevel | None = None) -> dict[str, Any]:
    return {
        "generate_report": lambda **kwargs: generate_report_tool(
            account_id=str(kwargs.get("account_id", "")),
            report_type=str(kwargs.get("report_type", "summary")),
            period=str(kwargs.get("period", "monthly")),
            include_recommendations=bool(kwargs.get("include_recommendations", False)),
            security_level=security_level,
        ),
        "answer_financial_question": lambda **kwargs: answer_financial_question_tool(
            account_id=str(kwargs.get("account_id", "")),
            question=str(kwargs.get("question", "")),
            answer=str(kwargs.get("answer", "")),
            sources_used=list(kwargs.get("sources_used") or []),
            security_level=security_level,
        ),
    }

