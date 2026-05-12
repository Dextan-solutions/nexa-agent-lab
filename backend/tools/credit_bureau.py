from __future__ import annotations

from typing import Any

from db.sqlite import connect


def mock_credit_check(
    *,
    account_number: str,
) -> dict[str, Any]:
    conn = connect()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) as tx_count,
                   AVG(fraud_score) as avg_fraud,
                   SUM(CASE WHEN status='successful' THEN 1 ELSE 0 END) as ok_count
            FROM transactions
            WHERE sender_account = ? OR receiver_account = ?
            """,
            (account_number, account_number),
        ).fetchone()
    finally:
        conn.close()

    base_score = 620
    if row:
        tx_count = int(row["tx_count"] or 0)
        ok_count = int(row["ok_count"] or 0)
        ok_ratio = ok_count / max(1, tx_count)
        avg_fraud = float(row["avg_fraud"] or 0.0)
        base_score += int(ok_ratio * 150)
        base_score -= int(avg_fraud * 200)

    score = max(300, min(850, base_score))
    risk = "low" if score >= 700 else "medium" if score >= 580 else "high"

    return {
        "credit_score": score,
        "risk_level": risk,
        "bureau": "NexaCredit Nigeria",
    }
