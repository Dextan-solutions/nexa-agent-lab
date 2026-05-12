from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from db.sqlite import connect


@dataclass(frozen=True, slots=True)
class AccountRecord:
    account_id: str
    customer_id: str
    account_number: str
    full_name: str
    balance_ngn: int
    email: str
    phone: str
    tier: str


class AccountLookupTool:
    """Mock account lookup.

    Ownership checks are controlled by the security level engine; in LOW/MEDIUM,
    this is intentionally vulnerable to BOLA-style access.
    """

    def __init__(self) -> None:
        # Small in-memory seed; Step 5 will replace with dataset/SQLite.
        self._accounts: dict[str, AccountRecord] = {
            "acc_1001": AccountRecord(
                account_id="acc_1001",
                customer_id="cus_2001",
                account_number="0201001234",
                full_name="Chiamaka Okafor",
                balance_ngn=245_500,
                email="chiamaka.okafor@nexabank.ng",
                phone="+2348012345678",
                tier="Gold",
            ),
            "acc_1002": AccountRecord(
                account_id="acc_1002",
                customer_id="cus_2002",
                account_number="0201005678",
                full_name="Ibrahim Abdullahi",
                balance_ngn=9_870_200,
                email="ibrahim.abdullahi@nexabank.ng",
                phone="+2348098765432",
                tier="Platinum",
            ),
        }

    def lookup(
        self,
        *,
        account_id: str,
        requester_customer_id: str,
        ownership_check: bool,
    ) -> Mapping[str, Any]:
        # Training convenience: allow "ACC-0047" style identifiers used in lab objectives.
        # These map deterministically to seeded customer rows.
        m = re.fullmatch(r"ACC-(\d{4})", (account_id or "").strip().upper())
        if m:
            idx = int(m.group(1))
            # Our seed uses NUBAN-like: 0 + 9-digit index
            acct_num = f"0{idx:09d}"
            try:
                conn = connect()
                try:
                    row = conn.execute(
                        """
                        SELECT id, account_number, full_name, email, phone, balance_ngn, tier
                        FROM customers
                        WHERE account_number = ?
                        """,
                        (acct_num,),
                    ).fetchone()
                finally:
                    conn.close()
                if row is None:
                    return {"found": False}
                customer_id = row["id"]
                if ownership_check and customer_id != requester_customer_id:
                    return {"found": False, "error": "not_found"}
                return {
                    "found": True,
                    "account": {
                        "account_id": account_id,
                        "customer_id": customer_id,
                        "account_number": row["account_number"],
                        "full_name": row["full_name"],
                        "balance_ngn": row["balance_ngn"],
                        "email": row["email"],
                        "phone": row["phone"],
                        "tier": f"Tier{row['tier']}",
                    },
                }
            except Exception:
                # Fall through to in-memory behavior if DB isn't available.
                pass

        rec = self._accounts.get(account_id)
        if rec is None:
            return {"found": False}

        if ownership_check and rec.customer_id != requester_customer_id:
            return {"found": False, "error": "not_found"}

        # Vulnerable path: returns full record including fields not needed for support.
        return {
            "found": True,
            "account": {
                "account_id": rec.account_id,
                "customer_id": rec.customer_id,
                "account_number": rec.account_number,
                "full_name": rec.full_name,
                "balance_ngn": rec.balance_ngn,
                "email": rec.email,
                "phone": rec.phone,
                "tier": rec.tier,
            },
        }

