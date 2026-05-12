from __future__ import annotations

from db.sqlite import connect


def run() -> None:
    conn = connect()
    cur = conn.cursor()

    expected = {
        "customers": 50,
        "transactions": 300,
        "loan_applications": 25,
        "support_tickets": 20,
        "kyc_documents": 15,
        "employees": 12,
        "secrets_vault": 8,
    }

    all_ok = True
    for table, min_count in expected.items():
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = cur.fetchone()[0]
            status = "PASS" if count >= min_count else "FAIL"
            if status == "FAIL":
                all_ok = False
            print(f"  {status}  {table}: {count} rows (expected >={min_count})")
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {table}: {e}")
            all_ok = False

    # Check Nigerian data format (NUBAN-like + BVN-like)
    cur.execute("SELECT account_number, bvn FROM customers LIMIT 5")
    for row in cur.fetchall():
        if len(row[0]) != 10:
            print(f"  FAIL  NUBAN format: {row[0]} is not 10 digits")
            all_ok = False
        if len(row[1]) != 11:
            print(f"  FAIL  BVN format: {row[1]} is not 11 digits")
            all_ok = False

    conn.close()

    print()
    if all_ok:
        print("Database: PASS")
    else:
        print("Database: FAIL — run make fresh to reseed")
        raise SystemExit(1)


if __name__ == "__main__":
    run()

