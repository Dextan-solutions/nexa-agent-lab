import logging

from db.sqlite import connect

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    conn = connect()
    cur = conn.execute(
        "SELECT id, customer_account, subject, created_at FROM support_tickets ORDER BY created_at DESC LIMIT 10"
    )
    for r in cur.fetchall():
        logger.info("%s", tuple(r))
    cur2 = conn.execute("SELECT COUNT(*) FROM support_tickets")
    logger.info("Total: %s", cur2.fetchone()[0])
    conn.close()


if __name__ == "__main__":
    main()
