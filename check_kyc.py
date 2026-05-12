import logging

from db.sqlite import connect

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    conn = connect()
    cur = conn.execute(
        "SELECT id, verification_status, uploaded_at FROM kyc_documents ORDER BY uploaded_at DESC LIMIT 10"
    )
    for r in cur.fetchall():
        logger.info("%s", tuple(r))
    conn.close()


if __name__ == "__main__":
    main()
