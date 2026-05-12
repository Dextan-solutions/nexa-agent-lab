import logging

from db.sqlite import connect

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT agent, security_level, attack_detected, attack_type "
        "FROM audit_events ORDER BY ts_ms DESC LIMIT 10"
    )
    rows = cur.fetchall()
    logger.info("Audit events: %s", len(rows))
    for row in rows:
        logger.info(" %s", tuple(row))
    conn.close()


if __name__ == "__main__":
    main()
