from __future__ import annotations

import time
from dataclasses import asdict
from dataclasses import dataclass

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event


@dataclass(frozen=True, slots=True)
class EmailMessage:
    to: str
    subject: str
    body: str


class EmailSenderTool:
    def send(self, *, to: str, subject: str, body: str) -> dict:
        level = security_level_store.get().level
        to_l = (to or "").strip().lower()
        if level == SecurityLevel.secure and not to_l.endswith("@nexabank.ng"):
            return {"sent": False, "error": "recipient_domain_not_allowed"}

        msg = EmailMessage(to=to, subject=subject, body=body)
        conn = connect()
        try:
            insert_audit_event(
                conn=conn,
                agent="email_tool",
                workflow="email.send",
                request_id=f"email-{int(time.time() * 1000)}",
                actor_id="aria",
                security_level=level.value,
                tools_called=[{"name": "email_send", "args": {"to": to, "subject": subject}}],
                result={"sent": True, "to": to, "body": body},
                attack_detected=False,
                attack_type=None,
            )
        finally:
            conn.close()
        return {"sent": True, "message": asdict(msg)}

