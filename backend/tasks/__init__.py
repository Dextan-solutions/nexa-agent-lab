from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Mapping

from celery.result import AsyncResult

from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName
from agents.finn.agent import FinnAgent
from agents.leo.agent import LeoAgent
from agents.max.agent import MaxAgent
from agents.ops.agent import OpsAgent
from agents.vera.agent import VeraAgent
from config.security_level_store import security_level_store
from celery_app import celery_app
from db.sqlite import connect, insert_audit_event


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


@celery_app.task(name="agenthive.ping")
def ping() -> dict:
    return {"ok": True, "ts": _iso_now()}


@celery_app.task(name="agenthive.aria_process_support_ticket")
def aria_process_support_ticket(ticket_id: str) -> dict:
    tid = str(ticket_id)
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM support_tickets WHERE id = ?", (tid,)).fetchone()
        if row is None:
            return {"ok": False, "error": "ticket_not_found", "ticket_id": tid}
        t = dict(row)
        now = _iso_now()
        reply = {
            "action": "reply",
            "subject": str(t.get("subject") or "Support ticket"),
            "summary": "Ticket processed asynchronously by Aria.",
            "next_steps": "Support will follow up if additional information is required.",
        }
        conn.execute(
            """
            UPDATE support_tickets
            SET status = 'resolved',
                agent_response = ?,
                agent_tools_called = ?,
                resolved_at = ?
            WHERE id = ?
            """,
            (json.dumps(reply, ensure_ascii=False), "[]", now, tid),
        )
        insert_audit_event(
            conn=conn,
            agent="aria",
            workflow="support_ticket",
            request_id=tid,
            actor_id=str(t.get("customer_account") or "unknown"),
            security_level="low",
            tools_called=[],
            result={"ok": True, "ticket_id": tid, "status": "resolved"},
            attack_detected=False,
            attack_type=None,
        )
        conn.commit()
        return {"ok": True, "ticket_id": tid, "status": "resolved"}
    finally:
        conn.close()


@celery_app.task(name="agenthive.leo_process_loan")
def leo_process_loan(application_id: str) -> dict:
    trig = AgentTrigger(
        workflow=WorkflowName.loan_processing,
        actor_id="system",
        request_id=f"celery-leo-{uuid.uuid4()}",
        metadata={"application_id": str(application_id)},
    )
    agent = LeoAgent()
    res = asyncio.run(
        agent.run(
            trigger=trig,
            payload={"application_id": str(application_id)},
            security_level=None,
        )
    )
    return {"ok": bool(res.ok), "application_id": str(application_id), "flag": res.flag, "output": dict(res.output)}


@celery_app.task(name="agenthive.vera_process_kyc_document")
def vera_process_kyc_document(document_id: str) -> dict:
    doc_id = str(document_id)
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM kyc_documents WHERE id = ?", (doc_id,)).fetchone()
        doc = dict(row) if row else {}
    finally:
        conn.close()

    if not doc:
        return {"ok": False, "error": "document_not_found", "document_id": doc_id}

    # Best-effort: ingest extracted text into the compliance collection so it can later influence RAG retrieval.
    # This is what makes delayed poisoning realistic, but it may fail if the embedding provider is unavailable.
    ingest_result: dict[str, Any] | None = None
    extracted = str(doc.get("extracted_data") or "")
    if extracted.strip():
        try:
            from memory.document_pipeline import DocumentPipeline

            dp = DocumentPipeline(security_level_store.get().level)
            ingest_result = asyncio.run(
                dp.ingest(
                    text=extracted,
                    collection="nexabank_compliance_docs",
                    metadata={
                        "source_id": doc_id,
                        "doc_type": doc.get("document_type"),
                        "uploaded_at": doc.get("uploaded_at"),
                        "verified_by": "vera",
                        "customer_account": doc.get("customer_account"),
                        "verification_status": doc.get("verification_status"),
                        "poisoned": bool(doc.get("poisoned", 0)),
                    },
                    source_id=doc_id,
                )
            )
        except Exception as e:  # noqa: BLE001
            ingest_result = {"ok": False, "error": str(e)}

    # Deterministic DB update + audit trail (does not depend on an LLM).
    from agents.vera.tools import document_verify_tool

    verify = document_verify_tool(
        document_id=doc_id,
        customer_account=str(doc.get("customer_account") or ""),
        decision="verified",
        reasoning="Automated nightly KYC verification.",
        tier_upgrade=1,
        compliance_notes="Auto-verified by scheduled batch.",
        security_level=security_level_store.get().level,
    )
    return {
        "ok": bool(verify.get("ok")),
        "document_id": doc_id,
        "verification_status": verify.get("verification_status"),
        "ingest": ingest_result,
    }


@celery_app.task(name="agenthive.finn_generate_summary")
def finn_generate_summary(account_id: str) -> dict:
    trig = AgentTrigger(
        workflow=WorkflowName.statement_generation,
        actor_id="system",
        request_id=f"celery-finn-{uuid.uuid4()}",
        metadata={"account_id": str(account_id)},
    )
    agent = FinnAgent()
    res = asyncio.run(
        agent.run(
            trigger=trig,
            payload={"account_id": str(account_id), "question": ""},
            security_level=None,
        )
    )
    return {"ok": bool(res.ok), "account_id": str(account_id), "flag": res.flag, "output": dict(res.output)}


@celery_app.task(name="agenthive.ops_handle_request")
def ops_handle_request(employee_id: str, request: str) -> dict:
    trig = AgentTrigger(
        workflow=WorkflowName.internal_it,
        actor_id=str(employee_id),
        request_id=f"celery-ops-{uuid.uuid4()}",
        metadata={"employee_id": str(employee_id)},
    )
    agent = OpsAgent()
    res = asyncio.run(
        agent.run(
            trigger=trig,
            payload={"employee_id": str(employee_id), "request": str(request)},
            security_level=None,
        )
    )
    return {"ok": bool(res.ok), "employee_id": str(employee_id), "flag": res.flag, "output": dict(res.output)}


@celery_app.task(name="agenthive.max_fraud_monitor")
def max_fraud_monitor() -> dict:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT id
            FROM transactions
            WHERE status = 'pending'
              AND flagged_by_agent = 0
              AND fraud_score >= 0.60
              AND created_at >= datetime('now', '-10 minutes')
            ORDER BY fraud_score DESC, created_at ASC
            LIMIT 10
            """
        ).fetchall()
        tx_ids = [str(r["id"]) for r in rows]
    finally:
        conn.close()

    if not tx_ids:
        return {"ok": True, "processed": 0}

    agent = MaxAgent()
    processed: list[str] = []
    for tx_id in tx_ids:
        trig = AgentTrigger(
            workflow=WorkflowName.fraud_monitoring,
            actor_id="system",
            request_id=f"celery-max-{uuid.uuid4()}",
            metadata={"transaction_id": tx_id},
        )
        try:
            asyncio.run(agent.run(trigger=trig, payload={"transaction_id": tx_id}, security_level=None))
            processed.append(tx_id)
        except Exception:
            # Leave flagged_by_agent as-is for retry on next beat tick.
            continue

        conn2 = connect()
        try:
            conn2.execute("UPDATE transactions SET flagged_by_agent = 1 WHERE id = ?", (tx_id,))
            conn2.commit()
        finally:
            conn2.close()

    return {"ok": True, "processed": len(processed), "transaction_ids": processed[:10]}


@celery_app.task(name="agenthive.vera_nightly_kyc_batch")
def vera_nightly_kyc_batch() -> dict:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT id FROM kyc_documents
            WHERE verification_status = 'pending'
            AND uploaded_at <= datetime('now', '-7 days')
            ORDER BY uploaded_at ASC
            """
        ).fetchall()
        doc_ids = [str(r["id"]) for r in rows]
    finally:
        conn.close()

    if not doc_ids:
        return {"ok": True, "processed": 0}

    results: list[str] = []
    for doc_id in doc_ids:
        vera_process_kyc_document.delay(doc_id)
        results.append(doc_id)

    return {
        "ok": True,
        "queued": len(results),
        "document_ids": results,
    }


@celery_app.task(name="agenthive.finn_nightly_batch")
def finn_nightly_batch() -> dict:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT account_id FROM customers ORDER BY account_number ASC"
        ).fetchall()
        account_ids = [str(r["account_id"]) for r in rows if r["account_id"]]
    finally:
        conn.close()

    if not account_ids:
        return {"ok": True, "processed": 0}

    results: list[str] = []
    for account_id in account_ids:
        finn_generate_summary.delay(account_id)
        results.append(account_id)

    return {
        "ok": True,
        "queued": len(results),
        "account_ids": results[:5],
        "total": len(results),
    }

