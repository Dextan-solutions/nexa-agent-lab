from __future__ import annotations

import asyncio
import time
import uuid

import httpx

from agents.base_agent import SecurityLevel
from celery_app import celery_app
from db.sqlite import connect
from memory.document_pipeline import DocumentPipeline


def _print_result(ok: bool, label: str, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"  {status}  {label}: {detail}")
    else:
        print(f"  {status}  {label}")


async def _wait_for_kyc_status(doc_id: str, *, timeout_s: float = 30.0) -> str | None:
    deadline = time.time() + timeout_s
    elapsed = 0
    while time.time() < deadline:
        conn = connect()
        try:
            row = conn.execute(
                "SELECT verification_status FROM kyc_documents WHERE id = ?",
                (doc_id,),
            ).fetchone()
            if row is None:
                return None
            status = str(row["verification_status"] or "")
            if status and status != "pending":
                return status
        finally:
            conn.close()
        await asyncio.sleep(5.0)
        elapsed += 5
        if elapsed % 30 == 0 and elapsed > 0:
            print(f"  INFO  Still waiting... {elapsed}s elapsed")
    return None


async def run() -> None:
    try:
        await _run_inner()
    finally:
        try:
            httpx.post(
                "http://localhost:8000/api/v1/lab/security-level",
                json={"level": "low"},
                timeout=5.0,
            )
        except Exception:
            pass


async def _run_inner() -> None:
    all_ok = True
    expected_tasks = {
        "agenthive.ping",
        "agenthive.max_fraud_monitor",
        "agenthive.aria_process_support_ticket",
        "agenthive.leo_process_loan",
        "agenthive.vera_process_kyc_document",
        "agenthive.vera_nightly_kyc_batch",
        "agenthive.finn_generate_summary",
        "agenthive.finn_nightly_batch",
        "agenthive.ops_handle_request",
    }

    # Workers can take a moment to come up after compose restarts; retry briefly
    # so `inspect().registered()` doesn't fail the whole healthcheck due to timing.
    reg: dict[str, list[str]] = {}
    for attempt in range(1, 16):  # ~30s total
        insp = celery_app.control.inspect(timeout=5.0)
        reg = insp.registered() or {}
        if reg:
            break
        if attempt in (3, 8, 13):
            print(f"  INFO  Waiting for Celery worker... attempt={attempt}/15")
        await asyncio.sleep(2.0)
    reg_set: set[str] = set()
    for _worker, tasks in reg.items():
        reg_set |= set(tasks or [])

    missing = sorted(t for t in expected_tasks if t not in reg_set)
    _print_result(not missing, "Celery registered tasks", f"missing={missing!r}" if missing else f"{len(expected_tasks)}")
    if missing:
        all_ok = False

    beat = celery_app.conf.beat_schedule or {}
    expected_entries = {"max-fraud-monitor", "vera-nightly-kyc", "finn-nightly-statements"}
    beat_ok = set(beat.keys()) == expected_entries
    _print_result(beat_ok, "Beat schedule entries", f"found={sorted(beat.keys())}")
    if not beat_ok:
        all_ok = False

    async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=10.0) as client:
        # Trigger endpoints in an order that keeps the delayed-injection check deterministic:
        # the Finn batch can enqueue many jobs and slow the worker.
        for path in (
            "/api/v1/lab/trigger/vera-batch",
            "/api/v1/lab/trigger/max-monitor",
        ):
            try:
                r = await client.post(path, json={})
                ok = r.status_code == 200 and bool(r.json().get("task_id"))
                _print_result(ok, f"Lab trigger {path}", f"status={r.status_code}")
                if not ok:
                    all_ok = False
            except Exception as e:  # noqa: BLE001
                _print_result(False, f"Lab trigger {path}", str(e))
                all_ok = False

        #
        # TEST 1 — Batch functionality check (queues docs; does NOT wait for Vera to finish).
        #
        batch_doc_id = f"KYC-BATCH-HC-{uuid.uuid4().hex[:8].upper()}"
        conn = connect()
        try:
            conn.execute("DELETE FROM kyc_documents WHERE id = ?", (batch_doc_id,))
            conn.execute(
                """
                INSERT INTO kyc_documents
                  (id, customer_account, document_type, file_path, extracted_data,
                   verification_status, agent_notes, poisoned, metadata_json, uploaded_at, verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-8 days'), ?)
                """,
                (
                    batch_doc_id,
                    "0000000001",
                    "passport",
                    "/data/uploads/kyc/hc.bin",
                    "Passport - Batch HC User. Please verify.",
                    "pending",
                    None,
                    0,
                    "{}",
                    None,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        try:
            async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=10.0) as client:
                await client.post(
                    "/api/v1/lab/security-level",
                    json={"level": "low"},
                    timeout=5.0,
                )

                r2 = await client.post("/api/v1/lab/trigger/vera-batch", json={})
                ok2 = r2.status_code == 200
                data = r2.json() if ok2 else {}
                queued = data.get("queued", "unknown")
                print(f"  INFO  vera-batch queued {queued} documents for processing")
                ok_batch = ok2 and isinstance(queued, int) and queued >= 1
                _print_result(ok_batch, "Batch: vera-batch queued documents", f"queued={queued!r}")
                if not ok_batch:
                    all_ok = False
        finally:
            # Cleanup the batch test document after the batch has queried/enqueued work.
            conn = connect()
            try:
                conn.execute("DELETE FROM kyc_documents WHERE id = ?", (batch_doc_id,))
                conn.commit()
            finally:
                conn.close()

        #
        # TEST 2 — Delayed injection scenario (direct document trigger + wait + audit checks).
        #
        test_id = f"KYC-HC-{uuid.uuid4().hex[:8].upper()}"
        conn = connect()
        try:
            conn.execute("DELETE FROM kyc_documents WHERE id = ?", (test_id,))
            conn.execute(
                """
                INSERT INTO kyc_documents
                  (id, customer_account, document_type, file_path, extracted_data,
                   verification_status, agent_notes, poisoned, metadata_json, uploaded_at, verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-8 days'), ?)
                """,
                (
                    test_id,
                    "0000000001",
                    "passport",
                    "/data/uploads/kyc/hc.bin",
                    "Passport - Test User. Please verify.",
                    "pending",
                    None,
                    0,
                    "{}",
                    None,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        # Trigger and wait - NO cleanup until after wait + audit checks complete.
        try:
            async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=10.0) as client:
                await client.post(
                    "/api/v1/lab/security-level",
                    json={"level": "low"},
                    timeout=5.0,
                )

                r_direct = await client.post(
                    f"/api/v1/lab/trigger/vera-document/{test_id}",
                    json={},
                )
                ok_trigger = r_direct.status_code == 200
                _print_result(
                    ok_trigger,
                    "Delayed injection: vera document trigger",
                    f"status={r_direct.status_code}",
                )
                if not ok_trigger:
                    all_ok = False

            status = await _wait_for_kyc_status(test_id, timeout_s=300.0)
            ok3 = status is not None
            _print_result(ok3, "Delayed injection: KYC status changed", f"status={status!r}")
            if not ok3:
                all_ok = False

            conn = connect()
            try:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM audit_events
                    WHERE agent = 'vera' AND request_id = ?
                    """,
                    (test_id,),
                ).fetchone()
                n = int(row["n"]) if row else 0
            finally:
                conn.close()
            ok4 = n >= 1
            _print_result(ok4, "Delayed injection: audit_events vera entry", f"count={n}")
            if not ok4:
                all_ok = False
        finally:
            conn = connect()
            try:
                conn.execute("DELETE FROM kyc_documents WHERE id = ?", (test_id,))
                conn.commit()
            finally:
                conn.close()

            try:
                pipeline = DocumentPipeline(SecurityLevel.low)
                col = pipeline._collection("nexabank_compliance_docs")
                col.delete(where={"source_id": test_id})
            except Exception:
                pass

        # Finn batch must be the absolute last thing: after delayed injection AND cleanup.
        async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=10.0) as client:
            rf = await client.post("/api/v1/lab/trigger/finn-batch", json={})
            okf = rf.status_code == 200 and bool(rf.json().get("task_id"))
            _print_result(okf, "Lab trigger /api/v1/lab/trigger/finn-batch", f"status={rf.status_code}")
            if not okf:
                all_ok = False

        print()
        if all_ok:
            print("Tasks: PASS")
        else:
            print("Tasks: FAIL")
            raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(run())

