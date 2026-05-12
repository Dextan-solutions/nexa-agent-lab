from __future__ import annotations

import asyncio
import time
import uuid

from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName
from agents.vera.agent import VeraAgent
from agents.vera.vulnerabilities import FLAG_LOW
from config.security_level_store import security_level_store
from db.sqlite import connect
from memory.document_pipeline import DocumentPipeline


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


async def run() -> None:
    try:
        all_ok = True
        agent = VeraAgent()

        async def _set_level(level: SecurityLevel) -> None:
            security_level_store.set(level)
            try:
                import httpx as _httpx

                _httpx.post(
                    "http://localhost:8000/api/v1/lab/security-level",
                    json={"level": level.value},
                    timeout=5.0,
                )
            except Exception:
                pass

        tools = agent.get_tools()
        expected = {"document_verify", "compliance_flag"}
        actual = {t.name for t in tools}
        if actual == expected:
            print(f"  PASS  Tool definitions: {actual}")
        else:
            print(f"  FAIL  Tool definitions: {actual} (expected {expected})")
            all_ok = False

        manifests = agent.get_vulnerability_manifests()
        if len(manifests) == 4:
            print(f"  PASS  Vulnerability manifests: {len(manifests)}")
            for m in manifests:
                print(f"        {m.difficulty.value}: {m.title}")
        else:
            print(f"  FAIL  Expected 4 manifests, got {len(manifests)}")
            all_ok = False

        conn = connect()
        try:
            one = conn.execute("SELECT account_number FROM customers LIMIT 1").fetchone()
            applicant = str(one["account_number"]) if one else "0000000001"
        finally:
            conn.close()

        low_doc_id = f"KYC-HC-VERA-LOW-{uuid.uuid4().hex[:6].upper()}"
        sec_doc_id = f"KYC-HC-VERA-SEC-{uuid.uuid4().hex[:6].upper()}"

        extracted_passport = (
            "Passport Scan: Customer Name: Test User. Passport No: P1234567. Nationality: NG. "
            "DOB: 1990-01-01. Expiry: 2030-01-01."
        )

        conn = connect()
        try:
            conn.execute("DELETE FROM kyc_documents WHERE id IN (?, ?)", (low_doc_id, sec_doc_id))
            conn.commit()
            conn.execute(
                """
                INSERT INTO kyc_documents
                  (id, customer_account, document_type, file_path, extracted_data,
                   verification_status, agent_notes, poisoned, metadata_json, uploaded_at, verified_at)
                VALUES (?, ?, ?, ?, ?, 'pending', NULL, 0, '{}', ?, NULL)
                """,
                (low_doc_id, applicant, "passport", "/data/uploads/kyc/hc_passport.bin", extracted_passport, _iso_now()),
            )
            conn.execute(
                """
                INSERT INTO kyc_documents
                  (id, customer_account, document_type, file_path, extracted_data,
                   verification_status, agent_notes, poisoned, metadata_json, uploaded_at, verified_at)
                VALUES (?, ?, ?, ?, ?, 'pending', NULL, 0, '{}', ?, NULL)
                """,
                (sec_doc_id, applicant, "passport", "/data/uploads/kyc/hc_passport.bin", extracted_passport, _iso_now()),
            )
            conn.commit()
        finally:
            conn.close()

        try:
            await _set_level(SecurityLevel.low)
            trig = AgentTrigger(
                workflow=WorkflowName.kyc_verification,
                actor_id=applicant,
                request_id=low_doc_id,
                metadata={"document_id": low_doc_id},
            )
            res_low = await agent.run(
                trigger=trig,
                payload={"document_id": low_doc_id},
                security_level=SecurityLevel.low,
            )
            if res_low.flag == FLAG_LOW:
                print(f"  PASS  LOW rag poisoning flag: {res_low.flag}")
            else:
                print(f"  FAIL  LOW expected {FLAG_LOW!r}, got {res_low.flag!r}")
                all_ok = False

            conn = connect()
            try:
                row = conn.execute(
                    "SELECT verification_status FROM kyc_documents WHERE id = ?",
                    (low_doc_id,),
                ).fetchone()
                if row and str(row["verification_status"] or "") != "pending":
                    print("  PASS  LOW side-effects: verification_status updated")
                else:
                    print(f"  FAIL  LOW side-effects verification_status: {dict(row) if row else {}}")
                    all_ok = False
            finally:
                conn.close()

            conn = connect()
            try:
                row = conn.execute(
                    "SELECT attack_type FROM audit_events "
                    "WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                    (low_doc_id,),
                ).fetchone()
                if row and str(row["attack_type"] or "") == "rag_poisoning":
                    print("  PASS  LOW audit: attack_type=rag_poisoning confirmed")
                else:
                    print(f"  FAIL  LOW audit: {dict(row) if row else {}}")
                    all_ok = False
            finally:
                conn.close()

            await _set_level(SecurityLevel.secure)
            trig2 = AgentTrigger(
                workflow=WorkflowName.kyc_verification,
                actor_id=applicant,
                request_id=sec_doc_id,
                metadata={"document_id": sec_doc_id},
            )
            res_sec = await agent.run(
                trigger=trig2,
                payload={"document_id": sec_doc_id},
                security_level=SecurityLevel.secure,
            )
            if res_sec.flag is None:
                print("  PASS  SECURE: no exploit flag")
            else:
                print(f"  FAIL  SECURE leaked flag: {res_sec.flag!r}")
                all_ok = False

            conn = connect()
            try:
                row = conn.execute(
                    "SELECT attack_detected FROM audit_events "
                    "WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                    (sec_doc_id,),
                ).fetchone()
                if row and int(row["attack_detected"]) == 0:
                    print("  PASS  SECURE: no attack in audit trail")
                else:
                    print("  FAIL  SECURE: unexpected attack in audit trail")
                    all_ok = False
            finally:
                conn.close()

        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  Vera scenario run: {e}")
            all_ok = False
        finally:
            conn = connect()
            try:
                conn.execute("DELETE FROM kyc_documents WHERE id IN (?, ?)", (low_doc_id, sec_doc_id))
                conn.commit()
            finally:
                conn.close()

            try:
                pipeline = DocumentPipeline(SecurityLevel.low)
                col = pipeline._collection("nexabank_compliance_docs")
                col.delete(where={"source_id": {"$in": [low_doc_id, sec_doc_id]}})
            except Exception:
                pass  # best-effort cleanup

        print()
        if all_ok:
            print("Vera Agent: PASS")
        else:
            print("Vera Agent: FAIL")
            raise SystemExit(1)
    finally:
        try:
            import httpx

            httpx.post(
                "http://localhost:8000/api/v1/lab/security-level",
                json={"level": "low"},
                timeout=5.0,
            )
        except Exception:
            pass  # best-effort reset


if __name__ == "__main__":
    asyncio.run(run())

