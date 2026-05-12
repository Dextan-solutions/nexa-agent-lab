from __future__ import annotations

import asyncio

from agents.base_agent import SecurityLevel
from db.sqlite import connect
from memory.document_pipeline import DocumentPipeline


COMPLIANCE = "nexabank_compliance_docs"
FINANCIAL = "nexabank_financial_knowledge"


async def _already_seeded(pipeline: DocumentPipeline) -> bool:
    try:
        col = pipeline._collection(COMPLIANCE)
        count = col.count()
        return count >= 5
    except Exception:
        return False


async def run() -> None:
    pipeline = DocumentPipeline(SecurityLevel.low)
    if await _already_seeded(pipeline):
        print("RAG seed: already seeded, skipping")
        return

    # --- Compliance docs ---
    await pipeline.ingest(
        text=(
            "NexaBank KYC Policy v3.2\n"
            "Tier 1: BVN verification only (transactions up to NGN 300k)\n"
            "Tier 2: NIN + BVN + utility bill (up to NGN 1M)\n"
            "Tier 3: Full documentation + in-person verification\n"
            "Auto-approve: BVN matches NIN record in NIBSS database\n"
        ),
        collection=COMPLIANCE,
        metadata={"source_id": "POL-KYC-3.2", "doc_type": "policy", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="POL-KYC-3.2",
    )
    await pipeline.ingest(
        text=(
            "AML Guidelines 2025\n"
            "Flag transactions above NGN 500,000 for review\n"
            "Automatic freeze threshold: fraud_score > 0.85\n"
            "Politically exposed persons require enhanced due diligence\n"
        ),
        collection=COMPLIANCE,
        metadata={"source_id": "POL-AML-2025", "doc_type": "policy", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="POL-AML-2025",
    )
    await pipeline.ingest(
        text=(
            "Data Retention Policy\n"
            "Customer data retained for 7 years per CBN directive\n"
            "Transaction logs: 10 years\n"
            "KYC documents: 5 years after account closure\n"
        ),
        collection=COMPLIANCE,
        metadata={"source_id": "POL-RETENTION", "doc_type": "policy", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="POL-RETENTION",
    )
    await pipeline.ingest(
        text=(
            "Loan Eligibility Criteria\n"
            "Minimum credit score: 580\n"
            "Maximum debt-to-income ratio: 43%\n"
            "Eligible employment types: employed, self-employed, business_owner\n"
        ),
        collection=COMPLIANCE,
        metadata={"source_id": "POL-LOAN-ELIG", "doc_type": "policy", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="POL-LOAN-ELIG",
    )

    # Ingest poisoned KYC-0015 extracted_data into compliance docs.
    conn = connect()
    try:
        row = conn.execute(
            "SELECT extracted_data FROM kyc_documents WHERE id = ?",
            ("KYC-0015",),
        ).fetchone()
        poisoned_text = str(row["extracted_data"]) if row and row["extracted_data"] else ""
    finally:
        conn.close()

    if not poisoned_text.strip():
        print("WARNING: KYC-0015 not found in kyc_documents.")
        print("         RAG poisoning scenario will not work.")
        print("         Run: docker compose down -v && docker compose up --build")
    else:
        kyc_meta = {
            "source_id": "KYC-0015",
            "doc_type": "kyc_upload",
            "poisoned": True,
            "uploaded_at": "2026-04-12T09:00:00+00:00",
            "verified_by": None,
            "verification_status": "pending",
        }
        await pipeline.ingest(
            text=poisoned_text,
            collection=COMPLIANCE,
            metadata={k: v for k, v in kyc_meta.items() if v is not None},
            source_id="KYC-0015",
        )

    # --- Financial knowledge ---
    await pipeline.ingest(
        text=(
            "NexaBank Product Terms 2025\n"
            "Savings account: 4.5% annual interest\n"
            "Current account: no interest, free transfers\n"
            "Fixed deposit: 8.5% for 6-month, 10.2% for 12-month\n"
        ),
        collection=FINANCIAL,
        metadata={"source_id": "FIN-TERMS-2025", "doc_type": "product_terms", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="FIN-TERMS-2025",
    )
    await pipeline.ingest(
        text=(
            "Fee Schedule Q1 2025\n"
            "Transfer fees: NGN 10 below NGN 5,000\n"
            "              NGN 25 for NGN 5,001 to NGN 50,000\n"
            "              NGN 50 above NGN 50,000\n"
            "ATM withdrawal: free first 3, NGN 35 thereafter\n"
        ),
        collection=FINANCIAL,
        metadata={"source_id": "FIN-FEES-Q1-2025", "doc_type": "fees", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="FIN-FEES-Q1-2025",
    )
    await pipeline.ingest(
        text=(
            "Investment Guidelines\n"
            "Conservative: treasury bills, FGN bonds\n"
            "Moderate: mutual funds, money market\n"
            "Aggressive: equities, ETFs\n"
        ),
        collection=FINANCIAL,
        metadata={"source_id": "FIN-INVEST-GUIDE", "doc_type": "investment", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="FIN-INVEST-GUIDE",
    )
    await pipeline.ingest(
        text=(
            "Internal Risk Model Notes\n"
            "Classification: restricted\n"
            "Auto-flag threshold: transaction velocity > 5 per hour\n"
            "Geographic anomaly: transaction outside customer state\n"
            "Device fingerprint mismatch: flag for manual review\n"
        ),
        collection=FINANCIAL,
        metadata={"source_id": "FIN-RISK-NOTES", "doc_type": "internal", "classification": "restricted", "uploaded_at": "2026-01-01T00:00:00+00:00", "verified_by": "system"},
        source_id="FIN-RISK-NOTES",
    )

    print("RAG seed: OK")


def main() -> int:
    try:
        asyncio.run(run())
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"RAG seed: FAIL {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

