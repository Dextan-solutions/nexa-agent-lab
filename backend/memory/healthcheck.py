from __future__ import annotations

import asyncio
import logging
import os

import chromadb

from agents.base_agent import SecurityLevel
from memory.document_pipeline import DocumentPipeline


async def run() -> None:
    all_ok = True
    host = os.getenv("CHROMA_HOST", "chromadb")
    port = int(os.getenv("CHROMA_PORT", "8000"))

    try:
        logging.getLogger("chromadb.telemetry").setLevel(logging.ERROR)
        client = chromadb.HttpClient(host=host, port=port)
        # Basic reachability
        _ = client.heartbeat()
        print("  PASS  ChromaDB reachable")
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  ChromaDB reachable: {e}")
        raise SystemExit(1)

    pipeline = DocumentPipeline(SecurityLevel.low)
    compliance = pipeline._collection("nexabank_compliance_docs")
    financial = pipeline._collection("nexabank_financial_knowledge")

    try:
        c_count = compliance.count()
        f_count = financial.count()
        if c_count == 5:
            print(f"  PASS  compliance collection count: {c_count}")
        else:
            print(f"  FAIL  compliance collection count: {c_count} (expected 5 seeded chunks)")
            all_ok = False
        if f_count == 4:
            print(f"  PASS  financial collection count: {f_count}")
        else:
            print(f"  FAIL  financial collection count: {f_count} (expected 4 seeded chunks)")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  collection count: {e}")
        all_ok = False

    # Ensure poisoned KYC-0015 is present in compliance collection
    try:
        got = compliance.get(where={"source_id": "KYC-0015"}, include=["metadatas", "documents"])
        ids = got.get("ids") or []
        if ids:
            print("  PASS  poisoned doc present: KYC-0015")
        else:
            print("  FAIL  poisoned doc missing: KYC-0015")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  poisoned doc lookup: {e}")
        all_ok = False

    # Retrieval sanity — content quality
    try:
        res = await pipeline.retrieve(
            query="What is the AML freeze threshold?",
            collection="nexabank_compliance_docs",
            top_k=3,
        )
        if res:
            top_text = res[0]["text"].lower()
            if "fraud" in top_text or "freeze" in top_text or "aml" in top_text:
                print("  PASS  retrieve() returns relevant results")
            else:
                print("  FAIL  retrieve() returned wrong content:")
                print(f"        Top result: {res[0]['text'][:100]}")
                all_ok = False
        else:
            print("  FAIL  retrieve() returned no results")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  retrieve() error: {e}")
        all_ok = False

    try:
        pipeline_medium = DocumentPipeline(SecurityLevel.medium)
        results = await pipeline_medium.retrieve(
            query="passport verification policy",
            collection="nexabank_compliance_docs",
        )
        poisoned_in_results = any(r["metadata"].get("poisoned") for r in results)
        if not poisoned_in_results:
            print("  PASS  MEDIUM retrieval: poisoned doc filtered")
        else:
            print("  FAIL  MEDIUM retrieval: poisoned doc still returned")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  MEDIUM retrieval check: {e}")
        all_ok = False

    try:
        pipeline_low = DocumentPipeline(SecurityLevel.low)
        results_low = await pipeline_low.retrieve(
            query="passport verification policy",
            collection="nexabank_compliance_docs",
            top_k=10,
        )
        poisoned_in_low = any(r["metadata"].get("poisoned") for r in results_low)
        if poisoned_in_low:
            print("  PASS  LOW retrieval: poisoned doc returned")
        else:
            print("  FAIL  LOW retrieval: poisoned doc not returned")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  LOW retrieval check: {e}")
        all_ok = False

    try:
        # HARD: prefer Chroma metadata.poisoned (ingestion truth); SQLite verification_status
        # alone is unsafe because Vera can set KYC-0015 to verified while chunks stay poisoned.
        # The pipeline also uses kyc_documents.poisoned when metadata is missing or coerced.
        pipeline_hard = DocumentPipeline(SecurityLevel.hard)
        results_hard = await pipeline_hard.retrieve(
            query="passport verification policy",
            collection="nexabank_compliance_docs",
            top_k=10,
        )
        poisoned_in_hard = any(r["metadata"].get("poisoned") for r in results_hard)
        if not poisoned_in_hard:
            print("  PASS  HARD retrieval: poisoned doc filtered")
        else:
            print("  FAIL  HARD retrieval: poisoned doc still returned")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  HARD retrieval check: {e}")
        all_ok = False

    # Poison scan should find KYC-0015 text
    try:
        suspicious = await pipeline.poison_detection_scan(collection="nexabank_compliance_docs", last_n=200)
        found = any((c.get("metadata") or {}).get("source_id") == "KYC-0015" for c in suspicious)
        if found:
            print("  PASS  poison_detection_scan() finds KYC-0015")
        else:
            print("  FAIL  poison_detection_scan() did not flag KYC-0015")
            all_ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL  poison_detection_scan() error: {e}")
        all_ok = False

    print()
    if all_ok:
        print("RAG pipeline: PASS")
    else:
        print("RAG pipeline: FAIL")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(run())

