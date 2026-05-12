from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

logging.getLogger("chromadb").setLevel(logging.ERROR)
logging.getLogger("chromadb.telemetry").setLevel(logging.ERROR)
logging.getLogger("chromadb.telemetry.product").setLevel(logging.ERROR)

import chromadb

from agents.base_agent import SecurityLevel
from config.security_level_store import security_level_store
from db.sqlite import connect, insert_audit_event
from llm import get_llm_provider


_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060]")
_HIDDEN_HTML = re.compile(r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*transparent)")
_INSTRUCTION_LIKE = re.compile(
    r"(?i)\b(ignore\s+previous|system\s*:|assistant\s*:|developer\s*:|tool\s*:)\b"
)
_IMPERATIVE = re.compile(r"(?im)^(send|email|lookup|retrieve|freeze|disburse|approve|reject)\b")
_POLICY_INJECTION = re.compile(r"(?i)\b(compliance\s+update|effective\s+immediately|cbn\s+directive|automatically\s+approved)\b")


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _chunk_text(*, text: str, chunk_chars: int = 512, overlap_chars: int = 64) -> list[str]:
    t = text or ""
    if not t.strip():
        return []
    out: list[str] = []
    i = 0
    while i < len(t):
        chunk = t[i : i + chunk_chars]
        out.append(chunk)
        if i + chunk_chars >= len(t):
            break
        i = max(0, i + chunk_chars - overlap_chars)
    return out


def _strip_invisible_basic(text: str) -> str:
    t = _ZERO_WIDTH.sub("", text or "")
    t = _HIDDEN_HTML.sub("", t)
    return t


def _strip_invisible_strong(text: str) -> str:
    t = _strip_invisible_basic(text)
    # Remove obviously obfuscated segments (very high punctuation ratio).
    lines = []
    for line in t.splitlines():
        s = line.strip()
        if not s:
            continue
        punct = sum(1 for c in s if c in "{}[]<>/\\|`~")
        if punct / max(1, len(s)) > 0.35:
            continue
        lines.append(line)
    return "\n".join(lines)


def _secure_screen(text: str) -> bool:
    t = text or ""
    if _INSTRUCTION_LIKE.search(t):
        return True
    if _IMPERATIVE.search(t):
        return True
    if _POLICY_INJECTION.search(t):
        return True
    return False


def _metadata_poisoned_flag(meta: dict[str, Any]) -> bool:
    """True if Chroma metadata marks this chunk as poisoned (handles bool/int/str from Chroma)."""
    v = (meta or {}).get("poisoned")
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes"}
    return False


def _metadata_for_level(level: SecurityLevel, metadata: dict[str, Any], *, source_id: str) -> dict[str, Any]:
    if level == SecurityLevel.low:
        return dict(metadata)
    if level == SecurityLevel.medium:
        # filtered: keep common useful keys, drop long/unknown fields
        allow = {"source_id", "doc_type", "uploaded_at", "verified_by", "customer_account", "verification_status", "poisoned"}
        return {k: v for k, v in dict(metadata).items() if k in allow}
    # HARD/SECURE allowlist only
    allow2 = {"source_id", "doc_type", "uploaded_at", "verified_by"}
    return {k: v for k, v in dict(metadata).items() if k in allow2} | {"source_id": source_id}


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    text: str
    metadata: dict[str, Any]
    distance: float | None


class DocumentPipeline:
    def __init__(self, security_level: SecurityLevel):
        self.level = security_level
        logging.getLogger("chromadb.telemetry").setLevel(logging.ERROR)
        self.chroma = chromadb.HttpClient(
            host=os.getenv("CHROMA_HOST", "chromadb"),
            port=int(os.getenv("CHROMA_PORT", "8000")),
        )

    def _collection(self, name: str):
        try:
            return self.chroma.get_or_create_collection(name)
        except Exception as e:
            raise RuntimeError(
                f"ChromaDB collection '{name}' unavailable: {e}. "
                f"Check CHROMA_HOST={os.getenv('CHROMA_HOST')} "
                f"CHROMA_PORT={os.getenv('CHROMA_PORT')}"
            ) from e

    async def ingest(
        self,
        *,
        text: str,
        collection: str,
        metadata: dict,
        source_id: str,
    ) -> dict:
        lvl = self.level
        t = text or ""

        if lvl == SecurityLevel.medium:
            t = _strip_invisible_basic(t)
        elif lvl == SecurityLevel.hard:
            t = _strip_invisible_strong(t)
        elif lvl == SecurityLevel.secure:
            # Strict screening: reject instruction-like patterns.
            if _secure_screen(t):
                conn = connect()
                try:
                    insert_audit_event(
                        conn=conn,
                        agent="rag_pipeline",
                        workflow="rag.ingest",
                        request_id=f"rag-{int(time.time()*1000)}",
                        actor_id=str(metadata.get("source_id") or source_id),
                        security_level=lvl.value,
                        tools_called=[{"name": "ingest", "args": {"collection": collection, "source_id": source_id}}],
                        result={"ok": False, "rejected": True},
                        attack_detected=True,
                        attack_type="rag_poisoning_attempt",
                    )
                finally:
                    conn.close()
                return {"ok": False, "rejected": True}

            t = _strip_invisible_strong(t)

        chunks = _chunk_text(text=t)
        if not chunks:
            return {"ok": False, "error": "empty_text"}

        provider = get_llm_provider()
        col = self._collection(collection)

        met_base = {
            "source_id": source_id,
            "collection": collection,
            "ingested_at": _iso_now(),
            "security_level": lvl.value,
            "poisoned": bool(metadata.get("poisoned", False)),
        }
        met_user = _metadata_for_level(lvl, dict(metadata), source_id=source_id)

        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict[str, Any]] = []
        embeddings: list[list[float]] = []

        for idx, chunk in enumerate(chunks):
            emb = await provider.embed(text=chunk)
            ids.append(f"{source_id}:{idx}")
            documents.append(chunk)
            metadatas.append({**met_base, **met_user, "chunk_index": idx})
            embeddings.append(list(emb.vector))

        col.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
        return {"ok": True, "chunks": len(chunks), "collection": collection, "source_id": source_id}

    async def retrieve(
        self,
        *,
        query: str,
        collection: str,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list[dict]:
        lvl = self.level
        provider = get_llm_provider()
        q_emb = await provider.embed(text=query)
        col = self._collection(collection)

        where = filters or None
        res = col.query(
            query_embeddings=[list(q_emb.vector)],
            n_results=max(1, min(int(top_k), 20)),
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]

        out: list[RetrievedChunk] = []
        for i in range(min(len(docs), len(metas))):
            out.append(RetrievedChunk(text=str(docs[i]), metadata=dict(metas[i] or {}), distance=dists[i] if i < len(dists) else None))

        if lvl == SecurityLevel.medium:
            out = [c for c in out if not _metadata_poisoned_flag(c.metadata)]

        # HARD/SECURE: validate sources against DB when source is a KYC document id.
        if lvl in {SecurityLevel.hard, SecurityLevel.secure}:
            conn = connect()
            try:
                kyc_ids = {c.metadata.get("source_id") for c in out if str(c.metadata.get("source_id", "")).startswith("KYC-")}
                verified: set[str] = set()
                owner_map: dict[str, str] = {}
                sql_poisoned: set[str] = set()
                if kyc_ids:
                    q = "SELECT id, customer_account, verification_status, poisoned FROM kyc_documents WHERE id IN (%s)" % (
                        ",".join(["?"] * len(kyc_ids))
                    )
                    cur = conn.execute(q, tuple(sorted(kyc_ids)))
                    for r in cur.fetchall():
                        if str(r["verification_status"]) == "verified":
                            verified.add(str(r["id"]))
                        owner_map[str(r["id"])] = str(r["customer_account"])
                        if int(r["poisoned"] or 0) == 1:
                            sql_poisoned.add(str(r["id"]))

                filtered_chunks: list[RetrievedChunk] = []
                for c in out:
                    meta = c.metadata or {}
                    sid = str(meta.get("source_id") or "")

                    # At HARD/SECURE, always drop poisoned chunks: Chroma metadata.poisoned is
                    # authoritative when present; also honor SQLite kyc_documents.poisoned for
                    # KYC-* ids if Chroma omits or coerces the flag. SQLite verification_status
                    # alone is unsafe (Vera may mark KYC-0015 verified while the upload stays poisoned).
                    if _metadata_poisoned_flag(meta) or (sid.startswith("KYC-") and sid in sql_poisoned):
                        continue

                    if sid.startswith("KYC-"):
                        if sid not in verified:
                            continue
                        if lvl == SecurityLevel.secure and filters and "customer_account" in filters:
                            if owner_map.get(sid) != str(filters.get("customer_account")):
                                continue
                    filtered_chunks.append(c)
                out = filtered_chunks
            finally:
                conn.close()

        return [{"text": c.text, "metadata": c.metadata, "distance": c.distance} for c in out]

    async def poison_detection_scan(self, *, collection: str, last_n: int = 50) -> list[dict]:
        col = self._collection(collection)
        got = col.get(include=["documents", "metadatas"])
        docs = got.get("documents") or []
        metas = got.get("metadatas") or []
        ids = got.get("ids") or []

        suspicious: list[dict] = []
        for i in range(min(len(docs), len(metas), len(ids))):
            text = str(docs[i] or "")
            meta = dict(metas[i] or {}) | {"id": ids[i]}
            score = 0
            reasons: list[str] = []
            if _metadata_poisoned_flag(meta):
                score += 10
                reasons.append("marked_poisoned")
            if _INSTRUCTION_LIKE.search(text):
                score += 8
                reasons.append("instruction_pattern")
            if _POLICY_INJECTION.search(text):
                score += 6
                reasons.append("policy_injection")
            if _IMPERATIVE.search(text):
                score += 3
                reasons.append("imperative_verb")
            if score > 0:
                suspicious.append(
                    {
                        "text": text,
                        "metadata": meta,
                        "suspicion_score": score,
                        "reasons": reasons,
                    }
                )

        suspicious.sort(key=lambda x: x["suspicion_score"], reverse=True)
        return suspicious[:last_n]

