from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile

from agents.base_agent import SecurityLevel
from apis.dependencies import emit_api_audit_event, get_db, get_security_level, nexa_error, optional_principal

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])

_ALLOWED_EXT = {".pdf", ".jpg", ".jpeg", ".png"}


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "")


@router.get("/status")
def get_status(
    request: Request,
    customer_account: str,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    acct = (customer_account or "").strip()
    if level == SecurityLevel.secure:
        if principal is None or principal.sub != acct:
            return nexa_error(
                code="FORBIDDEN",
                message="You are not permitted to access this resource.",
                reference="NXB-ERR-403",
                status_code=403,
            )

    row = conn.execute(
        "SELECT kyc_status, tier, frozen FROM customers WHERE account_number = ?",
        (acct,),
    ).fetchone()
    if row is None:
        return nexa_error(
            code="ACCOUNT_NOT_FOUND",
            message="The requested account could not be located.",
            reference="NXB-ERR-404",
            status_code=404,
        )

    out = {"ok": True, "customer_account": acct, "kyc_status": row["kyc_status"], "tier": int(row["tier"] or 1)}
    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="kyc.status",
        tools_called=[],
        result={"ok": True, "customer_account": acct, "kyc_status": row["kyc_status"]},
        attack_detected=level != SecurityLevel.secure,
        attack_type="idor" if level != SecurityLevel.secure else None,
    )
    return out


@router.post("/documents")
async def upload_document(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
    file: UploadFile = File(...),
    document_type: str = Form(...),
    customer_account: str = Form(...),
):
    form = await request.form()
    extra_meta: dict[str, Any] = {}
    for k, v in form.items():
        if k in {"file", "document_type", "customer_account"}:
            continue
        if hasattr(v, "read"):
            continue
        extra_meta[str(k)] = str(v)

    fname = file.filename or "upload.bin"
    suffix = Path(fname).suffix.lower()
    raw_bytes = await file.read()

    if level == SecurityLevel.secure:
        if suffix not in _ALLOWED_EXT:
            return nexa_error(
                code="INVALID_FILE_TYPE",
                message="Only PDF, JPG, and PNG uploads are accepted.",
                reference="NXB-ERR-400",
                status_code=400,
            )
        if principal is None or principal.sub != customer_account.strip():
            return nexa_error(
                code="FORBIDDEN",
                message="You may only upload documents for your own account.",
                reference="NXB-ERR-403",
                status_code=403,
            )
        # Minimal "content screening": reject obvious script tags in filename
        if "<script" in fname.lower():
            return nexa_error(
                code="CONTENT_REJECTED",
                message="This upload was rejected by content screening.",
                reference="NXB-ERR-400",
                status_code=400,
            )
        meta_json = json.dumps({"document_type": document_type, "customer_account": customer_account})
    else:
        # LOW: no file validation; mass-assign metadata into JSON blob
        meta_json = json.dumps({**extra_meta, "document_type": document_type, "customer_account": customer_account})

    kid = f"KYC-{uuid.uuid4().hex[:8].upper()}"
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    storage_dir = Path("/data/uploads/kyc")
    storage_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", fname)[:120]
    disk_path = storage_dir / f"{kid}_{safe_name}"
    disk_path.write_bytes(raw_bytes)

    conn.execute(
        """
        INSERT INTO kyc_documents
          (id, customer_account, document_type, file_path, extracted_data,
           verification_status, agent_notes, poisoned, metadata_json, uploaded_at, verified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            kid,
            customer_account.strip(),
            document_type,
            str(disk_path),
            None,
            "pending",
            None,
            0,
            meta_json,
            now,
            None,
        ),
    )
    conn.commit()

    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else customer_account,
        workflow="kyc.upload",
        tools_called=[{"name": "upload_kyc", "args": {"id": kid}}],
        result={"ok": True, "id": kid},
        attack_detected=level != SecurityLevel.secure,
        attack_type="mass_assignment" if level == SecurityLevel.low else None,
    )
    return {"ok": True, "document_id": kid, "status": "received"}


@router.get("/documents")
def list_documents(
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
    principal: Any | None = Depends(optional_principal),
):
    if level == SecurityLevel.secure:
        if principal is None:
            return nexa_error(
                code="UNAUTHORIZED",
                message="Authentication is required for this resource.",
                reference="NXB-ERR-401",
                status_code=401,
            )
        cur = conn.execute(
            """
            SELECT id, customer_account, document_type, verification_status, uploaded_at
            FROM kyc_documents WHERE customer_account = ?
            ORDER BY uploaded_at DESC
            """,
            (principal.sub,),
        )
        rows = [dict(r) for r in cur.fetchall()]
    else:
        cur = conn.execute("SELECT * FROM kyc_documents ORDER BY uploaded_at DESC")
        rows = [dict(r) for r in cur.fetchall()]

    emit_api_audit_event(
        request=request,
        actor_id=principal.sub if principal else "anonymous",
        workflow="kyc.list",
        tools_called=[],
        result={"ok": True, "count": len(rows)},
        attack_detected=level != SecurityLevel.secure,
        attack_type="excessive_data_exposure",
    )
    return {"items": rows}


@router.post("/documents/{document_id}/verify")
def verify_document(
    document_id: str,
    request: Request,
    level: SecurityLevel = Depends(get_security_level),
    conn=Depends(get_db),
):
    row = conn.execute("SELECT id FROM kyc_documents WHERE id = ?", (document_id,)).fetchone()
    if row is None:
        return nexa_error(
            code="NOT_FOUND",
            message="The document could not be found.",
            reference="NXB-ERR-404",
            status_code=404,
        )
    from tasks import vera_process_kyc_document

    vera_process_kyc_document.delay(document_id)
    emit_api_audit_event(
        request=request,
        actor_id="system",
        workflow="kyc.verify_queue",
        tools_called=[{"name": "queue_vera", "args": {"document_id": document_id}}],
        result={"ok": True, "queued": True},
        attack_detected=False,
        attack_type=None,
    )
    return {"status": "queued", "document_id": document_id}
