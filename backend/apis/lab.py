from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException

from agents.base_agent import SecurityLevel
from apis.dependencies import get_db
from config.security_level_store import security_level_store

router = APIRouter(prefix="/api/v1/lab", tags=["lab"])

_FLAG_PATTERN = re.compile(r"AGENTHIVE\{[^}]+\}")


def _flags_from_audit_row(row: Mapping[str, Any]) -> set[str]:
    """Collect AGENTHIVE{...} tokens from result_json and related columns."""
    found: set[str] = set()
    text = str(row.get("result_json") or "")
    for m in _FLAG_PATTERN.findall(text):
        found.add(m)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        fl = data.get("flag")
        if isinstance(fl, str) and fl.startswith("AGENTHIVE{"):
            found.add(fl)
    blob = " ".join(str(row.get(k) or "") for k in ("attack_type", "workflow", "agent"))
    for m in _FLAG_PATTERN.findall(blob):
        found.add(m)
    return found


def _primary_flag_from_audit_row(row: Mapping[str, Any]) -> str | None:
    text = str(row.get("result_json") or "")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        fl = data.get("flag")
        if isinstance(fl, str) and fl.startswith("AGENTHIVE{"):
            return fl
    all_flags = _flags_from_audit_row(row)
    return min(all_flags) if all_flags else None


def _iso_ts(ts_ms: int | None) -> str:
    if not ts_ms:
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


@lru_cache(maxsize=1)
def _manifest_rows() -> list[dict[str, Any]]:
    from agents.aria.agent import AriaAgent
    from agents.finn.agent import FinnAgent
    from agents.leo.agent import LeoAgent
    from agents.max.agent import MaxAgent
    from agents.ops.agent import OpsAgent
    from agents.vera.agent import VeraAgent

    agents: list[Any] = [
        AriaAgent(),
        VeraAgent(),
        FinnAgent(),
        LeoAgent(),
        MaxAgent(),
        OpsAgent(),
    ]
    rows: list[dict[str, Any]] = []
    for ag in agents:
        for m in ag.get_vulnerability_manifests():
            rows.append(
                {
                    "agent": m.agent.value,
                    "title": m.title,
                    "description": m.description,
                    "difficulty": m.difficulty.name,
                    "objective": m.objective,
                    "hint_1": m.hint_1,
                    "hint_2": m.hint_2,
                    "hint_3": m.hint_3,
                    "flag": m.flag,
                    "workflow": m.workflow.value,
                }
            )
    return rows


def _captured_flag_values(conn: Any) -> set[str]:
    cur = conn.execute(
        """
        SELECT result_json, attack_type, workflow, agent
        FROM audit_events
        WHERE attack_detected = 1
        """
    )
    found: set[str] = set()
    for row in cur.fetchall():
        found.update(_flags_from_audit_row(dict(row)))
    return found


@router.post("/security-level")
def set_level(body: dict) -> dict:
    level_str = body.get("level", "low")
    try:
        lvl = SecurityLevel(level_str)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid level") from e
    security_level_store.set(lvl)
    return {"ok": True, "level": lvl.value}


@router.get("/security-level")
def get_level() -> dict:
    return {"level": security_level_store.get().level.value}


@router.get("/scenarios")
def lab_scenarios(conn=Depends(get_db)) -> list[dict[str, Any]]:
    captured = _captured_flag_values(conn)
    out: list[dict[str, Any]] = []
    for row in _manifest_rows():
        item = dict(row)
        item["captured"] = row["flag"] in captured
        out.append(item)
    return out


@router.get("/flags")
def lab_flags(conn=Depends(get_db)) -> list[dict[str, Any]]:
    cur = conn.execute(
        """
        SELECT id, ts_ms, agent, attack_type, security_level, result_json, workflow
        FROM audit_events
        WHERE attack_detected = 1
        ORDER BY id DESC
        LIMIT 50
        """
    )
    items: list[dict[str, Any]] = []
    for row in cur.fetchall():
        flag = _primary_flag_from_audit_row(dict(row))
        if not flag:
            continue
        items.append(
            {
                "timestamp": _iso_ts(int(row["ts_ms"]) if row["ts_ms"] is not None else None),
                "agent": str(row["agent"]),
                "flag": flag,
                "attack_type": str(row["attack_type"] or ""),
                "security_level": str(row["security_level"]),
            }
        )
    return items


@router.get("/telemetry")
def lab_telemetry(conn=Depends(get_db)) -> list[dict[str, Any]]:
    cur = conn.execute(
        """
        SELECT id, ts_ms, agent, workflow, request_id, security_level, attack_detected, attack_type, actor_id
        FROM audit_events
        ORDER BY id DESC
        LIMIT 50
        """
    )
    return [
        {
            "id": int(r["id"]),
            "timestamp": _iso_ts(int(r["ts_ms"]) if r["ts_ms"] is not None else None),
            "agent": str(r["agent"]),
            "workflow": str(r["workflow"]),
            "request_id": str(r["request_id"] or ""),
            "security_level": str(r["security_level"]),
            "attack_detected": bool(int(r["attack_detected"])),
            "attack_type": str(r["attack_type"] or ""),
            "actor_id": str(r["actor_id"]),
        }
        for r in cur.fetchall()
    ]


@router.get("/progress")
def lab_progress(conn=Depends(get_db)) -> dict[str, Any]:
    manifests = _manifest_rows()
    captured_flags = _captured_flag_values(conn)
    total = len(manifests)
    captured_n = sum(1 for m in manifests if m["flag"] in captured_flags)

    by_agent: dict[str, dict[str, int]] = {}
    by_diff: dict[str, dict[str, int]] = {}
    for m in manifests:
        ag = m["agent"]
        diff = m["difficulty"]
        by_agent.setdefault(ag, {"total": 0, "captured": 0})
        by_agent[ag]["total"] += 1
        if m["flag"] in captured_flags:
            by_agent[ag]["captured"] += 1
        by_diff.setdefault(diff, {"total": 0, "captured": 0})
        by_diff[diff]["total"] += 1
        if m["flag"] in captured_flags:
            by_diff[diff]["captured"] += 1

    return {
        "total_scenarios": total,
        "captured": captured_n,
        "by_agent": by_agent,
        "by_difficulty": by_diff,
    }


@router.post("/trigger/vera-batch")
def trigger_vera_batch() -> dict:
    from tasks import vera_nightly_kyc_batch

    r = vera_nightly_kyc_batch.delay()
    queued: int | str = "unknown"
    try:
        out = r.get(timeout=2.0)  # batch task is expected to be quick
        if isinstance(out, dict) and "queued" in out:
            queued = int(out["queued"])
        elif isinstance(out, dict) and "processed" in out:
            queued = int(out["processed"])
    except Exception:
        queued = "unknown"
    return {"ok": True, "task_id": r.id, "queued": queued}


@router.post("/trigger/vera-document/{document_id}")
def trigger_vera_document(document_id: str) -> dict:
    from tasks import vera_process_kyc_document

    r = vera_process_kyc_document.delay(document_id)
    return {"ok": True, "task_id": str(r.id)}


@router.post("/trigger/finn-batch")
def trigger_finn_batch() -> dict:
    from tasks import finn_nightly_batch

    r = finn_nightly_batch.delay()
    return {"ok": True, "task_id": r.id}


@router.post("/trigger/max-monitor")
def trigger_max_monitor() -> dict:
    from tasks import max_fraud_monitor

    r = max_fraud_monitor.delay()
    return {"ok": True, "task_id": r.id}
