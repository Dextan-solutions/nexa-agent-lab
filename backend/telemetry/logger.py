from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    ts_ms: int
    kind: str
    request_id: str
    actor_id: str
    agent: str
    workflow: str
    security_level: str
    data: Mapping[str, Any]


class TelemetryLogger:
    def __init__(self, *, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def emit(
        self,
        *,
        kind: str,
        request_id: str,
        actor_id: str,
        agent: str,
        workflow: str,
        security_level: str,
        data: Mapping[str, Any],
    ) -> None:
        evt = TelemetryEvent(
            ts_ms=int(time.time() * 1000),
            kind=kind,
            request_id=request_id,
            actor_id=actor_id,
            agent=agent,
            workflow=workflow,
            security_level=security_level,
            data=data,
        )
        line = json.dumps(asdict(evt), ensure_ascii=False)
        self._path.open("a", encoding="utf-8").write(line + "\n")


