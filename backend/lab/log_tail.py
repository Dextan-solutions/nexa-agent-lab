from __future__ import annotations

from pathlib import Path


def tail_lines(path: str | Path, n: int) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    # Simple tail implementation for jsonl logs.
    with p.open("rb") as f:
        f.seek(0, 2)
        end = f.tell()
        size = 0
        block = 1024
        data = b""
        while end > 0 and size < 5_000_000 and data.count(b"\n") <= n + 1:
            step = min(block, end)
            end -= step
            f.seek(end)
            data = f.read(step) + data
            size += step
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-n:]

