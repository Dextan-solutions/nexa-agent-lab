"""Quick checks for Phase 2I lab panel API endpoints (no full banking suite)."""

from __future__ import annotations

import asyncio
import sys

import httpx


async def main() -> int:
    base = "http://localhost:8000"
    ok = True
    async with httpx.AsyncClient(base_url=base, timeout=30.0) as client:
        r = await client.get("/api/v1/lab/scenarios")
        if r.status_code == 200 and len(r.json()) == 24:
            print("  PASS  GET /api/v1/lab/scenarios (24)")
        else:
            print(f"  FAIL  scenarios {r.status_code} {r.text[:80]}")
            ok = False

        r = await client.get("/api/v1/lab/flags")
        if r.status_code == 200 and isinstance(r.json(), list):
            print(f"  PASS  GET /api/v1/lab/flags ({len(r.json())})")
        else:
            print(f"  FAIL  flags {r.status_code}")
            ok = False

        r = await client.get("/api/v1/lab/telemetry")
        if r.status_code == 200 and isinstance(r.json(), list):
            print(f"  PASS  GET /api/v1/lab/telemetry ({len(r.json())})")
        else:
            print(f"  FAIL  telemetry {r.status_code}")
            ok = False

        r = await client.get("/api/v1/lab/progress")
        j = r.json() if r.status_code == 200 else {}
        if isinstance(j, dict) and j.get("total_scenarios") == 24:
            print("  PASS  GET /api/v1/lab/progress")
        else:
            print(f"  FAIL  progress {r.status_code} {j!r}")
            ok = False

    print()
    print("Lab API: PASS" if ok else "Lab API: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
