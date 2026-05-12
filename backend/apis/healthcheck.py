from __future__ import annotations

import asyncio

import httpx

from agents.base_agent import SecurityLevel
from apis.dependencies import mint_role_token
from config.security_level_store import security_level_store
from db.sqlite import connect


async def _set_level(client: httpx.AsyncClient, level: SecurityLevel) -> None:
    """Sync lab security level to Redis via the running API (and local store for mint_role_token).

    Suites should end with ``await _set_level(client, SecurityLevel.low)`` in a ``finally``
    block so the shared store is never left at a higher level after the run.
    """
    # This file runs as a separate process. We must update the running FastAPI
    # app process via HTTP, not just mutate our local process store.
    security_level_store.set(level)  # local store for mint_role_token
    resp = await client.post(
        "/api/v1/lab/security-level",
        json={"level": level.value},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to set security level: {resp.text}")


async def run() -> None:
    base = "http://localhost:8000"
    all_ok = True
    seeded_account = "0000000001"

    async with httpx.AsyncClient(base_url=base, timeout=60.0) as client:
        try:
            # --- Auth login behavior checks (Phase 2A) ---
            # 1) LOW — non-existent account + wrong PIN => 200
            await _set_level(client, SecurityLevel.low)
            resp = await client.post(
                "/api/v1/auth/login",
                json={"account_number": "9999999999", "pin": "000000"},
            )
            if resp.status_code == 200 and resp.json().get("access_token"):
                print("  PASS  Auth LOW: non-existent account + wrong PIN returns token")
            else:
                print(f"  FAIL  Auth LOW: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 2) MEDIUM — valid account + wrong PIN => 200
            await _set_level(client, SecurityLevel.medium)
            resp = await client.post(
                "/api/v1/auth/login",
                json={"account_number": seeded_account, "pin": "000000"},
            )
            if resp.status_code == 200 and resp.json().get("access_token"):
                print("  PASS  Auth MEDIUM: valid account + wrong PIN returns token")
            else:
                print(f"  FAIL  Auth MEDIUM: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 3) HARD — valid account + wrong PIN => 401
            await _set_level(client, SecurityLevel.hard)
            resp = await client.post(
                "/api/v1/auth/login",
                json={"account_number": seeded_account, "pin": "000000"},
            )
            if resp.status_code == 401:
                print("  PASS  Auth HARD: valid account + wrong PIN rejected")
            else:
                print(f"  FAIL  Auth HARD: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 4) SECURE — valid account + correct PIN => 200
            await _set_level(client, SecurityLevel.secure)
            resp = await client.post(
                "/api/v1/auth/login",
                json={"account_number": seeded_account, "pin": "123456"},
            )
            if resp.status_code == 200 and resp.json().get("access_token"):
                print("  PASS  Auth SECURE: valid account + correct PIN returns token")
            else:
                print(f"  FAIL  Auth SECURE: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # Reset back to LOW for the remaining API checks.
            await _set_level(client, SecurityLevel.low)

            resp = await client.get("/api/v1/accounts/ACC-0047")
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and "bvn" in data:
                    print("  PASS  BOLA: full record exposed at LOW level")
                else:
                    print("  FAIL  BOLA: BVN not in response")
                    all_ok = False
            else:
                print(f"  FAIL  Account endpoint: {resp.status_code}")
                all_ok = False

            resp = await client.post(
                "/api/v1/loans/applications",
                json={
                    "purpose": "Test",
                    "amount_requested_ngn": 100000,
                    "monthly_income_ngn": 50000,
                    "employment_status": "employed",
                    "application_status": "approved",
                    "agent_decision": "approved",
                    "credit_score": 999,
                },
            )
            if resp.status_code in (200, 201):
                print("  PASS  Mass Assignment: agent fields accepted at LOW level")
            else:
                print(f"  FAIL  Mass Assignment: {resp.status_code} {resp.text[:100]}")
                all_ok = False

            resp = await client.post(
                "/api/v1/accounts/ACC-0047/freeze",
                json={"reason": "test", "initiated_by": "test"},
            )
            if resp.status_code == 200:
                print("  PASS  BFLA: freeze accepted without role at LOW level")
            else:
                print(f"  FAIL  BFLA: {resp.status_code}")
                all_ok = False

            resp = await client.get("/api/v1/internal/agent-context/finn")
            if resp.status_code == 200 and isinstance(resp.json(), dict) and "system_prompt" in resp.json():
                print("  PASS  Internal LOW: system_prompt leaked")
            else:
                print(f"  FAIL  Internal LOW: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # Internal API response shapes + wildcard injection checks
            # 1) LOW no auth: should return system_prompt and full secret_value in secrets
            await _set_level(client, SecurityLevel.low)
            resp = await client.get("/api/v1/internal/agent-context/finn")
            data = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 200 and "system_prompt" in data and "secrets" in data and any(
                "secret_value" in r for r in data.get("secrets", [])
            ):
                print("  PASS  Internal LOW shape: prompt + full secrets")
            else:
                print(f"  FAIL  Internal LOW shape: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 2) MEDIUM with token: system_prompt present, but secret_value redacted from secrets
            await _set_level(client, SecurityLevel.medium)
            tok = (await client.post("/api/v1/auth/login", json={"account_number": seeded_account, "pin": "000000"})).json().get("access_token")
            resp = await client.get("/api/v1/internal/agent-context/finn", headers={"Authorization": f"Bearer {tok}"})
            data = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 200 and "system_prompt" in data and "secrets" in data and all(
                "secret_value" not in r for r in data.get("secrets", [])
            ):
                print("  PASS  Internal MEDIUM shape: prompt leak, secrets redacted")
            else:
                print(f"  FAIL  Internal MEDIUM shape: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 3) HARD with token: config only, no system_prompt field
            await _set_level(client, SecurityLevel.hard)
            tok = (await client.post("/api/v1/auth/login", json={"account_number": seeded_account, "pin": "123456"})).json().get("access_token")
            resp = await client.get("/api/v1/internal/agent-context/finn", headers={"Authorization": f"Bearer {tok}"})
            data = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 200 and "config" in data and "system_prompt" not in data:
                print("  PASS  Internal HARD shape: config only")
            else:
                print(f"  FAIL  Internal HARD shape: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 4) SECURE with internal_service token: config includes owner_system, no system_prompt
            await _set_level(client, SecurityLevel.secure)
            internal_tok = mint_role_token(role="internal_service", sub="svc-internal")
            resp = await client.get(
                "/api/v1/internal/agent-context/finn",
                headers={"Authorization": f"Bearer {internal_tok}"},
            )
            data = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 200 and "config" in data and "system_prompt" not in data and any(
                "owner_system" in r for r in data.get("config", [])
            ):
                print("  PASS  Internal SECURE shape: config with owner_system")
            else:
                print(f"  FAIL  Internal SECURE shape: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # 5) LOW wildcard injection: GET /agent-context/% should return all vault entries and set audit attack_type
            await _set_level(client, SecurityLevel.low)
            # %25 is URL-encoded % character.
            # FastAPI decodes it to % before passing to route handler.
            # This tests whether the LIKE query is injectable via
            # the agent_name path parameter.
            resp = await client.get("/api/v1/internal/agent-context/%25")
            data = resp.json() if resp.status_code == 200 else {}
            secrets = data.get("secrets", []) if isinstance(data, dict) else []
            if resp.status_code == 200 and isinstance(secrets, list) and len(secrets) >= 8:
                conn = connect()
                try:
                    row = conn.execute(
                        "SELECT attack_detected, attack_type FROM audit_events WHERE workflow = ? ORDER BY id DESC LIMIT 1",
                        ("internal.agent_context",),
                    ).fetchone()
                finally:
                    conn.close()
                if row and int(row["attack_detected"]) == 1 and row["attack_type"] == "wildcard_injection":
                    print("  PASS  Internal LOW wildcard: returns all secrets + audit flagged")
                else:
                    print("  FAIL  Internal LOW wildcard: audit not flagged correctly")
                    all_ok = False
            else:
                print(f"  FAIL  Internal LOW wildcard: {resp.status_code} {resp.text[:120]}")
                all_ok = False

            # --- Lab panel API (Phase 2I) ---
            r_sc = await client.get("/api/v1/lab/scenarios")
            if r_sc.status_code == 200:
                scenarios = r_sc.json()
                n = len(scenarios) if isinstance(scenarios, list) else 0
                if n == 24:
                    print("  PASS  Lab GET /api/v1/lab/scenarios: 24 items")
                else:
                    print(f"  FAIL  Lab scenarios: expected 24, got {n}")
                    all_ok = False
            else:
                print(f"  FAIL  Lab scenarios: HTTP {r_sc.status_code}")
                all_ok = False

            r_fl = await client.get("/api/v1/lab/flags")
            if r_fl.status_code == 200 and isinstance(r_fl.json(), list):
                print(f"  PASS  Lab GET /api/v1/lab/flags: list ({len(r_fl.json())} rows)")
            else:
                print(f"  FAIL  Lab flags: HTTP {r_fl.status_code}")
                all_ok = False

            r_tv = await client.get("/api/v1/lab/telemetry")
            if r_tv.status_code == 200 and isinstance(r_tv.json(), list):
                print(f"  PASS  Lab GET /api/v1/lab/telemetry: list ({len(r_tv.json())} rows)")
            else:
                print(f"  FAIL  Lab telemetry: HTTP {r_tv.status_code}")
                all_ok = False

            r_pr = await client.get("/api/v1/lab/progress")
            if r_pr.status_code == 200:
                pr = r_pr.json()
                if isinstance(pr, dict) and pr.get("total_scenarios") == 24 and "captured" in pr:
                    print("  PASS  Lab GET /api/v1/lab/progress: summary OK")
                else:
                    print(f"  FAIL  Lab progress shape: {pr!r}")
                    all_ok = False
            else:
                print(f"  FAIL  Lab progress: HTTP {r_pr.status_code}")
                all_ok = False

        finally:
            try:
                await _set_level(client, SecurityLevel.low)
            except Exception:
                pass

    print()
    if all_ok:
        print("Banking APIs: PASS")
    else:
        print("Banking APIs: FAIL")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(run())
