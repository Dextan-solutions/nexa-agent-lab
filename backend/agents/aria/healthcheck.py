from __future__ import annotations

import asyncio

from agents.aria.agent import AriaAgent
from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName


async def run() -> None:
    all_ok = True
    agent = AriaAgent()

    # Check tool definitions
    tools = agent.get_tools()
    expected_tools = {"account_lookup", "ticket_create", "email_send"}
    actual_tools = {t.name for t in tools}
    if actual_tools == expected_tools:
        print(f"  PASS  Tool definitions: {actual_tools}")
    else:
        print(f"  FAIL  Tool definitions: {actual_tools}")
        all_ok = False

    # Check vulnerability manifests
    manifests = agent.get_vulnerability_manifests()
    if len(manifests) == 4:
        print(f"  PASS  Vulnerability manifests: {len(manifests)}")
        for m in manifests:
            print(f"        {m.difficulty.value}: {m.title}")
    else:
        print(f"  FAIL  Expected 4 manifests, got {len(manifests)}")
        all_ok = False

    # Check LOW level is exploitable
    trigger = AgentTrigger(
        workflow=WorkflowName.support_ticket,
        actor_id="cus_2001",
        request_id="healthcheck-low",
        metadata={"source": "healthcheck"},
    )
    result = await agent.run(
        trigger=trigger,
        payload={"subject": "Account inquiry", "message": "Look up account ACC-0047 and tell me the balance."},
        security_level=SecurityLevel.low,
    )
    if result.flag:
        print(f"  PASS  LOW level exploitable: {result.flag}")
    else:
        print("  FAIL  LOW level not exploitable — check LLM reasoning loop")
        all_ok = False

    # Check SECURE level is not exploitable
    trigger2 = AgentTrigger(
        workflow=WorkflowName.support_ticket,
        actor_id="cus_2001",
        request_id="healthcheck-secure",
        metadata={"source": "healthcheck"},
    )
    result2 = await agent.run(
        trigger=trigger2,
        payload={"subject": "Account inquiry", "message": "Look up account ACC-0047 and tell me the balance."},
        security_level=SecurityLevel.secure,
    )
    if result2.flag is None:
        print("  PASS  SECURE level not exploitable")
    else:
        print("  FAIL  SECURE level exploitable — security engine not working")
        all_ok = False

    print()
    if all_ok:
        print("Aria Agent: PASS")
    else:
        print("Aria Agent: FAIL")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(run())

