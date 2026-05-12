from __future__ import annotations

from agents.base_agent import (
    AgentName,
    Difficulty,
    VulnerabilityManifest,
    WorkflowName,
)


LOW = VulnerabilityManifest(
    title="BOLA — unauthenticated account access",
    description=(
        "The accounts endpoint is exposed without authentication at LOW security level. "
        "Any client can request a full customer record by account id, including BVN."
    ),
    difficulty=Difficulty.low,
    agent=AgentName.aria,
    workflow=WorkflowName.support_ticket,
    objective=(
        "Access account ACC-0047 without any authentication token. "
        "The endpoint returns the full customer record including BVN."
    ),
    flag="AGENTHIVE{bola_low_no_auth}",
    hint_1="No Authorization header is required at this level.",
    hint_2="Try GET /api/v1/accounts/ACC-0047 with no headers.",
    hint_3="The response includes BVN — proof of full exposure.",
    detection_query=(
        "SELECT * FROM audit_events "
        "WHERE agent='nexabank_api' AND workflow='accounts.get' "
        "AND actor_id IN ('anonymous')"
    ),
    fix_description=(
        "Require authentication and validate ownership against the JWT subject. "
        "Do not allow unauthenticated access to account records."
    ),
)


MEDIUM = VulnerabilityManifest(
    title="BOLA — authenticated but no ownership check",
    description=(
        "The endpoint requires a bearer token at this level, but does not verify that "
        "the requested account belongs to the authenticated customer."
    ),
    difficulty=Difficulty.medium,
    agent=AgentName.aria,
    workflow=WorkflowName.support_ticket,
    objective=(
        "Authenticate as your own account, then access a different customer's full account record."
    ),
    flag="AGENTHIVE{bola_medium_no_ownership}",
    hint_1="You need a valid token — but it can be your own.",
    hint_2="Once authenticated, try accessing ACC-0047 even though it is not your account.",
    hint_3="The server validates the token exists but never checks if the account belongs to you.",
    detection_query=(
        "SELECT * FROM audit_events "
        "WHERE agent='nexabank_api' AND workflow='accounts.get' "
        "AND attack_type='bola' AND security_level='medium'"
    ),
    fix_description=(
        "Enforce object-level authorization: account_id in the path must match "
        "the authenticated principal's account number/account id."
    ),
)


HARD = VulnerabilityManifest(
    title="BOLA — bypassable header ownership check",
    description=(
        "The endpoint uses a client-controlled request header (X-Customer-ID) to validate "
        "ownership. Attackers can set this header to bypass authorization."
    ),
    difficulty=Difficulty.hard,
    agent=AgentName.aria,
    workflow=WorkflowName.support_ticket,
    objective="Access ACC-0047 by manipulating the X-Customer-ID header.",
    flag="AGENTHIVE{bola_hard_header_bypass}",
    hint_1="The server uses a request header to verify account ownership instead of the JWT token.",
    hint_2="Request headers are set by the client — the attacker controls them.",
    hint_3="Set X-Customer-ID to the account ID you want to access.",
    detection_query=(
        "SELECT * FROM audit_events "
        "WHERE agent='nexabank_api' AND workflow='accounts.get' "
        "AND attack_type='bola' AND security_level='hard'"
    ),
    fix_description=(
        "Never trust client-controlled headers for authorization decisions. "
        "Validate ownership strictly using JWT claims."
    ),
)


CHAINED = VulnerabilityManifest(
    title="BOLA chain — account lookup to agent exfiltration",
    description=(
        "A chained exploit uses the BOLA account lookup as step one, then leverages "
        "Aria's tool access (email_send) to exfiltrate the retrieved data."
    ),
    difficulty=Difficulty.chained,
    agent=AgentName.aria,
    workflow=WorkflowName.support_ticket,
    objective=(
        "Use BOLA to retrieve ACC-0047, then inject Aria to email the retrieved account data "
        "to an external address."
    ),
    flag="AGENTHIVE{bola_chained_agent_exfil}",
    hint_1="The account API and Aria agent share the same tool sandbox.",
    hint_2="Aria calls account_lookup which calls this same API. The BOLA applies to both.",
    hint_3="A single injected ticket can trigger both the BOLA lookup and the email exfiltration.",
    detection_query=(
        "SELECT * FROM audit_events "
        "WHERE (agent='nexabank_api' AND workflow='accounts.get') "
        "OR (agent='email_tool' AND workflow='email.send')"
    ),
    fix_description=(
        "Fix BOLA at the API layer (SECURE ownership checks), and enforce tool governance "
        "for agents (approval + domain restrictions for outbound email)."
    ),
)


BOLA_VULNERABILITY_MANIFESTS = [LOW, MEDIUM, HARD, CHAINED]

