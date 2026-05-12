from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class SecurityLevel(str, Enum):
    low = "low"
    medium = "medium"
    hard = "hard"
    secure = "secure"


class Difficulty(str, Enum):
    low = "Low"
    medium = "Medium"
    hard = "Hard"
    chained = "Chained"


class AgentName(str, Enum):
    aria = "aria"
    finn = "finn"
    vera = "vera"
    max = "max"
    leo = "leo"
    ops = "ops"


class WorkflowName(str, Enum):
    support_ticket = "support_ticket"
    statement_generation = "statement_generation"
    kyc_verification = "kyc_verification"
    fraud_monitoring = "fraud_monitoring"
    loan_processing = "loan_processing"
    internal_it = "internal_it"


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    requires_approval_above: SecurityLevel | None
    allowed_for_agents: list[AgentName]
    parameters_schema: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class VulnerabilityManifest:
    title: str
    description: str
    difficulty: Difficulty
    agent: AgentName
    workflow: WorkflowName
    objective: str
    flag: str
    hint_1: str
    hint_2: str
    hint_3: str
    detection_query: str
    fix_description: str


@dataclass(frozen=True, slots=True)
class AgentTrigger:
    """Non-chat trigger describing where input came from.

    metadata may include ``source`` (for example ``api``, ``healthcheck``, ``portal_form``)
    for audit and agent wiring.
    """

    workflow: WorkflowName
    actor_id: str  # customer_id or employee_id
    request_id: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AgentResult:
    """Agent output returned to the workflow (may feed downstream systems)."""

    agent: AgentName
    workflow: WorkflowName
    ok: bool
    output: Mapping[str, Any]
    flag: str | None = None


class BaseAgent(ABC):
    """Common interface all agents implement.

    Agents are *invisible* in the NexaBank UI: they are triggered by workflows.
    """

    name: AgentName

    @abstractmethod
    async def run(
        self,
        *,
        trigger: AgentTrigger,
        payload: Mapping[str, Any],
        security_level: SecurityLevel | None,
    ) -> AgentResult:
        raise NotImplementedError

    @abstractmethod
    def get_tools(self) -> list[ToolDefinition]:
        raise NotImplementedError

    @abstractmethod
    def get_vulnerability_manifests(self) -> list[VulnerabilityManifest]:
        raise NotImplementedError

    @abstractmethod
    async def emit_audit_event(
        self,
        *,
        trigger: AgentTrigger,
        tools_called: list[Mapping[str, Any]],
        result: AgentResult,
        security_level: SecurityLevel | None,
        attack_detected: bool = False,
        attack_type: str | None = None,
    ) -> None:
        raise NotImplementedError


