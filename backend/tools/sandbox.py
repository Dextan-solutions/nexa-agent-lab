from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    args: Mapping[str, Any]


class ToolSandbox:
    """Minimal tool controller used by agents.

    Tool implementations are registered by each agent (e.g. Aria wires HTTP calls to
    NexaBank `/api/v1/*` routes via `tools/banking_client.py`).

    In LOW/MEDIUM it can allow direct action requested by untrusted user text.
    In HARD/SECURE it can require approval for certain tool classes.
    """

    def __init__(
        self,
        *,
        tools: Mapping[str, Callable[..., Any]],
        tool_approval: str,
        allow_tool_call_from_user_text: bool,
    ) -> None:
        self._tools = dict(tools)
        self._tool_approval = tool_approval
        self._allow_from_user_text = allow_tool_call_from_user_text

    def execute(self, *, call: ToolCall, requested_by_user_text: bool) -> Any:
        if call.name not in self._tools:
            raise ValueError(f"Unknown tool: {call.name}")

        if requested_by_user_text and not self._allow_from_user_text:
            return {"ok": False, "error": "tool_call_blocked"}

        # Approval policy stub (expanded later):
        if self._tool_approval in {"all_actions"} and call.name in {"account_lookup"}:
            # For now, simulate a required approval that isn't granted automatically.
            return {"ok": False, "error": "approval_required"}

        fn = self._tools[call.name]
        return fn(**call.args)

