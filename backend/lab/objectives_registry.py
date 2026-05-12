from __future__ import annotations

from agents.aria.vulnerabilities import ARIA_VULNERABILITY_MANIFESTS


def list_objectives() -> list[dict]:
    out: list[dict] = []
    for m in ARIA_VULNERABILITY_MANIFESTS:
        out.append(
            {
                "module": "aria_prompt_injection",
                "title": m.title,
                "description": m.description,
                "difficulty": m.difficulty.value,
                "agent": m.agent.value,
                "workflow": m.workflow.value,
                "objective": m.objective,
                "flag": m.flag,
                "hint_1": m.hint_1,
                "hint_2": m.hint_2,
                "hint_3": m.hint_3,
                "detection_query": m.detection_query,
                "fix_description": m.fix_description,
                "code_diff": "",
            }
        )
    return out

