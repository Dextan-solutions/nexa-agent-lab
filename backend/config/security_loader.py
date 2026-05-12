from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


@dataclass(frozen=True, slots=True)
class AgentSecurityConfig:
    agent: str
    level: str
    config: Mapping[str, Any]


def _normalize_level(level: str) -> str:
    v = (level or "").strip().lower()
    if v in {"low", "medium", "hard", "secure"}:
        return v
    raise ValueError(f"Unknown security level: {level!r}")


def load_security_levels(path: str | Path) -> Mapping[str, Any]:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("security_levels.yaml must parse to a mapping")
    return data


def get_agent_security_config(
    *,
    data: Mapping[str, Any],
    agent: str,
    level: str,
) -> AgentSecurityConfig:
    lvl = _normalize_level(level)

    defaults = data.get("defaults", {}) or {}
    default_cfg = defaults.get(lvl, {}) or {}

    agent_block = data.get(agent, {}) or {}
    levels = agent_block.get("levels", {}) or {}
    agent_cfg = levels.get(lvl, {}) or {}

    merged = {**default_cfg, **agent_cfg}
    return AgentSecurityConfig(agent=agent, level=lvl, config=merged)

