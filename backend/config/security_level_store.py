from __future__ import annotations

import time
from dataclasses import dataclass

import redis

from agents.base_agent import SecurityLevel
from config.settings import settings


def _normalize(level: str | SecurityLevel) -> SecurityLevel:
    if isinstance(level, SecurityLevel):
        return level
    raw = (level or "").strip()
    if not raw:
        raise ValueError("security_level must be one of LOW|MEDIUM|HARD|SECURE")
    v = raw.lower()
    # accept legacy uppercase env values
    if v in {"low", "medium", "hard", "secure"}:
        return SecurityLevel(v)
    raise ValueError("security_level must be one of LOW|MEDIUM|HARD|SECURE")


@dataclass(frozen=True, slots=True)
class SecurityLevelState:
    level: SecurityLevel
    updated_at_ms: int


class SecurityLevelStore:
    """Stores the global security level in Redis so it can be changed without restart."""

    _key_level = "agenthive:security_level"
    _key_updated = "agenthive:security_level_updated_ms"

    def __init__(self) -> None:
        self._r = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def get(self) -> SecurityLevelState:
        lvl = self._r.get(self._key_level)
        upd = self._r.get(self._key_updated)
        if not lvl:
            # First run: seed from env
            seeded = _normalize(settings.security_level)
            self.set(seeded)
            return SecurityLevelState(level=seeded, updated_at_ms=int(time.time() * 1000))
        try:
            lvl_n = _normalize(lvl)
        except ValueError:
            lvl_n = _normalize(settings.security_level)
        try:
            upd_ms = int(upd) if upd else 0
        except ValueError:
            upd_ms = 0
        return SecurityLevelState(level=lvl_n, updated_at_ms=upd_ms)

    def set(self, level: str | SecurityLevel) -> SecurityLevelState:
        lvl = _normalize(level)
        now_ms = int(time.time() * 1000)
        pipe = self._r.pipeline()
        pipe.set(self._key_level, lvl.value)
        pipe.set(self._key_updated, str(now_ms))
        pipe.execute()
        return SecurityLevelState(level=lvl, updated_at_ms=now_ms)


security_level_store = SecurityLevelStore()

