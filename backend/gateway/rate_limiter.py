from __future__ import annotations

import time
from dataclasses import dataclass

import redis
from fastapi import Request
from starlette.responses import JSONResponse, Response

from config.security_level_store import security_level_store
from config.settings import settings


def _limit_for_level(level: str) -> int:
    lvl = (level or "").strip().upper()
    if lvl == "LOW":
        return settings.rate_limit_requests_low
    if lvl == "MEDIUM":
        return settings.rate_limit_requests_medium
    if lvl == "HARD":
        return settings.rate_limit_requests_hard
    return settings.rate_limit_requests_secure


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_s: int


class RedisRateLimiter:
    def __init__(self) -> None:
        self._r = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def check(self, *, key: str, limit: int, window_s: int) -> RateLimitResult:
        now = int(time.time())
        window = now - (now % window_s)
        bucket = f"rl:{key}:{window}"

        pipe = self._r.pipeline()
        pipe.incr(bucket, 1)
        pipe.expire(bucket, window_s + 1)
        count, _ = pipe.execute()
        remaining = max(0, limit - int(count))
        return RateLimitResult(allowed=int(count) <= limit, remaining=remaining, reset_s=window + window_s)


_limiter = RedisRateLimiter()


async def rate_limit_middleware(request: Request, call_next) -> Response:
    # Identify by IP + path group.
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    key = f"{ip}:{path}"

    level = security_level_store.get().level
    request.state.security_level = level
    limit = _limit_for_level(level.value.upper())
    res = _limiter.check(key=key, limit=limit, window_s=settings.rate_limit_window_s)

    if not res.allowed:
        return JSONResponse(
            status_code=429,
            content={"ok": False, "error": "rate_limited", "reset_s": res.reset_s},
            headers={
                "x-ratelimit-limit": str(limit),
                "x-ratelimit-remaining": str(res.remaining),
                "x-ratelimit-reset": str(res.reset_s),
            },
        )

    response: Response = await call_next(request)
    response.headers["x-ratelimit-limit"] = str(limit)
    response.headers["x-ratelimit-remaining"] = str(res.remaining)
    response.headers["x-ratelimit-reset"] = str(res.reset_s)
    return response

