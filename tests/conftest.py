from __future__ import annotations

import asyncio
import os
from typing import Any

import fakeredis


class YieldingRedis:
    """Proxy that yields to the event loop before and after every command.

    fakeredis completes each command without suspending, so ``asyncio.gather`` would
    otherwise run coroutines back-to-back and hide check-then-write races. Yielding
    forces the interleaving a real network round-trip causes. Lua scripts stay atomic
    (one command), so only genuinely non-atomic code can fail these tests.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if name == "pipeline" or not callable(attr):
            return attr
        if name == "register_script":
            def register(src: str) -> Any:
                script = attr(src)

                async def run(*a: Any, **k: Any) -> Any:
                    await asyncio.sleep(0)
                    res = await script(*a, **k)
                    await asyncio.sleep(0)
                    return res

                return run

            return register

        async def wrapper(*a: Any, **k: Any) -> Any:
            await asyncio.sleep(0)
            res = await attr(*a, **k)
            await asyncio.sleep(0)
            return res

        return wrapper


def new_redis() -> Any:
    """fakeredis by default; set REDIS_URL to run the same tests against a real Redis."""
    url = os.environ.get("REDIS_URL")
    if url:
        import redis.asyncio as aioredis

        return YieldingRedis(aioredis.from_url(url, decode_responses=True))
    return YieldingRedis(fakeredis.FakeAsyncRedis(decode_responses=True))
