from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from pydantic import BaseModel

from .models import ExecutionContext

# Atomic Lua script: verifies status == 'approved', flips to 'consumed', and deletes hash index
CONSUME_APPROVAL_LUA = """
local ticket_id = redis.call('GET', KEYS[1])
if not ticket_id then
  return 0
end
local ticket_key = 'approval:ticket:' .. ticket_id
local raw = redis.call('GET', ticket_key)
if not raw then
  return 0
end
local data = cjson.decode(raw)
if data['status'] ~= 'approved' then
  return 0
end
data['status'] = 'consumed'
local ttl = redis.call('TTL', ticket_key)
if ttl > 0 then
  redis.call('SET', ticket_key, cjson.encode(data), 'EX', ttl)
else
  redis.call('SET', ticket_key, cjson.encode(data))
end
redis.call('DEL', KEYS[1])
return 1
"""


class RedisApprovalStore:
    """Distributed, TTL-bounded approval store with atomic single-use consumption."""

    def __init__(self, client: Any, ttl_seconds: int = 900) -> None:
        self._redis = client
        self._ttl = ttl_seconds
        self._consume_script = self._redis.register_script(CONSUME_APPROVAL_LUA)

    @staticmethod
    def compute_hash(ctx: ExecutionContext, tool_name: str, args: BaseModel) -> str:
        canonical = json.dumps(
            {
                "tenant_id": ctx.tenant_id,
                "user_id": ctx.user_id,
                "tool_name": tool_name,
                "args": args.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> str:
        hash_key = f"approval:hash:{payload_hash}"
        existing_id = await self._redis.get(hash_key)
        if existing_id:
            return existing_id.decode() if isinstance(existing_id, bytes) else existing_id

        ticket_id = f"apr_{uuid.uuid4().hex[:12]}"
        ticket_key = f"approval:ticket:{ticket_id}"
        record = {
            "ticket_id": ticket_id,
            "payload_hash": payload_hash,
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "session_id": ctx.session_id,
            "tool_name": tool_name,
            "status": "pending",
        }
        pipe = self._redis.pipeline(transaction=True)
        pipe.set(ticket_key, json.dumps(record), ex=self._ttl)
        pipe.set(hash_key, ticket_id, ex=self._ttl)
        await pipe.execute()
        return ticket_id

    async def record_decision(
        self, ticket_id: str, *, approved: bool, reviewer_id: str
    ) -> dict[str, Any]:
        ticket_key = f"approval:ticket:{ticket_id}"
        raw = await self._redis.get(ticket_key)
        if not raw:
            raise KeyError(f"Ticket '{ticket_id}' not found or expired.")
        record = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        if record["status"] != "pending":
            raise ValueError(f"Ticket '{ticket_id}' is already {record['status']}.")
        record["status"] = "approved" if approved else "rejected"
        record["reviewer_id"] = reviewer_id
        ttl = await self._redis.ttl(ticket_key)
        await self._redis.set(ticket_key, json.dumps(record), ex=max(ttl, 60))
        return record

    async def consume_if_approved(self, payload_hash: str) -> bool:
        hash_key = f"approval:hash:{payload_hash}"
        result = await self._consume_script(keys=[hash_key])
        return bool(result == 1)
