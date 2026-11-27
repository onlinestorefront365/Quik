from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel

from .approvals import (
    PENDING,
    ApprovalState,
    SelfApprovalError,
    TicketAlreadyDecidedError,
    compute_payload_hash,
)
from .models import ExecutionContext

# Tickets are Redis hashes (no JSON round-tripping inside Lua). Every state transition
# below is a single script, so concurrent callers are serialised by Redis.
#
# NOTE: scripts derive the ticket key from the hash index at run time, so this needs
# single-node Redis or Sentinel. Redis Cluster would require shared {hash-tags}.

# KEYS[1]=hash index, KEYS[2]=candidate ticket key
# ARGV[1]=candidate ticket id, ARGV[2]=ttl, ARGV[3..]=field/value pairs
CREATE_OR_GET_LUA = """
local existing = redis.call('GET', KEYS[1])
if existing then
  local st = redis.call('HGET', 'approval:ticket:' .. existing, 'status')
  if st then
    return {existing, st}
  end
end
redis.call('HSET', KEYS[2], unpack(ARGV, 3))
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return {ARGV[1], 'pending'}
"""

# KEYS[1]=ticket key; ARGV[1]=new status, ARGV[2]=reviewer id, ARGV[3]='1' if self-approval allowed
DECIDE_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'notfound'}
end
local st = redis.call('HGET', KEYS[1], 'status')
if st ~= 'pending' then
  return {'decided', st}
end
if ARGV[3] ~= '1' and ARGV[2] == redis.call('HGET', KEYS[1], 'user_id') then
  return {'self'}
end
redis.call('HSET', KEYS[1], 'status', ARGV[1], 'reviewer_id', ARGV[2])
local all = redis.call('HGETALL', KEYS[1])
table.insert(all, 1, 'ok')
return all
"""

# KEYS[1]=hash index; ARGV[1]=session id of the caller.
# Returns 1 consumed, 0 nothing to consume, -1 approved but bound to another session.
CONSUME_LUA = """
local ticket_id = redis.call('GET', KEYS[1])
if not ticket_id then
  return 0
end
local ticket_key = 'approval:ticket:' .. ticket_id
if redis.call('HGET', ticket_key, 'status') ~= 'approved' then
  return 0
end
if redis.call('HGET', ticket_key, 'session_id') ~= ARGV[1] then
  return -1
end
redis.call('HSET', ticket_key, 'status', 'consumed')
redis.call('DEL', KEYS[1])
return 1
"""


def _s(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


class RedisApprovalStore:
    """Distributed, TTL-bounded approval store with atomic transitions.

    - Create, decide and consume are each one Lua script (no check-then-write gaps).
    - A grant is single-use and bound to the session that requested it.
    - Rejected tickets keep their hash index, so an identical payload stays blocked
      until the TTL expires; changing any argument yields a new hash.
    - ``allow_self_approval`` is a plain policy flag (default False). The reviewer ID
      comes from the (HMAC-authenticated) approval app, so this guards against mistakes
      and naive abuse, not a compromised approval service.
    """

    def __init__(
        self, client: Any, ttl_seconds: int = 900, allow_self_approval: bool = False
    ) -> None:
        self._redis = client
        self._ttl = ttl_seconds
        self._allow_self_approval = allow_self_approval
        self._create = client.register_script(CREATE_OR_GET_LUA)
        self._decide = client.register_script(DECIDE_LUA)
        self._consume = client.register_script(CONSUME_LUA)

    compute_hash = staticmethod(compute_payload_hash)

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> ApprovalState:
        ticket_id = f"apr_{uuid.uuid4().hex[:12]}"
        fields = {
            "ticket_id": ticket_id,
            "payload_hash": payload_hash,
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "session_id": ctx.session_id,
            "tool_name": tool_name,
            "status": PENDING,
        }
        argv: list[Any] = [ticket_id, self._ttl]
        for k, v in fields.items():
            argv += [k, v]
        res = await self._create(
            keys=[f"approval:hash:{payload_hash}", f"approval:ticket:{ticket_id}"], args=argv
        )
        return ApprovalState(_s(res[0]), _s(res[1]))

    async def record_decision(
        self, ticket_id: str, *, approved: bool, reviewer_id: str
    ) -> dict[str, Any]:
        res = await self._decide(
            keys=[f"approval:ticket:{ticket_id}"],
            args=["approved" if approved else "rejected", reviewer_id,
                  "1" if self._allow_self_approval else "0"],
        )
        res = [_s(x) for x in res]
        if res[0] == "notfound":
            raise KeyError(f"Ticket '{ticket_id}' not found or expired.")
        if res[0] == "decided":
            raise TicketAlreadyDecidedError(f"Ticket '{ticket_id}' is already {res[1]}.")
        if res[0] == "self":
            raise SelfApprovalError("Reviewer cannot decide their own request.")
        return dict(zip(res[1::2], res[2::2]))

    async def consume_if_approved(self, ctx: ExecutionContext, payload_hash: str) -> bool:
        result = await self._consume(
            keys=[f"approval:hash:{payload_hash}"], args=[ctx.session_id]
        )
        return int(result) == 1
