from __future__ import annotations

import asyncio

import pytest
from pydantic import BaseModel

from agent_tool_middleware import ExecutionContext, SelfApprovalError, TicketAlreadyDecidedError
from agent_tool_middleware.approvals import InMemoryApprovalStore
from agent_tool_middleware.redis_approvals import RedisApprovalStore
from conftest import new_redis


class Args(BaseModel):
    amount: int


def ctx(session: str = "sess_1", user: str = "usr_req") -> ExecutionContext:
    return ExecutionContext(user, "org_a", frozenset({"support_lead"}), session)


@pytest.fixture(params=["redis", "memory"])
def store(request):
    if request.param == "redis":
        return RedisApprovalStore(new_redis(), ttl_seconds=900)
    return InMemoryApprovalStore()


async def _ticket(store, c: ExecutionContext | None = None, amount: int = 500):
    c = c or ctx()
    h = store.compute_hash(c, "refund", Args(amount=amount))
    return h, (await store.create_or_get_pending(c, "refund", h)).ticket_id


async def test_concurrent_create_yields_one_ticket(store) -> None:
    c = ctx()
    h = store.compute_hash(c, "refund", Args(amount=500))
    states = await asyncio.gather(*[store.create_or_get_pending(c, "refund", h) for _ in range(50)])
    assert len({s.ticket_id for s in states}) == 1
    assert {s.status for s in states} == {"pending"}


@pytest.mark.parametrize("approve_first", [True, False])
async def test_approve_vs_reject_exactly_one_wins(store, approve_first: bool) -> None:
    for i in range(50):
        _, tid = await _ticket(store, ctx(user=f"u{i}"))
        calls = [
            store.record_decision(tid, approved=True, reviewer_id="mgr_a"),
            store.record_decision(tid, approved=False, reviewer_id="mgr_b"),
        ]
        if not approve_first:
            calls.reverse()
        res = await asyncio.gather(*calls, return_exceptions=True)
        ok = [r for r in res if isinstance(r, dict)]
        errs = [r for r in res if isinstance(r, TicketAlreadyDecidedError)]
        assert len(ok) == 1 and len(errs) == 1
        with pytest.raises(TicketAlreadyDecidedError):
            await store.record_decision(tid, approved=True, reviewer_id="mgr_c")


async def test_double_consume_succeeds_once(store) -> None:
    c = ctx()
    h, tid = await _ticket(store, c)
    await store.record_decision(tid, approved=True, reviewer_id="mgr_1")
    results = await asyncio.gather(*[store.consume_if_approved(c, h) for _ in range(20)])
    assert results.count(True) == 1


async def test_grant_is_bound_to_requesting_session(store) -> None:
    h, tid = await _ticket(store, ctx("sess_1"))
    await store.record_decision(tid, approved=True, reviewer_id="mgr_1")
    other = ctx("sess_2")  # same user, tenant and args, different session
    assert await store.consume_if_approved(other, h) is False
    assert (await store.create_or_get_pending(other, "refund", h)).status == "approved"
    # The wrong-session attempt must not burn the grant.
    assert await store.consume_if_approved(ctx("sess_1"), h) is True
    assert await store.consume_if_approved(ctx("sess_1"), h) is False


async def test_consume_race_across_sessions_only_owner_wins(store) -> None:
    h, tid = await _ticket(store, ctx("sess_1"))
    await store.record_decision(tid, approved=True, reviewer_id="mgr_1")
    cs = [ctx("sess_1"), ctx("sess_2"), ctx("sess_3")] * 5
    results = await asyncio.gather(*[store.consume_if_approved(c, h) for c in cs])
    assert [c.session_id for c, ok in zip(cs, results) if ok] == ["sess_1"]


async def test_rejected_payload_stays_blocked_but_changed_args_do_not(store) -> None:
    c = ctx()
    h, tid = await _ticket(store, c, amount=500)
    await store.record_decision(tid, approved=False, reviewer_id="mgr_1")
    again = await store.create_or_get_pending(c, "refund", h)
    assert (again.ticket_id, again.status) == (tid, "rejected")
    assert await store.consume_if_approved(c, h) is False
    h2, tid2 = await _ticket(store, c, amount=501)
    assert h2 != h and tid2 != tid


async def test_self_approval_refused_by_default_and_ticket_stays_pending(store) -> None:
    c = ctx(user="usr_req")
    h, tid = await _ticket(store, c)
    with pytest.raises(SelfApprovalError):
        await store.record_decision(tid, approved=True, reviewer_id="usr_req")
    assert (await store.create_or_get_pending(c, "refund", h)).status == "pending"
    await store.record_decision(tid, approved=True, reviewer_id="mgr_1")


async def test_self_approval_allowed_with_flag() -> None:
    for s in (RedisApprovalStore(new_redis(), allow_self_approval=True),
              InMemoryApprovalStore(allow_self_approval=True)):
        _, tid = await _ticket(s, ctx(user="usr_req"))
        rec = await s.record_decision(tid, approved=True, reviewer_id="usr_req")
        assert rec["status"] == "approved"


async def test_missing_ticket_raises_keyerror(store) -> None:
    with pytest.raises(KeyError):
        await store.record_decision("apr_nope", approved=True, reviewer_id="mgr_1")
