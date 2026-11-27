from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
from fastapi import FastAPI

from agent_tool_middleware import ExecutionContext
from agent_tool_middleware.redis_approvals import RedisApprovalStore
from agent_tool_middleware.webhooks import build_approval_router
from conftest import new_redis

SECRET = b"test-secret"


def _sign(body: bytes, secret: bytes = SECRET) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


async def _make_app():
    store = RedisApprovalStore(new_redis(), ttl_seconds=900)
    ctx = ExecutionContext("usr_lead", "org_alpha", frozenset({"support_lead"}), "sess_w")
    ticket_id = (await store.create_or_get_pending(ctx, "issue_refund", "hash_1")).ticket_id
    resumed: list[tuple[str, str, bool]] = []

    async def resume(session_id: str, tid: str, approved: bool) -> None:
        resumed.append((session_id, tid, approved))

    app = FastAPI()
    app.include_router(build_approval_router(store, resume, webhook_secret=SECRET))
    return app, ticket_id, resumed


@pytest.mark.asyncio
async def test_valid_signature_records_decision_and_resumes_agent() -> None:
    app, ticket_id, resumed = await _make_app()
    body = json.dumps({"approved": True, "reviewer_id": "mgr_1"}).encode()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            f"/webhooks/approvals/{ticket_id}/decision",
            content=body,
            headers={"X-Webhook-Signature": _sign(body), "Content-Type": "application/json"},
        )
    assert r.status_code == 200
    assert r.json() == {"ticket_id": ticket_id, "status": "approved"}
    assert resumed == [("sess_w", ticket_id, True)]


@pytest.mark.asyncio
async def test_bad_signature_is_rejected_and_nothing_resumes() -> None:
    app, ticket_id, resumed = await _make_app()
    body = json.dumps({"approved": True, "reviewer_id": "attacker"}).encode()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            f"/webhooks/approvals/{ticket_id}/decision",
            content=body,
            headers={"X-Webhook-Signature": _sign(body, b"wrong"), "Content-Type": "application/json"},
        )
    assert r.status_code == 401
    assert resumed == []


def test_refuses_to_start_without_secret(monkeypatch) -> None:
    monkeypatch.delenv("APPROVAL_WEBHOOK_SECRET", raising=False)
    store = RedisApprovalStore(new_redis())

    async def resume(*_: object) -> None: ...

    with pytest.raises(RuntimeError):
        build_approval_router(store, resume)


@pytest.mark.asyncio
async def test_self_approval_is_forbidden_and_unknown_or_decided_map_to_404_409() -> None:
    app, ticket_id, resumed = await _make_app()

    async def post(tid: str, reviewer: str, approved: bool = True):
        body = json.dumps({"approved": approved, "reviewer_id": reviewer}).encode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            return await c.post(
                f"/webhooks/approvals/{tid}/decision",
                content=body,
                headers={"X-Webhook-Signature": _sign(body), "Content-Type": "application/json"},
            )

    assert (await post(ticket_id, "usr_lead")).status_code == 403  # requester == reviewer
    assert resumed == []
    assert (await post("apr_missing", "mgr_1")).status_code == 404
    assert (await post(ticket_id, "mgr_1")).status_code == 200
    assert (await post(ticket_id, "mgr_2", approved=False)).status_code == 409
