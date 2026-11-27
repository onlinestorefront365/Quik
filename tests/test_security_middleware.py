from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from agent_tool_middleware import (
    ABACOwnershipMiddleware,
    AuditAndBudgetMiddleware,
    DecisionStatus,
    ExecutionContext,
    RBACMiddleware,
    RBACPolicy,
    RiskGateMiddleware,
    RiskTier,
    SchemaValidationMiddleware,
    ToolCallEnvelope,
    ToolDispatcher,
    ToolRegistry,
    verify_order_ownership,
)
from agent_tool_middleware.redis_approvals import RedisApprovalStore
from conftest import new_redis


class RefundArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order_id: str = Field(pattern=r"^ORD-\d{6}$")
    amount_usd: float = Field(gt=0, le=10_000)


class MockOrdersDB:
    def __init__(self) -> None:
        self.orders = {
            ("org_alpha", "ORD-100001"): {
                "tenant_id": "org_alpha",
                "assigned_agent_id": "usr_agent_1",
                "status": "delivered",
            },
            ("org_beta", "ORD-999999"): {
                "tenant_id": "org_beta",
                "assigned_agent_id": "usr_other",
                "status": "delivered",
            },
        }

    async def fetch_one(self, query: str, params: dict[str, Any]) -> dict[str, Any] | None:
        return self.orders.get((params["tenant_id"], params["order_id"]))


@pytest.fixture
def security_harness():
    registry = ToolRegistry()
    executed_calls: list[dict[str, Any]] = []

    @registry.register(
        name="issue_refund",
        input_model=RefundArgs,
        required_permission="billing:refund:write",
        base_risk=RiskTier.MEDIUM,
        dynamic_risk=lambda args, ctx: RiskTier.HIGH if args.amount_usd >= 250.0 else RiskTier.MEDIUM,
    )
    async def issue_refund(args: RefundArgs, ctx: ExecutionContext) -> dict[str, Any]:
        executed_calls.append({"tenant_id": ctx.tenant_id, "args": args.model_dump()})
        return {"refunded": args.amount_usd}

    policy = RBACPolicy({
        "support_viewer": {"billing:refund:read"},
        "support_agent": {"billing:refund:read", "billing:refund:write"},
        "support_lead": {"billing:refund:read", "billing:refund:write"},
    })
    redis_client = new_redis()
    approval_store = RedisApprovalStore(redis_client, ttl_seconds=900)
    db = MockOrdersDB()

    dispatcher = ToolDispatcher(
        registry=registry,
        middlewares=[
            AuditAndBudgetMiddleware(logger=lambda _: None),
            SchemaValidationMiddleware(registry),
            RBACMiddleware(registry, policy),
            ABACOwnershipMiddleware({"issue_refund": verify_order_ownership}, lambda: db),
            RiskGateMiddleware(registry, approval_store, gate_threshold=RiskTier.HIGH),
        ],
    )
    return dispatcher, approval_store, executed_calls


@pytest.mark.asyncio
async def test_rejects_injected_tenant_override_in_args(security_harness) -> None:
    dispatcher, _, executed = security_harness
    ctx = ExecutionContext("usr_agent_1", "org_alpha", frozenset({"support_agent"}), "sess_1")
    res = await dispatcher.dispatch(
        ToolCallEnvelope(
            "c1",
            "issue_refund",
            {"order_id": "ORD-100001", "amount_usd": 20.0, "tenant_id": "org_beta"},
        ),
        ctx,
    )
    assert res.status == DecisionStatus.ERROR
    assert len(executed) == 0


@pytest.mark.asyncio
async def test_rbac_blocks_read_only_role(security_harness) -> None:
    dispatcher, _, executed = security_harness
    viewer = ExecutionContext("usr_viewer", "org_alpha", frozenset({"support_viewer"}), "sess_2")
    res = await dispatcher.dispatch(
        ToolCallEnvelope("c2", "issue_refund", {"order_id": "ORD-100001", "amount_usd": 20.0}),
        viewer,
    )
    assert res.status == DecisionStatus.DENIED
    assert "missing permission" in (res.error or "")
    assert len(executed) == 0


@pytest.mark.asyncio
async def test_abac_blocks_cross_tenant_idor_before_approval_gate(security_harness) -> None:
    dispatcher, _, executed = security_harness
    alpha_lead = ExecutionContext("usr_lead", "org_alpha", frozenset({"support_lead"}), "sess_3")
    res = await dispatcher.dispatch(
        ToolCallEnvelope("c3", "issue_refund", {"order_id": "ORD-999999", "amount_usd": 5000.0}),
        alpha_lead,
    )
    assert res.status == DecisionStatus.DENIED
    assert res.approval_ticket_id is None
    assert len(executed) == 0


@pytest.mark.asyncio
async def test_blocks_payload_tampering_and_replay_after_approval(security_harness) -> None:
    dispatcher, approval_store, executed = security_harness
    lead = ExecutionContext("usr_lead", "org_alpha", frozenset({"support_lead"}), "sess_4")
    call = ToolCallEnvelope("c4", "issue_refund", {"order_id": "ORD-100001", "amount_usd": 300.0})

    gated = await dispatcher.dispatch(call, lead)
    assert gated.status == DecisionStatus.PENDING_APPROVAL
    assert gated.approval_ticket_id is not None

    await approval_store.record_decision(
        gated.approval_ticket_id, approved=True, reviewer_id="mgr_1"
    )

    # Tampered amount must not ride on the approval for the original payload.
    tampered = await dispatcher.dispatch(
        ToolCallEnvelope("c4b", "issue_refund", {"order_id": "ORD-100001", "amount_usd": 9000.0}),
        lead,
    )
    assert tampered.status == DecisionStatus.PENDING_APPROVAL
    assert tampered.approval_ticket_id != gated.approval_ticket_id
    assert len(executed) == 0

    # The exact approved payload executes once.
    legit = await dispatcher.dispatch(call, lead)
    assert legit.status == DecisionStatus.ALLOWED
    assert len(executed) == 1

    # Replaying the same payload needs a fresh approval.
    replay = await dispatcher.dispatch(call, lead)
    assert replay.status == DecisionStatus.PENDING_APPROVAL
    assert len(executed) == 1


@pytest.mark.asyncio
async def test_circuit_breaker_halts_runaway_agent_loop(security_harness) -> None:
    dispatcher, _, executed = security_harness
    agent = ExecutionContext(
        "usr_agent_1", "org_alpha", frozenset({"support_agent"}), "sess_loop", max_tool_calls=2
    )
    call = ToolCallEnvelope("c5", "issue_refund", {"order_id": "ORD-100001", "amount_usd": 10.0})

    r1 = await dispatcher.dispatch(call, agent)
    r2 = await dispatcher.dispatch(call, agent)
    r3 = await dispatcher.dispatch(call, agent)

    assert r1.status == DecisionStatus.ALLOWED
    assert r2.status == DecisionStatus.ALLOWED
    assert r3.status == DecisionStatus.DENIED
    assert "budget exceeded" in (r3.error or "")
    assert len(executed) == 2
