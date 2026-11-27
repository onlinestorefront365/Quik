from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_tool_middleware import (
    ABACOwnershipMiddleware,
    AuditAndBudgetMiddleware,
    ExecutionContext,
    InMemoryApprovalStore,
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


class InMemoryOrdersDB:
    def __init__(self) -> None:
        self.orders = {
            ("org_99", "ORD-100234"): {
                "tenant_id": "org_99",
                "assigned_agent_id": "usr_1",
                "status": "delivered",
            }
        }

    async def fetch_one(self, query: str, params: dict[str, Any]) -> dict[str, Any] | None:
        return self.orders.get((params["tenant_id"], params["order_id"]))


registry = ToolRegistry()


class RefundInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order_id: str = Field(pattern=r"^ORD-\d{6}$")
    amount_usd: float = Field(gt=0, le=10_000)
    reason: str = Field(min_length=5, max_length=200)


def evaluate_refund_risk(args: RefundInput, ctx: ExecutionContext) -> RiskTier:
    return RiskTier.HIGH if args.amount_usd >= 250.0 else RiskTier.MEDIUM


@registry.register(
    name="issue_refund",
    input_model=RefundInput,
    required_permission="billing:refund:write",
    base_risk=RiskTier.MEDIUM,
    dynamic_risk=evaluate_refund_risk,
)
async def issue_refund(args: RefundInput, ctx: ExecutionContext) -> dict[str, Any]:
    return {
        "refunded": True,
        "order_id": args.order_id,
        "amount_usd": args.amount_usd,
        "processed_for_tenant": ctx.tenant_id,
    }


async def main() -> None:
    policy = RBACPolicy({
        "support_viewer": {"billing:refund:read"},
        "support_lead": {"billing:refund:read", "billing:refund:write"},
    })
    approvals = InMemoryApprovalStore()
    db = InMemoryOrdersDB()

    dispatcher = ToolDispatcher(
        registry=registry,
        middlewares=[
            AuditAndBudgetMiddleware(),
            SchemaValidationMiddleware(registry),
            RBACMiddleware(registry, policy),
            ABACOwnershipMiddleware({"issue_refund": verify_order_ownership}, lambda: db),
            RiskGateMiddleware(registry, approvals, gate_threshold=RiskTier.HIGH),
        ],
    )

    # 1. Unauthorized role blocked at RBAC layer
    viewer_ctx = ExecutionContext("usr_1", "org_99", frozenset({"support_viewer"}), "sess_a")
    call = ToolCallEnvelope(
        "c1",
        "issue_refund",
        {"order_id": "ORD-100234", "amount_usd": 50, "reason": "Damaged box"},
    )
    print("Viewer attempt:", await dispatcher.dispatch(call, viewer_ctx))

    # 2. Authorized lead triggers dynamic HIGH risk gate ($500 >= $250)
    lead_ctx = ExecutionContext("usr_2", "org_99", frozenset({"support_lead"}), "sess_b")
    high_call = ToolCallEnvelope(
        "c2",
        "issue_refund",
        {"order_id": "ORD-100234", "amount_usd": 500, "reason": "Full return"},
    )
    gated = await dispatcher.dispatch(high_call, lead_ctx)
    print("High-value attempt:", gated)

    # 3. Human approves ticket out-of-band; agent resumes exact call
    assert gated.approval_ticket_id is not None
    await approvals.approve_ticket(gated.approval_ticket_id)
    resumed = await dispatcher.dispatch(high_call, lead_ctx)
    print("Resumed after approval:", resumed)


if __name__ == "__main__":
    asyncio.run(main())
