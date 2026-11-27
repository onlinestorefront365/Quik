from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol

from pydantic import BaseModel

from .models import DecisionStatus, ExecutionContext, ToolCallEnvelope, ToolExecutionResult


class AsyncDB(Protocol):
    async def fetch_one(
        self, query: str, params: dict[str, Any]
    ) -> dict[str, Any] | None: ...


OwnershipGuardFn = Callable[[Any, ExecutionContext, AsyncDB], Awaitable[bool]]


class ABACOwnershipMiddleware:
    """Enforces row-level tenant and owner isolation prior to risk gating or execution."""

    def __init__(
        self,
        guards: dict[str, OwnershipGuardFn],
        db_factory: Callable[[], AsyncDB],
    ) -> None:
        self._guards = guards
        self._db_factory = db_factory

    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: Callable[[ToolCallEnvelope, ExecutionContext], Awaitable[ToolExecutionResult]],
    ) -> ToolExecutionResult:
        guard = self._guards.get(envelope.tool_name)
        if guard is not None:
            db = self._db_factory()
            is_owner = await guard(envelope.parsed_args, ctx, db)
            if not is_owner:
                return ToolExecutionResult(
                    call_id=envelope.call_id,
                    status=DecisionStatus.DENIED,
                    error="Resource not found or access denied under current tenant scope.",
                )
        return await call_next(envelope, ctx)


async def verify_order_ownership(
    args: BaseModel, ctx: ExecutionContext, db: AsyncDB
) -> bool:
    """Verifies the target order belongs to ctx.tenant_id and, for non-leads, ctx.user_id."""
    row = await db.fetch_one(
        """
        SELECT tenant_id, assigned_agent_id, status
        FROM orders
        WHERE order_id = :order_id
          AND tenant_id = :tenant_id
        LIMIT 1
        """,
        {"order_id": getattr(args, "order_id"), "tenant_id": ctx.tenant_id},
    )
    if row is None:
        return False
    if "support_lead" in ctx.roles or "tenant_admin" in ctx.roles:
        return True
    return row["assigned_agent_id"] == ctx.user_id
