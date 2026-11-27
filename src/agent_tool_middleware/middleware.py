from __future__ import annotations

import json
import time
from typing import Awaitable, Callable, Protocol

from pydantic import ValidationError

from .approvals import ApprovalStoreProtocol
from .models import (
    DecisionStatus,
    ExecutionContext,
    RiskTier,
    ToolCallEnvelope,
    ToolExecutionResult,
)
from .rbac import RBACPolicy
from .registry import ToolRegistry

NextFn = Callable[[ToolCallEnvelope, ExecutionContext], Awaitable[ToolExecutionResult]]


class ToolMiddleware(Protocol):
    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: NextFn,
    ) -> ToolExecutionResult: ...


class AuditAndBudgetMiddleware:
    """Enforces per-session step budgets and logs every intercepted call."""

    def __init__(self, logger: Callable[[str], None] = print) -> None:
        self._session_counts: dict[str, int] = {}
        self._logger = logger

    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: NextFn,
    ) -> ToolExecutionResult:
        count = self._session_counts.get(ctx.session_id, 0) + 1
        self._session_counts[ctx.session_id] = count
        if count > ctx.max_tool_calls:
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.DENIED,
                error="Session tool-call budget exceeded. Terminate or escalate.",
            )

        start = time.perf_counter()
        result = await call_next(envelope, ctx)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        audit_event = {
            "trace_id": ctx.trace_id,
            "session_id": ctx.session_id,
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "tool": envelope.tool_name,
            "risk": envelope.resolved_risk.name,
            "status": result.status.value,
            "ticket_id": result.approval_ticket_id,
            "latency_ms": elapsed_ms,
        }
        self._logger(f"[AUDIT] {json.dumps(audit_event)}")
        return result


class SchemaValidationMiddleware:
    """Rejects unknown tools and enforces strict Pydantic argument parsing."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: NextFn,
    ) -> ToolExecutionResult:
        spec = self._registry.get(envelope.tool_name)
        if spec is None:
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.DENIED,
                error=f"Unknown tool: {envelope.tool_name}",
            )
        try:
            envelope.parsed_args = spec.input_model.model_validate(envelope.raw_args)
        except ValidationError as exc:
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.ERROR,
                error=f"Schema validation failed: {exc.errors(include_url=False)}",
            )
        return await call_next(envelope, ctx)


class RBACMiddleware:
    """Verifies role permissions before allowing policy evaluation or execution."""

    def __init__(self, registry: ToolRegistry, policy: RBACPolicy) -> None:
        self._registry = registry
        self._policy = policy

    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: NextFn,
    ) -> ToolExecutionResult:
        spec = self._registry.get(envelope.tool_name)
        if spec is None:
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.DENIED,
                error=f"Unknown tool: {envelope.tool_name}",
            )
        if not self._policy.is_authorized(ctx.roles, spec.required_permission):
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.DENIED,
                error=(
                    f"Access denied: missing permission '{spec.required_permission}' "
                    f"for tool '{spec.name}'."
                ),
            )
        return await call_next(envelope, ctx)


class RiskGateMiddleware:
    """Evaluates static + dynamic risk and gates HIGH/CRITICAL calls."""

    def __init__(
        self,
        registry: ToolRegistry,
        approval_store: ApprovalStoreProtocol,
        gate_threshold: RiskTier = RiskTier.HIGH,
    ) -> None:
        self._registry = registry
        self._approval_store = approval_store
        self._gate_threshold = gate_threshold

    async def __call__(
        self,
        envelope: ToolCallEnvelope,
        ctx: ExecutionContext,
        call_next: NextFn,
    ) -> ToolExecutionResult:
        spec = self._registry.get(envelope.tool_name)
        assert spec is not None and envelope.parsed_args is not None

        effective_risk = spec.base_risk
        if spec.dynamic_risk is not None:
            dynamic = spec.dynamic_risk(envelope.parsed_args, ctx)
            effective_risk = max(effective_risk, dynamic)
        envelope.resolved_risk = effective_risk

        if effective_risk >= self._gate_threshold:
            payload_hash = self._approval_store.compute_hash(
                ctx, spec.name, envelope.parsed_args
            )
            if not await self._approval_store.consume_if_approved(payload_hash):
                ticket_id = await self._approval_store.create_or_get_pending(
                    ctx, spec.name, payload_hash
                )
                return ToolExecutionResult(
                    call_id=envelope.call_id,
                    status=DecisionStatus.PENDING_APPROVAL,
                    approval_ticket_id=ticket_id,
                    error=(
                        f"Action requires human approval (ticket={ticket_id}, "
                        f"risk={effective_risk.name}). Pause execution until approved."
                    ),
                )
        return await call_next(envelope, ctx)
