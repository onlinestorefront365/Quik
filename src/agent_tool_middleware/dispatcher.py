from __future__ import annotations

import asyncio

from .middleware import NextFn, ToolMiddleware
from .models import (
    DecisionStatus,
    ExecutionContext,
    ToolCallEnvelope,
    ToolExecutionResult,
)
from .registry import ToolRegistry


class ToolDispatcher:
    def __init__(
        self, registry: ToolRegistry, middlewares: list[ToolMiddleware]
    ) -> None:
        self._registry = registry
        self._middlewares = middlewares

    async def _execute_terminal(
        self, envelope: ToolCallEnvelope, ctx: ExecutionContext
    ) -> ToolExecutionResult:
        spec = self._registry.get(envelope.tool_name)
        assert spec is not None and envelope.parsed_args is not None
        try:
            output = await asyncio.wait_for(
                spec.handler(envelope.parsed_args, ctx),
                timeout=spec.timeout_seconds,
            )
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.ALLOWED,
                output=output,
            )
        except asyncio.TimeoutError:
            return ToolExecutionResult(
                call_id=envelope.call_id,
                status=DecisionStatus.ERROR,
                error=f"Tool '{spec.name}' timed out after {spec.timeout_seconds}s.",
            )

    async def dispatch(
        self, envelope: ToolCallEnvelope, ctx: ExecutionContext
    ) -> ToolExecutionResult:
        handler: NextFn = self._execute_terminal
        for mw in reversed(self._middlewares):
            next_handler = handler

            async def wrapped(
                env: ToolCallEnvelope,
                context: ExecutionContext,
                _mw: ToolMiddleware = mw,
                _next: NextFn = next_handler,
            ) -> ToolExecutionResult:
                return await _mw(env, context, _next)

            handler = wrapped
        return await handler(envelope, ctx)
