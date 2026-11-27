from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from pydantic import BaseModel

from .models import ExecutionContext, RiskTier

ToolHandler = Callable[[Any, ExecutionContext], Awaitable[Any]]
DynamicRiskFn = Callable[[Any, ExecutionContext], RiskTier]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: type[BaseModel]
    required_permission: str
    base_risk: RiskTier
    handler: ToolHandler
    dynamic_risk: DynamicRiskFn | None = None
    timeout_seconds: float = 10.0


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        *,
        name: str,
        input_model: type[BaseModel],
        required_permission: str,
        base_risk: RiskTier = RiskTier.LOW,
        dynamic_risk: DynamicRiskFn | None = None,
        timeout_seconds: float = 10.0,
    ) -> Callable[[ToolHandler], ToolHandler]:
        def decorator(func: ToolHandler) -> ToolHandler:
            self._tools[name] = ToolSpec(
                name=name,
                input_model=input_model,
                required_permission=required_permission,
                base_risk=base_risk,
                handler=func,
                dynamic_risk=dynamic_risk,
                timeout_seconds=timeout_seconds,
            )
            return func

        return decorator

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)
