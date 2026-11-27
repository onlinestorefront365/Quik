from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel


class RiskTier(IntEnum):
    LOW = 1  # Read-only, idempotent lookups
    MEDIUM = 2  # Reversible state mutations within normal thresholds
    HIGH = 3  # Financial transfers, external emails, bulk writes
    CRITICAL = 4  # Destructive actions, privilege escalation, schema changes


class DecisionStatus(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    ERROR = "error"


@dataclass(frozen=True)
class ExecutionContext:
    """Trusted identity and budget metadata injected by the host application."""

    user_id: str
    tenant_id: str
    roles: frozenset[str]
    session_id: str
    max_tool_calls: int = 15
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ToolCallEnvelope:
    """Untrusted tool invocation emitted by the LLM."""

    call_id: str
    tool_name: str
    raw_args: dict[str, Any]
    parsed_args: BaseModel | None = None
    resolved_risk: RiskTier = RiskTier.LOW


@dataclass(frozen=True)
class ToolExecutionResult:
    """Structured outcome returned to the agent loop."""

    call_id: str
    status: DecisionStatus
    output: Any = None
    error: str | None = None
    approval_ticket_id: str | None = None
