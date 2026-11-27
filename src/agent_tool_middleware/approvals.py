from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel

from .models import ExecutionContext

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
CONSUMED = "consumed"


class TicketAlreadyDecidedError(ValueError):
    """The ticket is no longer pending (already approved, rejected or consumed)."""


class SelfApprovalError(PermissionError):
    """The reviewer is the user who requested the action."""


def compute_payload_hash(ctx: ExecutionContext, tool_name: str, args: BaseModel) -> str:
    """Hash binding tenant, user, tool and exact arguments.

    The session ID is deliberately excluded: an approval is for an action, not for a
    conversation. The session is stored on the ticket and enforced at consume time.
    """
    canonical = json.dumps(
        {
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "tool_name": tool_name,
            "args": args.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalState:
    ticket_id: str
    status: str


class ApprovalStoreProtocol(Protocol):
    @staticmethod
    def compute_hash(ctx: ExecutionContext, tool_name: str, args: BaseModel) -> str: ...

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> ApprovalState: ...

    async def consume_if_approved(self, ctx: ExecutionContext, payload_hash: str) -> bool: ...


@dataclass
class ApprovalTicket:
    ticket_id: str
    payload_hash: str
    tenant_id: str
    user_id: str
    session_id: str
    tool_name: str
    status: str = PENDING
    reviewer_id: str | None = None


class InMemoryApprovalStore:
    """Single-process approval ticket store for local development and testing.

    Mirrors the semantics of ``RedisApprovalStore``: session-bound single-use grants,
    rejected payloads stay blocked, and self-approval is refused by default.
    """

    def __init__(self, allow_self_approval: bool = False) -> None:
        self._tickets: dict[str, ApprovalTicket] = {}
        self._allow_self_approval = allow_self_approval

    compute_hash = staticmethod(compute_payload_hash)

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> ApprovalState:
        for ticket in self._tickets.values():
            if ticket.payload_hash == payload_hash and ticket.status != CONSUMED:
                return ApprovalState(ticket.ticket_id, ticket.status)
        ticket_id = f"apr_{uuid.uuid4().hex[:12]}"
        self._tickets[ticket_id] = ApprovalTicket(
            ticket_id=ticket_id,
            payload_hash=payload_hash,
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            session_id=ctx.session_id,
            tool_name=tool_name,
        )
        return ApprovalState(ticket_id, PENDING)

    async def record_decision(
        self, ticket_id: str, *, approved: bool, reviewer_id: str
    ) -> dict[str, Any]:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise KeyError(f"Ticket '{ticket_id}' not found or expired.")
        if ticket.status != PENDING:
            raise TicketAlreadyDecidedError(f"Ticket '{ticket_id}' is already {ticket.status}.")
        if not self._allow_self_approval and reviewer_id == ticket.user_id:
            raise SelfApprovalError("Reviewer cannot decide their own request.")
        ticket.status = APPROVED if approved else REJECTED
        ticket.reviewer_id = reviewer_id
        return {
            "ticket_id": ticket.ticket_id,
            "session_id": ticket.session_id,
            "user_id": ticket.user_id,
            "status": ticket.status,
            "reviewer_id": reviewer_id,
        }

    async def approve_ticket(self, ticket_id: str, reviewer_id: str = "reviewer") -> None:
        await self.record_decision(ticket_id, approved=True, reviewer_id=reviewer_id)

    async def consume_if_approved(self, ctx: ExecutionContext, payload_hash: str) -> bool:
        for ticket in self._tickets.values():
            if (
                ticket.payload_hash == payload_hash
                and ticket.status == APPROVED
                and ticket.session_id == ctx.session_id
            ):
                ticket.status = CONSUMED
                return True
        return False
