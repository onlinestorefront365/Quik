from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from .models import ExecutionContext


class ApprovalStoreProtocol(Protocol):
    @staticmethod
    def compute_hash(ctx: ExecutionContext, tool_name: str, args: BaseModel) -> str: ...

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> str: ...

    async def consume_if_approved(self, payload_hash: str) -> bool: ...


@dataclass
class ApprovalTicket:
    ticket_id: str
    payload_hash: str
    tenant_id: str
    user_id: str
    session_id: str
    tool_name: str
    approved: bool = False
    consumed: bool = False


class InMemoryApprovalStore:
    """Single-process approval ticket store for local development and testing."""

    def __init__(self) -> None:
        self._tickets: dict[str, ApprovalTicket] = {}

    @staticmethod
    def compute_hash(ctx: ExecutionContext, tool_name: str, args: BaseModel) -> str:
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

    async def create_or_get_pending(
        self, ctx: ExecutionContext, tool_name: str, payload_hash: str
    ) -> str:
        for ticket in self._tickets.values():
            if ticket.payload_hash == payload_hash and not ticket.consumed:
                return ticket.ticket_id
        ticket_id = f"apr_{uuid.uuid4().hex[:12]}"
        self._tickets[ticket_id] = ApprovalTicket(
            ticket_id=ticket_id,
            payload_hash=payload_hash,
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            session_id=ctx.session_id,
            tool_name=tool_name,
        )
        return ticket_id

    async def approve_ticket(self, ticket_id: str) -> None:
        if ticket_id not in self._tickets:
            raise KeyError(f"Unknown approval ticket: {ticket_id}")
        self._tickets[ticket_id].approved = True

    async def consume_if_approved(self, payload_hash: str) -> bool:
        for ticket in self._tickets.values():
            if (
                ticket.payload_hash == payload_hash
                and ticket.approved
                and not ticket.consumed
            ):
                ticket.consumed = True
                return True
        return False
