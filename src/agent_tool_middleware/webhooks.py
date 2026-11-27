from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from pydantic import BaseModel

from .redis_approvals import RedisApprovalStore


class ApprovalDecisionPayload(BaseModel):
    approved: bool
    reviewer_id: str


def verify_hmac_signature(
    raw_body: bytes, signature_header: str, secret: bytes
) -> None:
    expected = "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode("utf-8"), signature_header.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )


def build_approval_router(
    store: RedisApprovalStore,
    resume_agent_callback: Callable[[str, str, bool], Awaitable[None]],
    webhook_secret: bytes | None = None,
) -> APIRouter:
    secret = webhook_secret
    if secret is None:
        env_secret = os.environ.get("APPROVAL_WEBHOOK_SECRET")
        if not env_secret:
            raise RuntimeError(
                "Approval webhook secret not configured: pass webhook_secret or set "
                "APPROVAL_WEBHOOK_SECRET."
            )
        secret = env_secret.encode("utf-8")

    router = APIRouter(prefix="/webhooks/approvals", tags=["approvals"])

    @router.post("/{ticket_id}/decision")
    async def handle_approval_decision(
        ticket_id: str,
        request: Request,
        background_tasks: BackgroundTasks,
        x_webhook_signature: str = Header(...),
    ) -> dict[str, Any]:
        raw_body = await request.body()
        verify_hmac_signature(raw_body, x_webhook_signature, secret)
        payload = ApprovalDecisionPayload.model_validate_json(raw_body)
        try:
            record = await store.record_decision(
                ticket_id,
                approved=payload.approved,
                reviewer_id=payload.reviewer_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        background_tasks.add_task(
            resume_agent_callback,
            record["session_id"],
            ticket_id,
            payload.approved,
        )
        return {"ticket_id": ticket_id, "status": record["status"]}

    return router
