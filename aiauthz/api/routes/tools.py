# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import hashlib
import json
import time

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_service_token
from aiauthz.api.schemas import ToolCallEnvelope, ToolCallResponse
from aiauthz.core.audit_chain import append_audit
from aiauthz.core.crypto import encrypt
from aiauthz.core.redis_client import get_redis
from aiauthz.db import models
from aiauthz.policy import evaluate, get_effective_policy
from aiauthz.policy.engine import PolicyDecision
from aiauthz.tools import TOOL_NAMES, get_executor

router = APIRouter(prefix="/v1/tools", tags=["tools"])


def _rate_limit_for(policy: dict, tool_name: str) -> int | None:
    rl = policy.get("rate_limits") or {}
    if tool_name in rl:
        return int(rl[tool_name])
    if "default" in rl:
        return int(rl["default"])
    return None


def _rate_exceeded(workspace_id: str, tool_name: str, limit: int) -> bool:
    """Fixed-window per-minute counter in Redis, per (workspace, tool)."""
    import time as _t
    r = get_redis()
    window = int(_t.time()) // 60
    key = f"aiauthz:rl:{workspace_id}:{tool_name}:{window}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, 120)
    return count > limit


def _resolve_active_user(
    db: Session,
    *,
    session_id: str,
    active_message_id: str,
) -> models.User:
    r = get_redis()
    bound = r.get(f"aiauthz:active:{session_id}")
    if not bound:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no_active_user_for_session")
    user_id, last_msg = bound.split("|", 1)
    if last_msg != active_message_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "active_message_id_mismatch")
    user = db.get(models.User, user_id)
    if not user or user.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "user_inactive")
    return user


def _execute_tool(
    *,
    db: Session,
    tool_name: str,
    body: ToolCallEnvelope,
    session_id: str,
    active_message_id: str,
    service_token: models.ApiToken,
) -> ToolCallResponse:
    user = _resolve_active_user(
        db, session_id=session_id, active_message_id=active_message_id
    )
    policy = get_effective_policy(db, workspace_id=user.workspace_id, user_id=user.id)
    decision = evaluate(policy=policy, tool_name=tool_name, role=user.role, args=body.args)

    # Rate limiting (resource-exhaustion / DoS mitigation). Only meter calls
    # that pass policy, so denials are free and cannot themselves exhaust quota.
    if decision.allow:
        limit = _rate_limit_for(policy, tool_name)
        if limit is not None and _rate_exceeded(user.workspace_id, tool_name, limit):
            decision = PolicyDecision(False, f"rate_limit_exceeded:{tool_name}:{limit}/min")

    args_json = json.dumps(body.args, sort_keys=True, separators=(",", ":"))
    args_hash = hashlib.sha256(args_json.encode("utf-8")).hexdigest()
    started = time.perf_counter()

    call = models.ToolCall(
        workspace_id=user.workspace_id,
        session_id=session_id,
        message_id=active_message_id,
        tool_name=tool_name,
        args_hash=args_hash,
        args_encrypted=encrypt(args_json.encode("utf-8")),
        decision="allow" if decision.allow else "deny",
        reason=decision.reason,
    )

    if not decision.allow:
        latency_ms = int((time.perf_counter() - started) * 1000)
        call.latency_ms = latency_ms
        db.add(call)
        append_audit(
            db,
            workspace_id=user.workspace_id,
            actor_type="agent", actor_id=service_token.owner_id,
            action=f"tools.{tool_name}", decision="deny", reason=decision.reason,
            target_type="user", target_id=user.id,
            request_hash=args_hash,
            extra={"session_id": session_id, "message_id": active_message_id},
        )
        db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"call_id": call.id, "reason": decision.reason},
        )

    executor = get_executor(tool_name)
    result = executor(body.args)
    latency_ms = int((time.perf_counter() - started) * 1000)
    call.latency_ms = latency_ms
    result_blob = json.dumps({
        "executed": result.executed,
        "tool_name": result.tool_name,
        "result": result.result,
        "note": result.note,
    }).encode("utf-8")
    call.result_encrypted = encrypt(result_blob)
    db.add(call)
    append_audit(
        db,
        workspace_id=user.workspace_id,
        actor_type="agent", actor_id=service_token.owner_id,
        action=f"tools.{tool_name}", decision="allow", reason=decision.reason,
        target_type="user", target_id=user.id,
        request_hash=args_hash,
        extra={
            "session_id": session_id,
            "message_id": active_message_id,
            "executed": result.executed,
        },
    )
    db.commit()

    return ToolCallResponse(
        call_id=call.id,
        decision="allow",
        reason=decision.reason,
        executed=result.executed,
        result=result.result,
    )


# Each tool gets its own URL so policy, metrics, and the MCP manifest can
# key on the path. All paths funnel through a single dispatcher.
def _make_handler(tool_name: str):
    def handler(
        body: ToolCallEnvelope,
        db: Session = Depends(db_session),
        token: models.ApiToken = Depends(require_service_token),
        x_session_id: str = Header(...),
        x_active_message_id: str = Header(...),
    ):
        return _execute_tool(
            db=db,
            tool_name=tool_name,
            body=body,
            session_id=x_session_id,
            active_message_id=x_active_message_id,
            service_token=token,
        )
    handler.__name__ = f"tool_{tool_name}"
    return handler


for _name in TOOL_NAMES:
    router.post(f"/{_name}", response_model=ToolCallResponse)(_make_handler(_name))


@router.post("/custom/{tool_name}", response_model=ToolCallResponse)
def custom_tool(
    tool_name: str,
    body: ToolCallEnvelope,
    db: Session = Depends(db_session),
    token: models.ApiToken = Depends(require_service_token),
    x_session_id: str = Header(...),
    x_active_message_id: str = Header(...),
):
    return _execute_tool(
        db=db,
        tool_name=f"custom:{tool_name}",
        body=body,
        session_id=x_session_id,
        active_message_id=x_active_message_id,
        service_token=token,
    )
