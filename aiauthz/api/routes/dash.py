# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token
from aiauthz.db import models

router = APIRouter(prefix="/v1/dash", tags=["dash"])


@router.get("/summary")
def summary(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    counts = {
        "users": db.query(func.count(models.User.id)).scalar() or 0,
        "sessions": db.query(func.count(models.Session.id)).scalar() or 0,
        "messages": db.query(func.count(models.Message.id)).scalar() or 0,
        "tool_calls": db.query(func.count(models.ToolCall.id)).scalar() or 0,
        "audit_entries": db.query(func.count(models.AuditLog.id)).scalar() or 0,
    }
    by_decision = {
        d or "unknown": c
        for d, c in db.query(models.AuditLog.decision, func.count(models.AuditLog.id))
        .group_by(models.AuditLog.decision)
        .all()
    }
    return {"counts": counts, "by_decision": by_decision}


@router.get("/recent-decisions")
def recent_decisions(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
    limit: int = 50,
):
    rows = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id, "timestamp": r.timestamp,
            "action": r.action, "decision": r.decision, "reason": r.reason,
            "actor_type": r.actor_type, "actor_id": r.actor_id,
        }
        for r in rows
    ]
