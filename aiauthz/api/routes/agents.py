# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Agent lifecycle bookkeeping.

The gateway records provisioning, restart, and deletion events for downstream
audit. Actual container orchestration is handled outside this process; the
``agent_backend_url`` on a workspace lets the operator attach an external
runtime such as Hermes or OpenClaw.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token
from aiauthz.api.schemas import OkResponse, ProvisionAgentRequest
from aiauthz.db import models

router = APIRouter(prefix="/v1/agents", tags=["agents"])


@router.post("")
def provision(
    body: ProvisionAgentRequest,
    db: Session = Depends(db_session),
    admin: models.ApiToken = Depends(require_admin_token),
):
    if not db.get(models.Workspace, body.workspace_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace_not_found")
    db.add(models.AuditLog(
        actor_type="admin", actor_id=admin.owner_id,
        action="agents.provision", decision="allow",
        target_type="workspace", target_id=body.workspace_id,
        extra={"name": body.name, "config": body.config},
    ))
    db.commit()
    return {"agent_id": body.name, "workspace_id": body.workspace_id, "status": "registered"}


@router.get("/{agent_id}/status")
def status_(agent_id: str, db: Session = Depends(db_session), _admin=Depends(require_admin_token)):
    return {"agent_id": agent_id, "status": "unknown", "note": "external_lifecycle"}


@router.post("/{agent_id}/restart", response_model=OkResponse)
def restart(agent_id: str, db: Session = Depends(db_session), admin: models.ApiToken = Depends(require_admin_token)):
    db.add(models.AuditLog(
        actor_type="admin", actor_id=admin.owner_id,
        action="agents.restart", decision="allow",
        target_type="agent", target_id=agent_id,
    ))
    db.commit()
    return OkResponse()


@router.delete("/{agent_id}", response_model=OkResponse)
def delete_(agent_id: str, db: Session = Depends(db_session), admin: models.ApiToken = Depends(require_admin_token)):
    db.add(models.AuditLog(
        actor_type="admin", actor_id=admin.owner_id,
        action="agents.delete", decision="allow",
        target_type="agent", target_id=agent_id,
    ))
    db.commit()
    return OkResponse()
