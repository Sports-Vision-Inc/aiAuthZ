# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token
from aiauthz.api.schemas import (
    CreateOrgRequest,
    CreateTeamRequest,
    CreateWorkspaceRequest,
)
from aiauthz.db import models

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.post("/orgs")
def create_org(
    body: CreateOrgRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    org = models.Organization(name=body.name, plan=body.plan, retention_settings={})
    db.add(org)
    db.commit()
    return {"id": org.id, "name": org.name, "plan": org.plan}


@router.get("/orgs")
def list_orgs(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    return [{"id": o.id, "name": o.name, "plan": o.plan} for o in db.query(models.Organization).all()]


@router.post("/teams")
def create_team(
    body: CreateTeamRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    if not db.get(models.Organization, body.org_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org_not_found")
    team = models.Team(org_id=body.org_id, name=body.name)
    db.add(team)
    db.commit()
    return {"id": team.id, "org_id": team.org_id, "name": team.name}


@router.post("/workspaces")
def create_workspace(
    body: CreateWorkspaceRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    if not db.get(models.Team, body.team_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team_not_found")
    ws = models.Workspace(
        team_id=body.team_id, name=body.name, agent_backend_url=body.agent_backend_url
    )
    db.add(ws)
    db.commit()
    return {"id": ws.id, "team_id": ws.team_id, "name": ws.name}


@router.get("/workspaces")
def list_workspaces(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    return [
        {"id": w.id, "team_id": w.team_id, "name": w.name, "agent_backend_url": w.agent_backend_url}
        for w in db.query(models.Workspace).all()
    ]


@router.get("/workspaces/{workspace_id}/members")
def list_members(
    workspace_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    return [
        {"id": u.id, "email": u.email, "role": u.role, "status": u.status}
        for u in db.query(models.User).filter_by(workspace_id=workspace_id).all()
    ]
