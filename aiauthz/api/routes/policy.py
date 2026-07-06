# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token
from aiauthz.api.schemas import PolicyApplyTemplateRequest, PolicySetRequest
from aiauthz.db import models
from aiauthz.policy import (
    DEFAULT_POLICY_YAML,
    apply_template,
    get_effective_policy,
    list_templates,
    set_policy,
)

router = APIRouter(prefix="/v1/policy", tags=["policy"])


@router.get("")
def get_policy(
    scope: str,
    id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    if scope == "workspace":
        return get_effective_policy(db, workspace_id=id)
    if scope == "user":
        user = db.get(models.User, id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user_not_found")
        return get_effective_policy(db, workspace_id=user.workspace_id, user_id=id)
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "scope_must_be_workspace_or_user")


@router.put("")
def put_policy(
    body: PolicySetRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    try:
        row = set_policy(
            db,
            scope_type=body.scope_type,
            scope_id=body.scope_id,
            policy_yaml=body.policy_yaml,
        )
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "policy_yaml_invalid")
    db.commit()
    return {"id": row.id, "scope_type": row.scope_type, "scope_id": row.scope_id}


@router.get("/templates")
def get_templates(_admin: models.ApiToken = Depends(require_admin_token)):
    return {"templates": list_templates(), "default": DEFAULT_POLICY_YAML}


@router.post("/from-template")
def post_from_template(
    body: PolicyApplyTemplateRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    try:
        row = apply_template(
            db, template=body.template, scope_type=body.scope_type, scope_id=body.scope_id
        )
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "template_not_found")
    db.commit()
    return {"id": row.id, "scope_type": row.scope_type, "scope_id": row.scope_id}
