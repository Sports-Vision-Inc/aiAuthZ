# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token, require_service_token
from aiauthz.api.schemas import (
    EnrollUserRequest,
    EnrollUserResponse,
    MintTokenRequest,
    MintTokenResponse,
    OkResponse,
    RevokeRequest,
    RotateKeyRequest,
    RotateKeyResponse,
)
from aiauthz.core.crypto import (
    encrypt,
    generate_service_token,
    generate_user_hmac_key,
    hash_token,
)
from aiauthz.db import models

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.post("/enroll", response_model=EnrollUserResponse)
def enroll_user(
    body: EnrollUserRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    if not db.get(models.Workspace, body.workspace_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace_not_found")
    raw_key = generate_user_hmac_key()
    seed = secrets.token_bytes(32)
    user = models.User(
        workspace_id=body.workspace_id,
        email=body.email,
        role=body.role,
        hmac_key_encrypted=encrypt(raw_key),
        watermark_seed_encrypted=encrypt(seed),
    )
    db.add(user)
    db.add(models.AuditLog(
        actor_type="admin", actor_id=_admin.owner_id,
        action="auth.enroll", target_type="user", target_id=user.id,
        decision="allow", reason="enrolled",
    ))
    db.commit()
    return EnrollUserResponse(user_id=user.id, hmac_key=raw_key.hex())


@router.post("/rotate-key", response_model=RotateKeyResponse)
def rotate_key(
    body: RotateKeyRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    user = db.get(models.User, body.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user_not_found")
    raw_key = generate_user_hmac_key()
    user.hmac_key_encrypted = encrypt(raw_key)
    db.add(models.AuditLog(
        actor_type="admin", actor_id=_admin.owner_id,
        action="auth.rotate_key", target_type="user", target_id=user.id,
        decision="allow",
    ))
    db.commit()
    return RotateKeyResponse(user_id=user.id, hmac_key=raw_key.hex())


@router.post("/revoke", response_model=OkResponse)
def revoke_user(
    body: RevokeRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    user = db.get(models.User, body.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user_not_found")
    user.status = "revoked"
    db.add(models.AuditLog(
        actor_type="admin", actor_id=_admin.owner_id,
        action="auth.revoke", target_type="user", target_id=user.id,
        decision="allow",
    ))
    db.commit()
    return OkResponse()


@router.post("/tokens", response_model=MintTokenResponse)
def mint_token(
    body: MintTokenRequest,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    raw = generate_service_token()
    expires_at = None
    if body.ttl_seconds:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    token = models.ApiToken(
        owner_id=body.owner_id,
        owner_type=body.owner_type,
        token_hash=hash_token(raw),
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    return MintTokenResponse(token_id=token.id, token=raw)


@router.delete("/tokens/{token_id}", response_model=OkResponse)
def revoke_token(
    token_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    token = db.get(models.ApiToken, token_id)
    if not token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token_not_found")
    token.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return OkResponse()


@router.get("/me")
def me(token: models.ApiToken = Depends(require_service_token)):
    return {
        "token_id": token.id,
        "owner_id": token.owner_id,
        "owner_type": token.owner_type,
        "scopes": token.scopes,
        "expires_at": token.expires_at,
    }
