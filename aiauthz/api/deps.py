# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from aiauthz.core.crypto import hash_token
from aiauthz.db import get_db, models


def db_session() -> Iterator[Session]:
    yield from get_db()


def require_service_token(
    authorization: str | None = Header(default=None),
    db: Session = Depends(db_session),
) -> models.ApiToken:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing_bearer_token")
    raw = authorization.split(" ", 1)[1].strip()
    token = (
        db.query(models.ApiToken)
        .filter_by(token_hash=hash_token(raw), revoked_at=None)
        .one_or_none()
    )
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_token")
    return token


def require_admin_token(
    token: models.ApiToken = Depends(require_service_token),
) -> models.ApiToken:
    if "admin" not in (token.scopes or []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin_scope_required")
    return token
