# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session
from aiauthz.api.schemas import MessageIngressRequest, MessageIngressResponse
from aiauthz.config import get_settings
from aiauthz.core.crypto import (
    canonical_payload,
    decrypt,
    encrypt,
    verify_payload,
)
from aiauthz.core.audit_chain import append_audit
from aiauthz.core.redis_client import get_redis
from aiauthz.core.watermark import receipt_bytes, watermark_bytes, watermark_message
from aiauthz.db import models

router = APIRouter(prefix="/v1", tags=["messages"])


def _resolve_user(db: Session, *, authorization: str | None) -> models.User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing_user_bearer")
    user_id = authorization.split(" ", 1)[1].strip()
    user = db.get(models.User, user_id)
    if not user or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user_inactive_or_missing")
    return user


@router.post("/messages", response_model=MessageIngressResponse)
async def submit_message(
    request: Request,
    body: MessageIngressRequest,
    db: Session = Depends(db_session),
    authorization: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
    x_nonce: str | None = Header(default=None),
    x_timestamp: str | None = Header(default=None),
):
    if not (x_signature and x_nonce and x_timestamp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing_hmac_headers")
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad_timestamp")

    user = _resolve_user(db, authorization=authorization)
    user_key = decrypt(user.hmac_key_encrypted)

    payload = canonical_payload(
        user_id=user.id,
        session_id=body.session_id,
        content=body.content,
        nonce=x_nonce,
        timestamp=ts,
    )
    result = verify_payload(
        key=user_key,
        payload=payload,
        signature=x_signature,
        nonce=x_nonce,
        timestamp=ts,
        user_id=user.id,
    )
    if not result.ok:
        append_audit(
            db,
            workspace_id=user.workspace_id,
            actor_type="user", actor_id=user.id,
            action="messages.ingress", decision="deny", reason=result.reason,
            extra={"session_id": body.session_id, "platform": body.platform},
        )
        db.commit()
        return MessageIngressResponse(
            message_id="", accepted=False, reason=result.reason
        )

    session = db.get(models.Session, body.session_id)
    if session is None:
        session = models.Session(
            id=body.session_id,
            workspace_id=user.workspace_id,
            user_id=user.id,
        )
        db.add(session)
        db.flush()
    elif session.user_id != user.id:
        # Reject cross-user binding so a spoofed display name in a new
        # channel cannot inherit an existing session's authority.
        append_audit(
            db,
            workspace_id=user.workspace_id,
            actor_type="user", actor_id=user.id,
            action="messages.ingress", decision="deny",
            reason="session_owned_by_different_user",
        )
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "session_owned_by_different_user")

    content_hash = hashlib.sha256(body.content.encode("utf-8")).hexdigest()
    msg = models.Message(
        session_id=session.id,
        user_id=user.id,
        content_hash=content_hash,
        content_encrypted=encrypt(body.content.encode("utf-8")),
        hmac_verified=True,
        nonce=x_nonce,
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        platform=body.platform,
        platform_metadata=body.platform_metadata,
    )
    db.add(msg)
    db.flush()

    settings = get_settings()
    wm_path = None
    wm_stored = False
    if settings.watermark_enabled:
        try:
            if settings.receipt_mode == "signed_qr":
                # Primary: cryptographically signed QR receipt (exact + robust).
                payload = receipt_bytes(
                    user_key=user_key,
                    user_id=user.id,
                    message_id=msg.id,
                    content=body.content,
                )
                msg.watermark_blob_encrypted = encrypt(payload)
                msg.watermark_mime = "image/png"
                wm_stored = True
            elif settings.watermark_store == "file":
                wm_path = watermark_message(
                    user_key=user_key,
                    user_id=user.id,
                    message_id=msg.id,
                    content=body.content,
                    output_dir=Path(settings.watermark_dir),
                )
                msg.watermark_path = wm_path
                wm_stored = True
            else:
                payload = watermark_bytes(
                    user_key=user_key,
                    user_id=user.id,
                    message_id=msg.id,
                    content=body.content,
                )
                msg.watermark_blob_encrypted = encrypt(payload)
                msg.watermark_mime = "image/png"
                wm_stored = True
        except Exception as exc:  # noqa: BLE001
            # Watermarking is an audit artifact; HMAC alone gates accept/reject.
            append_audit(
                db,
                workspace_id=user.workspace_id,
                actor_type="system", actor_id="watermark",
                action="watermark.error", decision="warn", reason=str(exc),
                target_type="message", target_id=msg.id,
            )

    r = get_redis()
    r.set(
        f"aiauthz:active:{session.id}",
        f"{user.id}|{msg.id}",
        ex=settings.nonce_ttl_seconds * 2,
    )
    session.last_active_message_id = msg.id

    append_audit(
        db,
        workspace_id=user.workspace_id,
        actor_type="user", actor_id=user.id,
        action="messages.ingress", decision="allow",
        target_type="message", target_id=msg.id,
        request_hash=content_hash,
    )
    db.commit()
    return MessageIngressResponse(
        message_id=msg.id, accepted=True,
        watermark_stored=wm_stored, watermark_path=wm_path,
    )


@router.get("/messages/{message_id}")
def get_message(message_id: str, db: Session = Depends(db_session)):
    msg = db.get(models.Message, message_id)
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message_not_found")
    return {
        "message_id": msg.id,
        "session_id": msg.session_id,
        "user_id": msg.user_id,
        "content_hash": msg.content_hash,
        "hmac_verified": msg.hmac_verified,
        "watermark_path": msg.watermark_path,
        "timestamp": msg.timestamp,
        "platform": msg.platform,
    }


@router.get("/sessions/{session_id}/messages")
def list_session_messages(session_id: str, db: Session = Depends(db_session)):
    rows = (
        db.query(models.Message)
        .filter_by(session_id=session_id)
        .order_by(models.Message.timestamp.asc())
        .all()
    )
    return [
        {
            "message_id": m.id,
            "user_id": m.user_id,
            "timestamp": m.timestamp,
            "content_hash": m.content_hash,
            "watermark_path": m.watermark_path,
        }
        for m in rows
    ]
