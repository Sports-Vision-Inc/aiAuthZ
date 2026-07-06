# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_admin_token
from aiauthz.core.audit_chain import append_audit, chain_head, verify_chain
from aiauthz.db import models

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("/decisions")
def list_decisions(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
    user: str | None = None,
    tool: str | None = None,
    decision: str | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = 200,
):
    q = db.query(models.AuditLog)
    if user:
        q = q.filter(models.AuditLog.actor_id == user)
    if tool:
        q = q.filter(models.AuditLog.action == f"tools.{tool}")
    if decision:
        q = q.filter(models.AuditLog.decision == decision)
    if from_:
        q = q.filter(models.AuditLog.timestamp >= from_)
    if to:
        q = q.filter(models.AuditLog.timestamp <= to)
    rows = q.order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "actor_type": r.actor_type,
            "actor_id": r.actor_id,
            "action": r.action,
            "decision": r.decision,
            "reason": r.reason,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "extra": r.extra,
        }
        for r in rows
    ]


@router.get("/decisions/{decision_id}")
def get_decision(
    decision_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    row = db.get(models.AuditLog, decision_id)
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "decision_not_found")
    return {
        "id": row.id,
        "timestamp": row.timestamp,
        "actor_type": row.actor_type,
        "actor_id": row.actor_id,
        "action": row.action,
        "decision": row.decision,
        "reason": row.reason,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "request_hash": row.request_hash,
        "extra": row.extra,
    }


@router.get("/decisions/{decision_id}/watermark")
def get_decision_watermark(
    decision_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    row = db.get(models.AuditLog, decision_id)
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "decision_not_found")
    if row.target_type != "message" or not row.target_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_message_for_decision")
    msg = db.get(models.Message, row.target_id)
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "watermark_not_available")
    if msg.watermark_blob_encrypted:
        from aiauthz.core.crypto import decrypt
        return Response(
            decrypt(msg.watermark_blob_encrypted),
            media_type=msg.watermark_mime or "image/png",
        )
    if msg.watermark_path and Path(msg.watermark_path).exists():
        return FileResponse(msg.watermark_path, media_type="image/png")
    raise HTTPException(status.HTTP_404_NOT_FOUND, "watermark_not_available")


@router.get("/messages/{message_id}/verify-watermark")
def verify_message_watermark(
    message_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    """Re-derive the keyed spread-spectrum mark from the user's HMAC key and
    correlate it against the residual recovered from the stored PNG. Returns the
    normalized correlation; a high score proves the artifact was produced by
    aiAuthZ for this user/message and has not been tampered with."""
    msg = db.get(models.Message, message_id)
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message_not_found")
    user = db.get(models.User, msg.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user_not_found")

    if msg.watermark_blob_encrypted:
        from aiauthz.core.crypto import decrypt
        png = decrypt(msg.watermark_blob_encrypted)
    elif msg.watermark_path and Path(msg.watermark_path).exists():
        png = Path(msg.watermark_path).read_bytes()
    else:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "watermark_not_available")

    from aiauthz.core.crypto import decrypt as _dec
    from aiauthz.core.watermark import verify_watermark
    user_key = _dec(user.hmac_key_encrypted)
    result = verify_watermark(
        png_bytes=png,
        user_key=user_key,
        user_id=msg.user_id,
        message_id=msg.id,
        content_sha256=msg.content_hash,
    )

    append_audit(
        db,
        workspace_id=user.workspace_id,
        actor_type="admin", actor_id="audit",
        action="watermark.verify",
        target_type="message", target_id=msg.id,
        decision="ok" if result["ok"] else "mismatch",
        reason=f"cosine={result['cosine']:.4f}",
    )
    db.commit()
    return {
        "message_id": msg.id,
        "user_id": msg.user_id,
        "content_hash": msg.content_hash,
        "verified": result["ok"],
        "cosine_similarity": result["cosine"],
        "threshold": result["threshold"],
        "alpha": result["alpha"],
        "n": result["n"],
    }


@router.get("/messages/{message_id}/verify-receipt")
def verify_message_receipt(
    message_id: str,
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    """Verify a signed-QR receipt: decode the QR from the stored (or a
    re-uploaded) artifact and constant-time-check the HMAC tag against the
    user's key. Exact — the signature either verifies or it does not."""
    msg = db.get(models.Message, message_id)
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message_not_found")
    user = db.get(models.User, msg.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user_not_found")
    if not msg.watermark_blob_encrypted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "receipt_not_available")

    from aiauthz.core.crypto import decrypt as _dec
    from aiauthz.core.watermark import verify_receipt
    png = _dec(msg.watermark_blob_encrypted)
    user_key = _dec(user.hmac_key_encrypted)
    result = verify_receipt(
        png_bytes=png, user_key=user_key, user_id=msg.user_id,
        message_id=msg.id, content_sha256=msg.content_hash,
    )
    append_audit(
        db,
        workspace_id=user.workspace_id,
        actor_type="admin", actor_id="audit",
        action="receipt.verify",
        target_type="message", target_id=msg.id,
        decision="ok" if result["ok"] else "mismatch",
        reason=result.get("reason"),
    )
    db.commit()
    return {
        "message_id": msg.id,
        "user_id": msg.user_id,
        "content_hash": msg.content_hash,
        "verified": result["ok"],
        "decoded": result.get("decoded"),
        "reason": result.get("reason"),
    }


@router.get("/stats")
def audit_stats(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    """Aggregate counters for an at-a-glance compliance dashboard."""
    from sqlalchemy import func
    counts = (
        db.query(models.AuditLog.action, models.AuditLog.decision, func.count(models.AuditLog.id))
        .group_by(models.AuditLog.action, models.AuditLog.decision)
        .all()
    )
    out: dict = {}
    for action, decision, n in counts:
        out.setdefault(action or "unknown", {})[decision or "unknown"] = n
    total = (
        db.query(func.count(models.AuditLog.id)).scalar() or 0,
        db.query(func.count(models.Message.id)).scalar() or 0,
        db.query(func.count(models.ToolCall.id)).scalar() or 0,
    )
    return {
        "by_action": out,
        "totals": {
            "audit_rows": total[0],
            "messages": total[1],
            "tool_calls": total[2],
        },
    }


@router.get("/verify-chain")
def audit_verify_chain(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    """Recompute the audit hash chain from genesis and report the first
    break, if any. A ``valid: true`` result proves no historical row was
    deleted, reordered, or edited since it was appended. ``head_hash`` is
    the value that should be anchored to an external append-only store."""
    return verify_chain(db)


@router.get("/chain-head")
def audit_chain_head(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
):
    """Current head hash. Publish this periodically to an object-lock
    bucket / transparency log / git so even a full-DB rewrite is detectable."""
    return {"head_hash": chain_head(db), "at": datetime.now().isoformat()}


@router.post("/redact")
def audit_redact(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
    retention_days: int = Query(..., ge=1, le=3650),
    workspace_id: str | None = None,
    dry_run: bool = False,
):
    """Retention via **crypto-erasure**, not deletion.

    Audit rows are append-only and hash-chained; they are never removed —
    doing so would break the chain and defeat the tamper-evidence guarantee.
    Instead this clears the *encrypted payload* columns (message bodies,
    tool arguments, tool results, watermark blobs) on records older than
    ``retention_days`` and stamps ``redacted_at``. The content hashes,
    decisions, and the chain itself survive, so:

      * storage of the heavy encrypted blobs is reclaimed,
      * a data-subject-erasure obligation is satisfiable (the recoverable
        content is gone), and
      * every past authorization decision remains provable and verifiable.

    The redaction operation is itself appended to the audit chain."""
    from datetime import timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    msg_q = db.query(models.Message).filter(
        models.Message.timestamp < cutoff,
        models.Message.redacted_at.is_(None),
    )
    tc_q = db.query(models.ToolCall).filter(
        models.ToolCall.executed_at < cutoff,
        models.ToolCall.redacted_at.is_(None),
    )
    if workspace_id:
        tc_q = tc_q.filter(models.ToolCall.workspace_id == workspace_id)
        # Messages have no direct workspace_id; scope via their session.
        ws_sessions = [
            s.id for s in db.query(models.Session.id).filter(
                models.Session.workspace_id == workspace_id
            )
        ]
        msg_q = msg_q.filter(models.Message.session_id.in_(ws_sessions))

    messages = msg_q.all()
    tool_calls = tc_q.all()
    eligible = len(messages) + len(tool_calls)

    if dry_run or eligible == 0:
        return {
            "cutoff": cutoff.isoformat(),
            "eligible": eligible,
            "redacted_messages": 0,
            "redacted_tool_calls": 0,
            "dry_run": bool(dry_run),
            "rows_deleted": 0,  # always zero — this endpoint never deletes
            "workspace_id": workspace_id,
        }

    now = datetime.now(timezone.utc)
    for m in messages:
        m.content_encrypted = None
        m.watermark_blob_encrypted = None
        m.watermark_path = None
        m.redacted_at = now
    for c in tool_calls:
        c.args_encrypted = None
        c.result_encrypted = None
        c.redacted_at = now

    append_audit(
        db,
        workspace_id=workspace_id,
        actor_type="admin", actor_id="retention",
        action="audit.redact", decision="ok",
        reason=f"crypto_erasure retention_days={retention_days}",
        extra={
            "cutoff": cutoff.isoformat(),
            "redacted_messages": len(messages),
            "redacted_tool_calls": len(tool_calls),
        },
    )
    db.commit()
    return {
        "cutoff": cutoff.isoformat(),
        "eligible": eligible,
        "redacted_messages": len(messages),
        "redacted_tool_calls": len(tool_calls),
        "dry_run": False,
        "rows_deleted": 0,
        "workspace_id": workspace_id,
    }


@router.get("/timeseries")
def audit_timeseries(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
    days: int = Query(default=30, ge=1, le=365),
    workspace_id: str | None = None,
):
    """Daily counters over the last *days* days. Powers usage line/bar
    charts on the dashboard and is what an integrator would call to
    build their own observability tile."""
    from datetime import timedelta, timezone
    from sqlalchemy import func

    end   = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    start = end - timedelta(days=days)

    # Date bucket — SQLite uses strftime, Postgres has date_trunc; func.date()
    # works on both for our purposes (date-only key).
    bucket = func.date(models.AuditLog.timestamp).label("d")

    q_msg = (
        db.query(bucket, func.count(models.AuditLog.id))
        .filter(models.AuditLog.timestamp >= start, models.AuditLog.timestamp < end)
        .filter(models.AuditLog.action == "messages.ingress", models.AuditLog.decision == "allow")
    )
    q_tool_allow = (
        db.query(bucket, func.count(models.AuditLog.id))
        .filter(models.AuditLog.timestamp >= start, models.AuditLog.timestamp < end)
        .filter(models.AuditLog.action.like("tools.%"), models.AuditLog.decision == "allow")
    )
    q_tool_deny = (
        db.query(bucket, func.count(models.AuditLog.id))
        .filter(models.AuditLog.timestamp >= start, models.AuditLog.timestamp < end)
        .filter(models.AuditLog.action.like("tools.%"), models.AuditLog.decision == "deny")
    )

    if workspace_id:
        q_msg        = q_msg.filter(models.AuditLog.workspace_id == workspace_id)
        q_tool_allow = q_tool_allow.filter(models.AuditLog.workspace_id == workspace_id)
        q_tool_deny  = q_tool_deny.filter(models.AuditLog.workspace_id == workspace_id)

    msg_map  = {str(d): n for d, n in q_msg.group_by(bucket).all()}
    allow_map = {str(d): n for d, n in q_tool_allow.group_by(bucket).all()}
    deny_map  = {str(d): n for d, n in q_tool_deny.group_by(bucket).all()}

    series = []
    cur = start
    while cur < end:
        key = cur.date().isoformat()
        series.append({
            "date":         key,
            "messages":     int(msg_map.get(key, 0)),
            "tool_allowed": int(allow_map.get(key, 0)),
            "tool_denied":  int(deny_map.get(key, 0)),
        })
        cur = cur + timedelta(days=1)

    totals = {
        "messages":     sum(p["messages"] for p in series),
        "tool_allowed": sum(p["tool_allowed"] for p in series),
        "tool_denied":  sum(p["tool_denied"] for p in series),
    }
    return {
        "from":   start.isoformat().replace("+00:00", "Z"),
        "to":     end.isoformat().replace("+00:00", "Z"),
        "days":   days,
        "bucket": "day",
        "series": series,
        "totals": totals,
    }


@router.get("/export")
def export_audit(
    db: Session = Depends(db_session),
    _admin: models.ApiToken = Depends(require_admin_token),
    format: str = "jsonl",
):
    rows = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.asc()).all()
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "timestamp", "actor_type", "actor_id", "action", "decision", "reason"])
        for r in rows:
            w.writerow([r.id, r.timestamp.isoformat(), r.actor_type, r.actor_id, r.action, r.decision, r.reason])
        return Response(buf.getvalue(), media_type="text/csv")
    if format == "json":
        return [
            {
                "id": r.id, "timestamp": r.timestamp.isoformat(),
                "actor_type": r.actor_type, "actor_id": r.actor_id,
                "action": r.action, "decision": r.decision, "reason": r.reason,
                "target_type": r.target_type, "target_id": r.target_id,
                "extra": r.extra,
            }
            for r in rows
        ]
    # jsonl
    lines = []
    for r in rows:
        lines.append(json.dumps({
            "id": r.id, "timestamp": r.timestamp.isoformat(),
            "actor_type": r.actor_type, "actor_id": r.actor_id,
            "action": r.action, "decision": r.decision, "reason": r.reason,
            "target_type": r.target_type, "target_id": r.target_id,
            "extra": r.extra,
        }))
    return Response("\n".join(lines), media_type="application/x-ndjson")
