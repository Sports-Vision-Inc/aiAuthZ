# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aiauthz.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[str] = mapped_column(String(32), default="free")
    retention_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_backend_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    byo_storage_config_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    hmac_key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    watermark_seed_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="member")  # owner|member|guest|system
    status: Mapped[str] = mapped_column(String(32), default="active")  # active|revoked
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_active_message_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_session_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    parent_session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    content_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    hmac_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    watermark_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    watermark_blob_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    watermark_mime: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Set when retention redaction clears content_encrypted / watermark blob.
    # content_hash is retained so the audit chain over this message still verifies.
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    # Denormalised for metering + retention queries; nullable so older
    # rows from before this column was added still load.
    workspace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    message_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    args_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    args_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)  # allow|deny
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    result_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Set when retention redaction (crypto-erasure) clears the encrypted
    # payload columns above. The row itself — and its audit trail — is kept.
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)  # org|team|workspace|user
    scope_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_type: Mapped[str] = mapped_column(String(32), nullable=False)  # user|service|workspace
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    # Monotonic append sequence and tamper-evident hash chain. ``row_hash`` is
    # SHA-256 over the row's canonical fields plus the previous row's
    # ``row_hash``; any ins, delete, or edit of a historical row breaks the
    # chain from that point forward. Populated by core.audit_chain.append_audit.
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    # Denormalised so per-workspace usage and retention prune are
    # single-table queries. Nullable for system rows (watermark errors,
    # migrations) and for backwards compatibility with pre-v1 rows.
    workspace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
