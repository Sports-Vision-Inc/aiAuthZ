# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# --- auth ---
class EnrollUserRequest(BaseModel):
    workspace_id: str
    email: str
    role: str = "member"


class EnrollUserResponse(BaseModel):
    user_id: str
    hmac_key: str = Field(..., description="hex-encoded; shown once")


class RotateKeyRequest(BaseModel):
    user_id: str


class RotateKeyResponse(BaseModel):
    user_id: str
    hmac_key: str


class RevokeRequest(BaseModel):
    user_id: str


class MintTokenRequest(BaseModel):
    owner_id: str
    owner_type: str = "service"
    scopes: list[str] = []
    ttl_seconds: int | None = None


class MintTokenResponse(BaseModel):
    token_id: str
    token: str = Field(..., description="shown once")


# --- messages ---
class MessageIngressRequest(BaseModel):
    content: str
    session_id: str
    platform: str | None = None
    platform_metadata: dict | None = None


class MessageIngressResponse(BaseModel):
    message_id: str
    accepted: bool
    reason: str | None = None
    watermark_stored: bool = False
    watermark_path: str | None = None


# --- tools ---
class ToolCallEnvelope(BaseModel):
    args: dict[str, Any] = {}


class ToolCallResponse(BaseModel):
    call_id: str
    decision: str
    reason: str
    executed: bool
    result: Any | None = None


# --- policy ---
class PolicySetRequest(BaseModel):
    scope_type: str  # workspace|user|team|org
    scope_id: str
    policy_yaml: str


class PolicyApplyTemplateRequest(BaseModel):
    template: str
    scope_type: str
    scope_id: str


# --- audit ---
class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    action: str
    decision: str | None
    reason: str | None
    target_type: str | None = None
    target_id: str | None = None


# --- admin ---
class CreateOrgRequest(BaseModel):
    name: str
    plan: str = "free"


class CreateTeamRequest(BaseModel):
    org_id: str
    name: str


class CreateWorkspaceRequest(BaseModel):
    team_id: str
    name: str
    agent_backend_url: str | None = None


# --- agents ---
class ProvisionAgentRequest(BaseModel):
    workspace_id: str
    name: str
    config: dict | None = None


# --- generic ---
class OkResponse(BaseModel):
    ok: bool = True
