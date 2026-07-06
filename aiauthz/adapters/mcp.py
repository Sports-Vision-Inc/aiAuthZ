# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Model Context Protocol (MCP) adapter.

JSON-RPC 2.0 endpoint that exposes the tool gateway to MCP-speaking clients
(Claude Code, Cursor, LangChain MCP, OpenAI Agents SDK, Hermes, OpenClaw).
Implements the ``initialize``, ``tools/list``, and ``tools/call`` methods
over HTTP POST. Streaming SSE transport is not implemented.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aiauthz.api.deps import db_session, require_service_token
from aiauthz.api.routes.tools import _execute_tool
from aiauthz.api.schemas import ToolCallEnvelope
from aiauthz.db import models
from aiauthz.tools import TOOL_NAMES

router = APIRouter(tags=["mcp"])


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


def _tool_descriptor(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"aiAuthZ-mediated {name}",
        "inputSchema": {
            "type": "object",
            "properties": {"args": {"type": "object"}},
            "required": ["args"],
        },
    }


def _wrap_response(payload: dict, accept: str | None):
    """Return either plain JSON or an SSE event per the streamable-http MCP spec.

    Hermes uses plain HTTP JSON-RPC and asks for ``application/json``.
    OpenClaw uses ``streamable-http`` and sends ``Accept: text/event-stream``;
    its client expects a single ``event: message`` carrying the response.
    """
    import json as _json
    from fastapi.responses import Response
    if accept and "text/event-stream" in accept.lower():
        body = f"event: message\ndata: {_json.dumps(payload)}\n\n"
        return Response(body, media_type="text/event-stream")
    return payload


@router.post("/mcp")
def mcp_endpoint(
    req: JsonRpcRequest,
    db: Session = Depends(db_session),
    token: models.ApiToken = Depends(require_service_token),
    x_session_id: str | None = Header(default=None),
    x_active_message_id: str | None = Header(default=None),
    accept: str | None = Header(default=None),
):
    if req.method == "initialize":
        return _wrap_response({
            "jsonrpc": "2.0", "id": req.id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "aiauthz", "version": "0.1.0"},
            },
        }, accept)
    if req.method == "tools/list":
        return _wrap_response({
            "jsonrpc": "2.0", "id": req.id,
            "result": {"tools": [_tool_descriptor(n) for n in TOOL_NAMES]},
        }, accept)
    if req.method == "tools/call":
        params = req.params or {}
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        if not tool_name:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing_tool_name")
        if not (x_session_id and x_active_message_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing_session_headers")
        envelope = ToolCallEnvelope(args=args.get("args", args))
        try:
            resp = _execute_tool(
                db=db,
                tool_name=tool_name,
                body=envelope,
                session_id=x_session_id,
                active_message_id=x_active_message_id,
                service_token=token,
            )
        except HTTPException as exc:
            return _wrap_response({
                "jsonrpc": "2.0", "id": req.id,
                "error": {"code": -32000, "message": str(exc.detail)},
            }, accept)
        import json as _json
        is_error = resp.decision != "allow"
        return _wrap_response({
            "jsonrpc": "2.0", "id": req.id,
            "result": {
                "content": [{"type": "text", "text": _json.dumps(resp.model_dump())}],
                "isError": is_error,
            },
        }, accept)
    return _wrap_response({
        "jsonrpc": "2.0", "id": req.id,
        "error": {"code": -32601, "message": f"method_not_found:{req.method}"},
    }, accept)
