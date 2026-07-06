# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Thin Python SDK around the aiAuthZ REST API.

Computes HMAC client-side correctly so consumers don't have to.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import httpx

from aiauthz.core.crypto import canonical_payload, sign_payload


class MessagesClient:
    def __init__(self, parent: "aiAuthZ") -> None:
        self._p = parent

    def create(
        self,
        *,
        user_id: str,
        user_hmac_key_hex: str,
        content: str,
        session_id: str,
        platform: str | None = None,
        platform_metadata: dict | None = None,
    ) -> dict[str, Any]:
        nonce = secrets.token_hex(16)
        ts = int(time.time())
        key = bytes.fromhex(user_hmac_key_hex)
        payload = canonical_payload(
            user_id=user_id, session_id=session_id,
            content=content, nonce=nonce, timestamp=ts,
        )
        sig = sign_payload(key, payload)
        headers = {
            "Authorization": f"Bearer {user_id}",
            "X-Signature": sig,
            "X-Nonce": nonce,
            "X-Timestamp": str(ts),
        }
        body = {
            "content": content,
            "session_id": session_id,
            "platform": platform,
            "platform_metadata": platform_metadata,
        }
        r = self._p._http.post("/v1/messages", json=body, headers=headers)
        r.raise_for_status()
        return r.json()


class ToolsClient:
    def __init__(self, parent: "aiAuthZ") -> None:
        self._p = parent

    def execute(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        session_id: str,
        message_id: str,
        service_token: str | None = None,
    ) -> dict[str, Any]:
        token = service_token or self._p._service_token
        if not token:
            raise ValueError("service_token required (pass to aiAuthZ or this call)")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Session-Id": session_id,
            "X-Active-Message-Id": message_id,
        }
        if tool_name.startswith("custom:"):
            url = f"/v1/tools/custom/{tool_name.split(':', 1)[1]}"
        else:
            url = f"/v1/tools/{tool_name}"
        r = self._p._http.post(url, json={"args": args}, headers=headers)
        r.raise_for_status()
        return r.json()


class aiAuthZ:
    def __init__(self, *, api_url: str, service_token: str | None = None, timeout: float = 30.0) -> None:
        self._http = httpx.Client(base_url=api_url.rstrip("/"), timeout=timeout)
        self._service_token = service_token
        self.messages = MessagesClient(self)
        self.tools = ToolsClient(self)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "aiAuthZ":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
