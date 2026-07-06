# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from aiauthz.config import get_settings
from aiauthz.core.redis_client import get_redis


def canonical_payload(
    *,
    user_id: str,
    session_id: str,
    content: str,
    nonce: str,
    timestamp: int,
) -> bytes:
    """Return the canonical bytes signed by client and server.

    The output is a deterministic JSON encoding with fixed key order so that
    independent implementations agree byte-for-byte. The content itself is
    hashed (not embedded) to keep signed payloads bounded in size.
    """
    obj = {
        "user_id": user_id,
        "session_id": session_id,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "nonce": nonce,
        "timestamp": int(timestamp),
    }
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_payload(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass
class HmacVerifyResult:
    ok: bool
    reason: str | None = None


def verify_payload(
    *,
    key: bytes,
    payload: bytes,
    signature: str,
    nonce: str,
    timestamp: int,
    user_id: str,
) -> HmacVerifyResult:
    settings = get_settings()
    now = int(time.time())
    if abs(now - int(timestamp)) > settings.nonce_ttl_seconds:
        return HmacVerifyResult(False, "timestamp_outside_window")

    expected = sign_payload(key, payload)
    if not hmac.compare_digest(expected, signature):
        return HmacVerifyResult(False, "signature_mismatch")

    r = get_redis()
    nonce_key = f"aiauthz:nonce:{user_id}:{nonce}"
    # SET NX with TTL is atomic across replicas, so a captured request
    # cannot be played twice within the configured window.
    if not r.set(nonce_key, "1", nx=True, ex=settings.nonce_ttl_seconds):
        return HmacVerifyResult(False, "nonce_replay")

    return HmacVerifyResult(True)
