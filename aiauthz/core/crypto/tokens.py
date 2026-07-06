# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import hashlib
import secrets


def generate_user_hmac_key() -> bytes:
    return secrets.token_bytes(32)


def generate_service_token() -> str:
    # 32 bytes urlsafe -> 43 chars; prefix for human recognition.
    return "agk_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
