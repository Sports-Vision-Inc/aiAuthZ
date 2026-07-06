# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from functools import lru_cache

import redis as redis_real
import fakeredis

from aiauthz.config import get_settings


@lru_cache(maxsize=1)
def get_redis():
    settings = get_settings()
    if settings.redis_url:
        return redis_real.Redis.from_url(settings.redis_url, decode_responses=True)
    return fakeredis.FakeRedis(decode_responses=True)
