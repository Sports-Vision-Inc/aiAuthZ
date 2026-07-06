# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from fastapi import APIRouter

from aiauthz import __version__
from aiauthz.tools import TOOL_NAMES

router = APIRouter(tags=["meta"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/readyz")
def readyz():
    return {"status": "ready"}


@router.get("/v1/version")
def version():
    return {"version": __version__}


@router.get("/v1/capabilities")
def capabilities():
    return {
        "tools": TOOL_NAMES,
        "adapters": ["http", "mcp"],
        "watermark": "dwt-svd-keyed-iterative-blending",
    }
