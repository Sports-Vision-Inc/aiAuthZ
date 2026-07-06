# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Endpoint wrapper around the egress filter.

Adapters call this before relaying agent output to a downstream platform so
that secret patterns, long blobs, and out-of-allowlist paths are redacted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from aiauthz.api.deps import require_service_token
from aiauthz.tools import filter_response

router = APIRouter(prefix="/v1/egress", tags=["egress"])


class EgressRequest(BaseModel):
    text: str
    allow_paths: list[str] | None = None


@router.post("/scan")
def scan(body: EgressRequest, _token=Depends(require_service_token)):
    res = filter_response(body.text, allow_paths=body.allow_paths)
    return {"allowed": res.allowed, "redacted": res.redacted, "findings": res.findings}
