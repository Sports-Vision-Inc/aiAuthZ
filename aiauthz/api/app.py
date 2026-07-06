# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from aiauthz import __version__
from aiauthz.adapters.mcp import router as mcp_router
from aiauthz.api.routes.admin import router as admin_router
from aiauthz.api.routes.agents import router as agents_router
from aiauthz.api.routes.audit import router as audit_router
from aiauthz.api.routes.auth import router as auth_router
from aiauthz.api.routes.dash import router as dash_router
from aiauthz.api.routes.egress import router as egress_router
from aiauthz.api.routes.messages import router as messages_router
from aiauthz.api.routes.meta import router as meta_router
from aiauthz.api.routes.policy import router as policy_router
from aiauthz.api.routes.tools import router as tools_router
from aiauthz.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="aiAuthZ",
        version=__version__,
        description="Authentication and authorization gateway for AI agents.",
        lifespan=lifespan,
    )
    app.include_router(meta_router)
    app.include_router(auth_router)
    app.include_router(messages_router)
    app.include_router(tools_router)
    app.include_router(policy_router)
    app.include_router(audit_router)
    app.include_router(admin_router)
    app.include_router(agents_router)
    app.include_router(dash_router)
    app.include_router(egress_router)
    app.include_router(mcp_router)
    return app


app = create_app()
