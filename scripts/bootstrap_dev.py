# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Bootstrap an aiAuthZ dev workspace with one admin token, one workspace,
two enrolled users (an owner and a member), and a service token for agents.

Usage:
    python -m scripts.bootstrap_dev
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from aiauthz.core.crypto import (
    encrypt,
    generate_service_token,
    generate_user_hmac_key,
    hash_token,
)
from aiauthz.db import init_db, session_scope
from aiauthz.db import models
from aiauthz.policy import set_policy, DEFAULT_POLICY_YAML


def main() -> None:
    init_db()
    out: dict = {}

    with session_scope() as db:
        admin_raw = generate_service_token()
        admin_token = models.ApiToken(
            owner_id="bootstrap",
            owner_type="admin",
            token_hash=hash_token(admin_raw),
            scopes=["admin"],
        )
        db.add(admin_token)

        org = models.Organization(name="Dev Org", plan="free", retention_settings={})
        db.add(org); db.flush()
        team = models.Team(org_id=org.id, name="Dev Team")
        db.add(team); db.flush()
        ws = models.Workspace(team_id=team.id, name="Dev Workspace")
        db.add(ws); db.flush()

        owner_key = generate_user_hmac_key()
        owner = models.User(
            workspace_id=ws.id, email="owner@example.com", role="owner",
            hmac_key_encrypted=encrypt(owner_key),
            watermark_seed_encrypted=encrypt(secrets.token_bytes(32)),
        )
        member_key = generate_user_hmac_key()
        member = models.User(
            workspace_id=ws.id, email="member@example.com", role="member",
            hmac_key_encrypted=encrypt(member_key),
            watermark_seed_encrypted=encrypt(secrets.token_bytes(32)),
        )
        db.add(owner); db.add(member); db.flush()

        set_policy(db, scope_type="workspace", scope_id=ws.id, policy_yaml=DEFAULT_POLICY_YAML)

        service_raw = generate_service_token()
        service_token = models.ApiToken(
            owner_id=ws.id,
            owner_type="service",
            token_hash=hash_token(service_raw),
            scopes=["tools"],
        )
        db.add(service_token); db.flush()

        out = {
            "admin_token": admin_raw,
            "service_token": service_raw,
            "org_id": org.id,
            "team_id": team.id,
            "workspace_id": ws.id,
            "owner": {"id": owner.id, "hmac_key_hex": owner_key.hex()},
            "member": {"id": member.id, "hmac_key_hex": member_key.hex()},
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
