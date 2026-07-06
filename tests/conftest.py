from __future__ import annotations

import os
import secrets
import tempfile
import time
from pathlib import Path

import pytest

# Set env BEFORE any app module is imported. db.session binds its SQLAlchemy
# engine at import time from the resolved settings, so these must be in
# os.environ (which takes precedence over any .env file) before the
# `from aiauthz...` imports below execute — otherwise the engine binds to the
# developer's on-disk database instead of an isolated temp one.
_TMPDIR = Path(tempfile.mkdtemp(prefix="aiauthz_test_"))
os.environ["AIAUTHZ_DATABASE_URL"] = f"sqlite:///{_TMPDIR}/aiauthz.db"
os.environ["AIAUTHZ_REDIS_URL"] = ""  # fakeredis
os.environ["AIAUTHZ_WATERMARK_DIR"] = str(_TMPDIR / "watermarks")
os.environ["AIAUTHZ_MASTER_KEY"] = "test-key-deterministic-for-tests-zzzzzzz="
os.environ["AIAUTHZ_NONCE_TTL_SECONDS"] = "300"


from fastapi.testclient import TestClient  # noqa: E402

from aiauthz.api.app import create_app  # noqa: E402
from aiauthz.config import reset_settings  # noqa: E402
from aiauthz.core.crypto import (  # noqa: E402
    canonical_payload,
    encrypt,
    generate_service_token,
    generate_user_hmac_key,
    hash_token,
    sign_payload,
)
from aiauthz.core.redis_client import get_redis  # noqa: E402
from aiauthz.db import init_db, session_scope  # noqa: E402
from aiauthz.db import models  # noqa: E402
from aiauthz.policy import set_policy, DEFAULT_POLICY_YAML  # noqa: E402


@pytest.fixture(scope="session")
def app():
    reset_settings()
    init_db()
    return create_app()


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def fixtures():
    """Fresh org / workspace / users / tokens for each test."""
    get_redis().flushall()

    with session_scope() as db:
        for table in reversed(models.Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.flush()
    with session_scope() as db:
        admin_raw = generate_service_token()
        db.add(models.ApiToken(
            owner_id="bootstrap", owner_type="admin",
            token_hash=hash_token(admin_raw), scopes=["admin"],
        ))

        org = models.Organization(name="T-Org", plan="free", retention_settings={})
        db.add(org); db.flush()
        team = models.Team(org_id=org.id, name="T-Team")
        db.add(team); db.flush()
        ws = models.Workspace(team_id=team.id, name="T-WS")
        db.add(ws); db.flush()

        owner_key = generate_user_hmac_key()
        owner = models.User(
            workspace_id=ws.id, email="owner@t.co", role="owner",
            hmac_key_encrypted=encrypt(owner_key),
            watermark_seed_encrypted=encrypt(secrets.token_bytes(32)),
        )
        member_key = generate_user_hmac_key()
        member = models.User(
            workspace_id=ws.id, email="member@t.co", role="member",
            hmac_key_encrypted=encrypt(member_key),
            watermark_seed_encrypted=encrypt(secrets.token_bytes(32)),
        )
        guest_key = generate_user_hmac_key()
        guest = models.User(
            workspace_id=ws.id, email="guest@t.co", role="guest",
            hmac_key_encrypted=encrypt(guest_key),
            watermark_seed_encrypted=encrypt(secrets.token_bytes(32)),
        )
        db.add_all([owner, member, guest]); db.flush()

        set_policy(db, scope_type="workspace", scope_id=ws.id, policy_yaml=DEFAULT_POLICY_YAML)

        service_raw = generate_service_token()
        db.add(models.ApiToken(
            owner_id=ws.id, owner_type="service",
            token_hash=hash_token(service_raw), scopes=["tools"],
        ))

        # Capture IDs before session closes (objects expire after commit).
        result = {
            "admin_token": admin_raw,
            "service_token": service_raw,
            "org_id": org.id,
            "team_id": team.id,
            "workspace_id": ws.id,
            "owner": {"id": owner.id, "key": owner_key},
            "member": {"id": member.id, "key": member_key},
            "guest": {"id": guest.id, "key": guest_key},
        }
    return result


def make_signed_message(*, user_id: str, key: bytes, content: str, session_id: str):
    nonce = secrets.token_hex(16)
    ts = int(time.time())
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
    body = {"content": content, "session_id": session_id, "platform": "test"}
    return headers, body
