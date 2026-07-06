from __future__ import annotations

import secrets

from aiauthz.core.audit_chain import verify_chain
from aiauthz.db import models, session_scope
from tests.conftest import make_signed_message


def _admin(fixtures):
    return {"Authorization": f"Bearer {fixtures['admin_token']}"}


def _generate_activity(client, fixtures):
    """Drive a few ingress + tool calls so the audit chain has links."""
    owner = fixtures["owner"]
    session_id = "sess-" + secrets.token_hex(4)
    headers, body = make_signed_message(
        user_id=owner["id"], key=owner["key"],
        content="please list files", session_id=session_id,
    )
    r = client.post("/v1/messages", json=body, headers=headers)
    assert r.status_code == 200 and r.json()["accepted"]
    msg_id = r.json()["message_id"]

    # An allowed and a denied tool call for variety.
    svc = {
        "Authorization": f"Bearer {fixtures['service_token']}",
        "X-Session-Id": session_id,
        "X-Active-Message-Id": msg_id,
    }
    client.post("/v1/tools/web_search", json={"args": {"q": "x"}}, headers=svc)

    member = fixtures["member"]
    session2 = "sess-" + secrets.token_hex(4)
    h2, b2 = make_signed_message(
        user_id=member["id"], key=member["key"],
        content="delete everything", session_id=session2,
    )
    r2 = client.post("/v1/messages", json=b2, headers=h2)
    msg2 = r2.json()["message_id"]
    svc2 = {
        "Authorization": f"Bearer {fixtures['service_token']}",
        "X-Session-Id": session2,
        "X-Active-Message-Id": msg2,
    }
    # member is denied shell by default policy -> a deny audit row
    client.post("/v1/tools/shell", json={"args": {"cmd": "rm -rf /"}}, headers=svc2)
    return msg_id


def test_chain_valid_after_activity(client, fixtures):
    _generate_activity(client, fixtures)
    r = client.get("/v1/audit/verify-chain", headers=_admin(fixtures))
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert data["count"] >= 4  # 2 ingress + 1 allow + 1 deny at minimum
    assert data["head_hash"] and data["head_hash"] != "0" * 64


def test_chain_detects_tampering(client, fixtures):
    _generate_activity(client, fixtures)
    # An attacker edits a historical decision directly in the database,
    # flipping a deny into an allow to hide an escalation.
    with session_scope() as db:
        row = (
            db.query(models.AuditLog)
            .filter(models.AuditLog.decision == "deny")
            .order_by(models.AuditLog.seq.asc())
            .first()
        )
        assert row is not None
        row.decision = "allow"
        row.reason = "role_allowed:member"  # forge a plausible reason

    r = client.get("/v1/audit/verify-chain", headers=_admin(fixtures))
    data = r.json()
    assert data["valid"] is False
    assert data["reason"] == "row_hash_mismatch"
    assert data["broken_at"] is not None


def test_chain_detects_row_deletion(client, fixtures):
    _generate_activity(client, fixtures)
    with session_scope() as db:
        row = (
            db.query(models.AuditLog)
            .order_by(models.AuditLog.seq.asc())
            .offset(1)
            .first()
        )
        db.delete(row)  # remove a historical row entirely

    r = client.get("/v1/audit/verify-chain", headers=_admin(fixtures))
    data = r.json()
    assert data["valid"] is False
    # A deletion shows up as a sequence gap or a broken prev_hash link.
    assert data["reason"] in ("seq_gap", "prev_hash_mismatch")


def test_redact_keeps_chain_and_rows(client, fixtures):
    """Crypto-erasure clears payloads but never deletes rows, so the chain
    still verifies after retention runs."""
    msg_id = _generate_activity(client, fixtures)

    # Force everything to be 'old' by redacting with retention_days floor.
    # Backdate rows so they fall before the cutoff.
    from datetime import datetime, timedelta, timezone
    old = datetime.now(timezone.utc) - timedelta(days=400)
    with session_scope() as db:
        for m in db.query(models.Message).all():
            m.timestamp = old
        for c in db.query(models.ToolCall).all():
            c.executed_at = old

    before = client.get("/v1/audit/stats", headers=_admin(fixtures)).json()

    r = client.post(
        "/v1/audit/redact",
        params={"retention_days": 30},
        headers=_admin(fixtures),
    )
    assert r.status_code == 200
    out = r.json()
    assert out["rows_deleted"] == 0
    assert out["redacted_messages"] >= 1

    after = client.get("/v1/audit/stats", headers=_admin(fixtures)).json()
    # No audit rows removed (in fact one added for the redaction event).
    assert after["totals"]["audit_rows"] >= before["totals"]["audit_rows"]
    assert after["totals"]["messages"] == before["totals"]["messages"]

    # Payload is gone; content_hash retained.
    with session_scope() as db:
        m = db.get(models.Message, msg_id)
        assert m.content_encrypted is None
        assert m.redacted_at is not None
        assert m.content_hash  # hash survives for chain/audit

    # Chain still valid after redaction.
    chain = client.get("/v1/audit/verify-chain", headers=_admin(fixtures)).json()
    assert chain["valid"] is True
