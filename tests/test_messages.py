from __future__ import annotations

import secrets
import time

from aiauthz.core.crypto import canonical_payload, sign_payload

from .conftest import make_signed_message


def test_message_accepted_with_valid_hmac(client, fixtures):
    headers, body = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="hello agent",
        session_id="sess-1",
    )
    r = client.post("/v1/messages", json=body, headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] is True
    assert data["message_id"]
    assert data["watermark_stored"] is True


def test_message_rejected_on_bad_signature(client, fixtures):
    headers, body = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="hello",
        session_id="sess-bad-sig",
    )
    headers["X-Signature"] = "0" * 64
    r = client.post("/v1/messages", json=body, headers=headers)
    assert r.status_code == 200
    assert r.json()["accepted"] is False
    assert r.json()["reason"] == "signature_mismatch"


def test_message_rejected_on_replayed_nonce(client, fixtures):
    headers, body = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="replay-me",
        session_id="sess-replay",
    )
    r1 = client.post("/v1/messages", json=body, headers=headers)
    assert r1.json()["accepted"] is True
    r2 = client.post("/v1/messages", json=body, headers=headers)
    assert r2.json()["accepted"] is False
    assert r2.json()["reason"] == "nonce_replay"


def test_message_rejected_on_stale_timestamp(client, fixtures):
    user_id = fixtures["owner"]["id"]
    key = fixtures["owner"]["key"]
    content = "stale"
    nonce = secrets.token_hex(16)
    ts = int(time.time()) - 10_000  # way outside window
    payload = canonical_payload(
        user_id=user_id, session_id="sess-stale",
        content=content, nonce=nonce, timestamp=ts,
    )
    sig = sign_payload(key, payload)
    headers = {
        "Authorization": f"Bearer {user_id}",
        "X-Signature": sig,
        "X-Nonce": nonce,
        "X-Timestamp": str(ts),
    }
    body = {"content": content, "session_id": "sess-stale", "platform": "test"}
    r = client.post("/v1/messages", json=body, headers=headers)
    assert r.json()["reason"] == "timestamp_outside_window"


def test_session_owned_by_other_user_is_blocked(client, fixtures):
    """CS#8 spoofing defense: another user cannot inject messages into a
    session that belongs to a different user."""
    h1, b1 = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="owner first",
        session_id="sess-owned",
    )
    assert client.post("/v1/messages", json=b1, headers=h1).json()["accepted"] is True

    h2, b2 = make_signed_message(
        user_id=fixtures["member"]["id"],
        key=fixtures["member"]["key"],
        content="member trying to hijack",
        session_id="sess-owned",
    )
    r = client.post("/v1/messages", json=b2, headers=h2)
    assert r.status_code == 403
    assert r.json()["detail"] == "session_owned_by_different_user"


def test_watermark_blob_stored_in_db(client, fixtures):
    headers, body = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="watermark me",
        session_id="sess-wm-db",
    )
    response = client.post("/v1/messages", json=body, headers=headers).json()
    assert response["accepted"] is True
    assert response["watermark_stored"] is True
    assert response["watermark_path"] is None


def test_get_message_and_session_listing(client, fixtures):
    h, b = make_signed_message(
        user_id=fixtures["owner"]["id"],
        key=fixtures["owner"]["key"],
        content="indexed",
        session_id="sess-list",
    )
    msg_id = client.post("/v1/messages", json=b, headers=h).json()["message_id"]

    r1 = client.get(f"/v1/messages/{msg_id}")
    assert r1.status_code == 200
    assert r1.json()["message_id"] == msg_id

    r2 = client.get("/v1/sessions/sess-list/messages")
    assert r2.status_code == 200
    ids = [m["message_id"] for m in r2.json()]
    assert msg_id in ids
