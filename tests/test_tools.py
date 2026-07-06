from __future__ import annotations

from .conftest import make_signed_message


def _post_message(client, fixtures, *, role: str, session_id: str, content: str = "hi"):
    user = fixtures[role]
    h, b = make_signed_message(
        user_id=user["id"], key=user["key"], content=content, session_id=session_id,
    )
    r = client.post("/v1/messages", json=b, headers=h)
    assert r.json()["accepted"] is True, r.text
    return r.json()["message_id"]


def test_owner_can_call_shell(client, fixtures):
    msg_id = _post_message(client, fixtures, role="owner", session_id="sess-tool-1")
    r = client.post(
        "/v1/tools/shell",
        json={"args": {"cmd": "echo hi"}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "sess-tool-1",
            "X-Active-Message-Id": msg_id,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow"
    assert body["result"]["authorized"] is True


def test_member_cannot_call_shell_default_policy(client, fixtures):
    msg_id = _post_message(client, fixtures, role="member", session_id="sess-tool-2")
    r = client.post(
        "/v1/tools/shell",
        json={"args": {"cmd": "rm -rf /"}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "sess-tool-2",
            "X-Active-Message-Id": msg_id,
        },
    )
    assert r.status_code == 403
    assert "role_not_in_allowlist" in r.json()["detail"]["reason"]


def test_member_can_call_web_search(client, fixtures):
    msg_id = _post_message(client, fixtures, role="member", session_id="sess-tool-3")
    r = client.post(
        "/v1/tools/web_search",
        json={"args": {"q": "agents of chaos"}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "sess-tool-3",
            "X-Active-Message-Id": msg_id,
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"


def test_active_message_id_mismatch_blocked(client, fixtures):
    msg_id = _post_message(client, fixtures, role="owner", session_id="sess-tool-4")
    r = client.post(
        "/v1/tools/shell",
        json={"args": {"cmd": "echo"}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "sess-tool-4",
            "X-Active-Message-Id": "spoofed-message-id",
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "active_message_id_mismatch"


def test_unknown_session_blocked(client, fixtures):
    r = client.post(
        "/v1/tools/file_read",
        json={"args": {"path": "/etc/passwd"}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "session-that-doesnt-exist",
            "X-Active-Message-Id": "x",
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "no_active_user_for_session"


def test_invalid_service_token_rejected(client, fixtures):
    r = client.post(
        "/v1/tools/web_search",
        json={"args": {"q": "x"}},
        headers={
            "Authorization": "Bearer not-a-real-token",
            "X-Session-Id": "any",
            "X-Active-Message-Id": "any",
        },
    )
    assert r.status_code == 401


def test_custom_tool_dispatches(client, fixtures):
    msg_id = _post_message(client, fixtures, role="owner", session_id="sess-custom")
    r = client.post(
        "/v1/tools/custom/my_tool",
        json={"args": {"x": 1}},
        headers={
            "Authorization": f"Bearer {fixtures['service_token']}",
            "X-Session-Id": "sess-custom",
            "X-Active-Message-Id": msg_id,
        },
    )
    # default policy denies unknown tool by default
    assert r.status_code == 403
