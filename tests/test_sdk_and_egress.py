from __future__ import annotations

import threading
import time

import pytest
import uvicorn

from aiauthz.api.app import create_app
from aiauthz.sdk import aiAuthZ
from aiauthz.tools import filter_response


@pytest.fixture(scope="module")
def live_server():
    app = create_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=8765, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield "http://127.0.0.1:8765"
    server.should_exit = True
    t.join(timeout=5)


def test_egress_redacts_secret(live_server, fixtures):
    text = "My AWS key is AKIAIOSFODNN7EXAMPLE and password is sk-abc123def456ghi789jkl012"
    res = filter_response(text)
    assert "REDACTED_SECRET" in res.redacted
    assert "secret_pattern" in res.findings


def test_egress_redacts_long_url():
    text = "see https://example.com/" + "a" * 200
    res = filter_response(text)
    assert "REDACTED_URL" in res.redacted


def test_sdk_messages_create_round_trip(live_server, fixtures):
    sdk = aiAuthZ(api_url=live_server, service_token=fixtures["service_token"])
    try:
        result = sdk.messages.create(
            user_id=fixtures["owner"]["id"],
            user_hmac_key_hex=fixtures["owner"]["key"].hex(),
            content="sdk-says-hi",
            session_id="sdk-sess-1",
        )
        assert result["accepted"] is True
        message_id = result["message_id"]

        tool_result = sdk.tools.execute(
            tool_name="web_search",
            args={"q": "test"},
            session_id="sdk-sess-1",
            message_id=message_id,
        )
        assert tool_result["decision"] == "allow"
    finally:
        sdk.close()
