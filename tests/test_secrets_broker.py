from __future__ import annotations

import pytest

from aiauthz.core import secrets as broker


def test_resolve_injects_secret(monkeypatch):
    monkeypatch.setenv("AIAUTHZ_SECRET_STRIPE_KEY", "sk_live_abc123")
    out = broker.resolve("Bearer {{secret:STRIPE_KEY}}")
    assert out == "Bearer sk_live_abc123"


def test_resolve_mapping_headers(monkeypatch):
    monkeypatch.setenv("AIAUTHZ_SECRET_TOKEN", "t0ken")
    headers = broker.resolve_mapping({"Authorization": "Bearer {{secret:TOKEN}}", "X-Static": "keep"})
    assert headers["Authorization"] == "Bearer t0ken"
    assert headers["X-Static"] == "keep"


def test_missing_secret_raises():
    with pytest.raises(broker.SecretNotFound):
        broker.resolve("{{secret:DOES_NOT_EXIST}}")


def test_no_placeholder_passthrough():
    assert broker.resolve("plain value") == "plain value"
    assert broker.has_placeholder("plain") is False
    assert broker.has_placeholder("{{secret:X}}") is True


def test_agent_never_sees_secret_value(monkeypatch):
    """The placeholder the agent supplies does not contain the secret; only
    the gateway-side resolve() introduces the real value."""
    monkeypatch.setenv("AIAUTHZ_SECRET_DB", "postgres://u:p@host/db")
    agent_supplied = "{{secret:DB}}"
    assert "postgres" not in agent_supplied
    assert broker.resolve(agent_supplied) == "postgres://u:p@host/db"
