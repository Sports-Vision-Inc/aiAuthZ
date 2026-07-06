# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from dataclasses import dataclass

import yaml
from sqlalchemy.orm import Session

from aiauthz.db import models

DEFAULT_POLICY_YAML = """\
tools:
  file_read: [owner]
  file_write: [owner]
  file_delete: [owner]
  shell: [owner]
  send_email: [owner]
  env_read: [owner]
  web_fetch: [owner, member]
  web_search: [owner, member, guest]
default: deny
# Argument-level constraints, checked AFTER the role gate. These stop the
# "escalation via a permitted tool" class — e.g. a member is allowed to call
# web_fetch, but role alone does not stop exfiltration to an arbitrary URL.
constraints:
  web_fetch:
    # Empty allowlist = deny all external destinations by default. Operators
    # add their own internal hosts. This closes data-exfil over a tool the
    # role is otherwise permitted to use.
    url_allowlist: []
  file_read:
    path_denylist: ["/etc/*", "/root/*", "**/.ssh/*", "**/*secret*", "**/*.env", "**/id_rsa*"]
  file_write:
    path_denylist: ["/etc/*", "/root/*", "/usr/*", "/bin/*"]
    max_bytes: 1048576
  send_email:
    # No external recipients by default.
    recipient_allowlist: []
# Per-(workspace, tool) request ceilings — mitigate resource exhaustion / DoS.
rate_limits:
  default: 120
  shell: 10
  send_email: 20
  web_fetch: 60
heartbeat:
  default: deny
  allow_tools: []
"""

POLICY_TEMPLATES = {
    "default_conservative": DEFAULT_POLICY_YAML,
    "open_team": """\
tools:
  file_read: [owner, member]
  file_write: [owner, member]
  file_delete: [owner]
  shell: [owner]
  send_email: [owner, member]
  env_read: [owner]
  web_fetch: [owner, member, guest]
  web_search: [owner, member, guest]
default: deny
""",
}


@dataclass
class PolicyDecision:
    allow: bool
    reason: str
    matched_role: str | None = None


def _load_policy_for(db: Session, scope_type: str, scope_id: str) -> dict | None:
    row = (
        db.query(models.Policy)
        .filter_by(scope_type=scope_type, scope_id=scope_id)
        .order_by(models.Policy.updated_at.desc())
        .first()
    )
    if not row:
        return None
    return yaml.safe_load(row.policy_yaml) or {}


def get_effective_policy(db: Session, *, workspace_id: str, user_id: str | None = None) -> dict:
    """Resolve effective policy. Precedence: user > workspace > default."""
    if user_id:
        p = _load_policy_for(db, "user", user_id)
        if p:
            return p
    p = _load_policy_for(db, "workspace", workspace_id)
    if p:
        return p
    return yaml.safe_load(DEFAULT_POLICY_YAML)


def set_policy(db: Session, *, scope_type: str, scope_id: str, policy_yaml: str) -> models.Policy:
    # Validate it parses.
    parsed = yaml.safe_load(policy_yaml)
    if not isinstance(parsed, dict):
        raise ValueError("policy_yaml must parse to a mapping")
    row = (
        db.query(models.Policy)
        .filter_by(scope_type=scope_type, scope_id=scope_id)
        .one_or_none()
    )
    if row:
        row.policy_yaml = policy_yaml
    else:
        row = models.Policy(scope_type=scope_type, scope_id=scope_id, policy_yaml=policy_yaml)
        db.add(row)
    db.flush()
    return row


def _match_any(value: str, patterns: list[str]) -> bool:
    import fnmatch
    return any(fnmatch.fnmatch(value, p) for p in patterns)


def _check_constraints(tool_name: str, constraints: dict, args: dict) -> PolicyDecision | None:
    """Argument-level checks after the role gate. Returns a deny decision, or
    None if the arguments satisfy every constraint."""
    args = args or {}

    path = args.get("path")
    if path is not None:
        deny = constraints.get("path_denylist") or []
        if deny and _match_any(str(path), deny):
            return PolicyDecision(False, f"path_denied:{path}")
        allow = constraints.get("path_allowlist")
        if allow is not None and not _match_any(str(path), allow):
            return PolicyDecision(False, f"path_not_in_allowlist:{path}")

    url = args.get("url")
    if url is not None:
        allow = constraints.get("url_allowlist")
        if allow is not None and not _match_any(str(url), allow):
            return PolicyDecision(False, f"url_not_in_allowlist:{url}")
        deny = constraints.get("url_denylist") or []
        if deny and _match_any(str(url), deny):
            return PolicyDecision(False, f"url_denied:{url}")

    to = args.get("to")
    if to is not None:
        allow = constraints.get("recipient_allowlist")
        if allow is not None and not _match_any(str(to), allow):
            return PolicyDecision(False, f"recipient_not_in_allowlist:{to}")

    max_bytes = constraints.get("max_bytes")
    if max_bytes is not None:
        blob = args.get("content") or args.get("body") or ""
        if len(str(blob).encode("utf-8")) > int(max_bytes):
            return PolicyDecision(False, f"payload_exceeds_max_bytes:{max_bytes}")

    return None


def evaluate(*, policy: dict, tool_name: str, role: str, args: dict | None = None) -> PolicyDecision:
    tools = policy.get("tools", {}) or {}
    allowed_roles = tools.get(tool_name)
    if allowed_roles is None:
        default = (policy.get("default") or "deny").lower()
        if default == "allow":
            granted = PolicyDecision(True, f"default_allow:{tool_name}", role)
        else:
            return PolicyDecision(False, f"default_deny:{tool_name}")
    elif role in allowed_roles:
        granted = PolicyDecision(True, f"role_allowed:{role}", role)
    else:
        return PolicyDecision(False, f"role_not_in_allowlist:{role}")

    # Role passed — now enforce any argument-level constraints for this tool.
    constraints = (policy.get("constraints") or {}).get(tool_name)
    if constraints:
        denied = _check_constraints(tool_name, constraints, args or {})
        if denied is not None:
            return denied
    return granted


def list_templates() -> list[str]:
    return list(POLICY_TEMPLATES.keys())


def apply_template(db: Session, *, template: str, scope_type: str, scope_id: str) -> models.Policy:
    if template not in POLICY_TEMPLATES:
        raise KeyError(f"unknown template: {template}")
    return set_policy(db, scope_type=scope_type, scope_id=scope_id, policy_yaml=POLICY_TEMPLATES[template])
