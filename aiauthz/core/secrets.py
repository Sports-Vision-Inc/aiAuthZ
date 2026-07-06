# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Credential broker.

Secrets (API keys, database URLs, tokens) live only on the gateway host. The
agent references a secret by name; after a call is authorized, the gateway
injects the real value into the forwarded request. The agent never receives the
value, so an agent-side compromise — or a tool call routed around the gateway —
has no credential to abuse.

Resolution order for a name ``FOO``:
  1. process env ``AIAUTHZ_SECRET_FOO``
  2. (extension point) a Vault / KMS / secrets-manager provider

References in forward-executor config use ``{{secret:NAME}}`` placeholders.
"""

from __future__ import annotations

import os
import re

_PLACEHOLDER = re.compile(r"\{\{\s*secret:([A-Za-z0-9_]+)\s*\}\}")


class SecretNotFound(KeyError):
    pass


def get_secret(name: str) -> str:
    value = os.environ.get(f"AIAUTHZ_SECRET_{name.upper()}")
    if value is None:
        raise SecretNotFound(name)
    return value


def resolve(value: str) -> str:
    """Replace every ``{{secret:NAME}}`` placeholder with its resolved value."""
    def _sub(m: re.Match) -> str:
        return get_secret(m.group(1))
    return _PLACEHOLDER.sub(_sub, value)


def resolve_mapping(mapping: dict) -> dict:
    """Resolve placeholders in the string values of a flat mapping (e.g. headers)."""
    return {k: resolve(v) if isinstance(v, str) else v for k, v in (mapping or {}).items()}


def has_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value or ""))
