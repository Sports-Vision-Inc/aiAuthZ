# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Outbound response filter.

Scans agent responses for known secret formats, oversize base64 payloads,
overly long URLs, and absolute filesystem paths outside the configured
allowlist. Patterns are conservative defaults; per-workspace overrides are
expected to live in workspace policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                  # AWS access key
    re.compile(r"sk-[A-Za-z0-9]{20,}"),               # OpenAI-style key
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),      # Slack
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),              # GitHub PAT
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
_FILE_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s/\\]+[/\\])+[^\s/\\]+")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
_LONG_URL_RE = re.compile(r"https?://[^\s]{120,}")


@dataclass
class EgressResult:
    allowed: bool
    redacted: str
    findings: list[str]


def filter_response(text: str, *, allow_paths: list[str] | None = None) -> EgressResult:
    findings: list[str] = []
    redacted = text

    for pat in _SECRET_PATTERNS:
        if pat.search(redacted):
            findings.append("secret_pattern")
            redacted = pat.sub("[REDACTED_SECRET]", redacted)

    if _LONG_URL_RE.search(redacted):
        findings.append("long_url")
        redacted = _LONG_URL_RE.sub("[REDACTED_URL]", redacted)

    if _BASE64_BLOB_RE.search(redacted):
        findings.append("base64_blob")
        redacted = _BASE64_BLOB_RE.sub("[REDACTED_BLOB]", redacted)

    allow_paths = allow_paths or []
    for m in list(_FILE_PATH_RE.finditer(redacted)):
        path = m.group(0)
        if not any(path.startswith(p) for p in allow_paths):
            findings.append("file_path")
            redacted = redacted.replace(path, "[REDACTED_PATH]")

    # Redact in place and report findings; the caller is responsible for
    # deciding whether to deliver, block, or escalate.
    return EgressResult(allowed=True, redacted=redacted, findings=findings)
