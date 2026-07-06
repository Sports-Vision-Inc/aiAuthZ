# Changelog

All notable changes to the open-source aiAuthZ gateway. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-06 — Initial public release

Identity-bound, off-host authorization for AI agents and any AI model with tool
access.

### Identity and authorization
- Per-message HMAC identity: every message is signed over
  `(user_id, session_id, sha256(content), nonce, timestamp)`, with single-use
  nonces and a timestamp window; the session's active user is bound to the
  verified message.
- Off-host policy engine: role→tool allowlists plus argument-level constraints
  (path and URL allow/deny lists, recipient allowlist, write-size limits) and
  per-tool rate limits.

### Audit and receipts
- Tamper-evident audit log: SHA-256 hash chain with `GET /v1/audit/verify-chain`
  and `GET /v1/audit/chain-head`; retention by crypto-erasure
  (`POST /v1/audit/redact`) that clears payloads without breaking the chain.
- Cryptographically signed QR receipts (`GET /v1/audit/messages/<id>/verify-receipt`),
  robust to screenshots and re-compression. An invisible DWT spread-spectrum
  watermark is included for the separate case of marking cover images.

### Integration and deployment
- MCP adapter (`POST /mcp`) and HTTP tool gateway for Claude Code, Cursor,
  Hermes, OpenClaw, and custom clients.
- `aiauthz doctor` to detect the overlapping-built-in-tools bypass.
- Credential broker (`{{secret:NAME}}`) so the agent host holds no secrets.
- Egress-locked reference deployment (`deploy/sandbox/`).

### Evaluation
- 58 tests. Benchmarks and a technical report (`docs/WHITEPAPER.md`) covering a
  15-model panel, the eleven *Agents of Chaos* case studies, AgentDojo, long-context
  degradation, a provenance bake-off, and live MCP end-to-end runs. All results
  reproducible via `scripts/reproduce_all.py`.

AGPL-3.0-or-later; commercial licenses available. No telemetry, no call-home.
