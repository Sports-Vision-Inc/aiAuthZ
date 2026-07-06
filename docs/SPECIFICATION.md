# aiAuthZ Specification

aiAuthZ is an authentication-and-authorization gateway for AI agents.
This document describes the on-the-wire contract that platform adapters,
agent runtimes, and operators rely on. It is intended to read like an API
specification: every interaction is given as request/response shape plus
the security invariants the gateway enforces.

## 1. System surfaces

| Surface | Path | Caller | Bearer |
|---|---|---|---|
| Admin / lifecycle | `/v1/admin/*`, `/v1/auth/*`, `/v1/policy/*`, `/v1/audit/*`, `/v1/agents/*`, `/v1/dash/*` | operators / control plane | admin token (`scopes: ["admin"]`) |
| Message ingress | `POST /v1/messages` | platform adapter (Telegram/Slack/email/web) | user_id bearer + HMAC headers |
| Tool gateway (HTTP) | `POST /v1/tools/<name>`, `POST /v1/tools/custom/<name>` | agent runtime | service token (`scopes: ["tools"]`) |
| Tool gateway (MCP) | `POST /mcp` (JSON-RPC 2.0) | MCP-speaking client (Claude Code, Cursor, Hermes, OpenClaw, LangChain MCP, OpenAI Agents SDK) | service token + session headers |
| Egress filter | `POST /v1/egress/scan` | adapter, before delivering response | service token |
| Health / version | `GET /healthz`, `GET /readyz`, `GET /v1/version`, `GET /v1/capabilities` | anyone | none |

## 2. Identity model

Three principals appear in every request:

- **User** — the human (or system identity for heartbeats/cron) on whose
  behalf an agent action is taken. Each user has an HMAC key issued by
  `POST /v1/auth/enroll` and a role (`owner`, `member`, `guest`,
  `system`).
- **Service** — the agent runtime. Authenticates with a service token.
  The token never represents a user; it represents the runtime.
- **Admin** — control-plane operator. Issues tokens, sets policy,
  exports audit, manages workspaces.

The gateway never trusts a runtime's claim about which user is "active."
The active user is whoever last submitted an HMAC-verified message in
the session and whose `message_id` the runtime echoes in
`X-Active-Message-Id` on the tool call.

## 3. Message ingress

```
POST /v1/messages
Authorization: Bearer <user_id>
X-Signature:   <hex-encoded HMAC-SHA256 over canonical_payload>
X-Nonce:       <16-byte hex>
X-Timestamp:   <unix seconds>
Content-Type:  application/json
```

```json
{
  "content": "the user's message",
  "session_id": "platform-scoped session identifier",
  "platform": "discord | slack | email | web | ...",
  "platform_metadata": {"any": "json"}
}
```

`canonical_payload` is the JSON encoding of the following with sorted
keys and no whitespace:

```json
{
  "user_id":        "<user id>",
  "session_id":     "<session id>",
  "content_sha256": "<sha-256 hex of content>",
  "nonce":          "<x-nonce>",
  "timestamp":      <int>
}
```

Acceptance requires all of:

1. `X-Timestamp` within `AIAUTHZ_NONCE_TTL_SECONDS` of server time.
2. `X-Signature` equal to `HMAC_SHA256(user_key, canonical_payload)`.
3. `X-Nonce` not previously seen for `user_id` within the TTL window
   (Redis SETNX).
4. The session, if it exists, is bound to `user_id`. Cross-user binding
   is rejected as `session_owned_by_different_user`.

On success the gateway returns:

```json
{
  "message_id":       "<uuid>",
  "accepted":         true,
  "watermark_stored": true,
  "watermark_path":   null
}
```

The `message_id` becomes the session's active message. Tool calls in
this session must echo it back.

## 4. Tool gateway

```
POST /v1/tools/<name>
Authorization:        Bearer <service_token>
X-Session-Id:         <session id>
X-Active-Message-Id:  <message_id from /v1/messages>
Content-Type:         application/json
```

```json
{ "args": { "...": "tool-specific" } }
```

Authorization checks, in order:

1. The service token is valid and not revoked.
2. `(session_id, active_message_id)` matches the most recent
   HMAC-verified message in that session (Redis read).
3. The role recorded for the active user permits the requested tool
   under the effective policy (user > workspace > default precedence).

Successful response:

```json
{
  "call_id":  "<uuid>",
  "decision": "allow",
  "reason":   "role_allowed:owner",
  "executed": true,
  "result":   { "authorized": true, "args": { "...": "..." } }
}
```

`executed` indicates the gateway *decided* the call. The gateway does
not perform side effects. The runtime is expected to consume `result`
and execute the action on its own infrastructure (or, when the operator
configures `executor: forward`, the gateway proxies the call to a
customer URL and returns its response).

Denied response:

```
HTTP 403
{ "detail": { "call_id": "<uuid>", "reason": "role_not_in_allowlist:member" } }
```

Every decision lands in the audit log with `actor_type=agent`,
`action=tools.<name>`, `decision=allow|deny`, plus the service token's
owner, the active user, the session, the message, and the SHA-256 of
the args.

## 5. Watermarking

For every accepted message the gateway produces a 256×256 grayscale
PNG that:

1. Encodes `agentguard:v1:<user_id>:<message_id>:<sha256(content)>` as
   a QR code (the "host" image). The plaintext content is never written
   to the artifact.
2. Embeds a second QR code with payload
   `agentguard:user:<user_id>:msg:<message_id>` via DWT-SVD with
   iterative blending. The blend parameters `(alpha, n)` are derived
   per message from `HMAC-SHA256(user_key, message_id)`, so forging
   the watermark requires knowledge of the user's secret.

The PNG is stored either as an encrypted blob in
`messages.watermark_blob_encrypted` (default, controlled by
`AIAUTHZ_WATERMARK_STORE=db`) or as a file under
`AIAUTHZ_WATERMARK_DIR`. Both stores are envelope-encrypted with the
master key.

Verification (operators or auditors): given a stored PNG plus
`(user_id, message_id, content_hash, user_key)`, recompute the QR host,
recompute `(alpha, n)`, run DWT-SVD extraction, and confirm the
extracted payload equals `agentguard:user:<user_id>:msg:<message_id>`.

## 6. Policy

Policies are YAML documents bound to a scope (`org`, `team`,
`workspace`, `user`):

```yaml
tools:
  shell:       [owner]
  file_read:   [owner]
  file_write:  [owner]
  file_delete: [owner]
  send_email:  [owner]
  env_read:    [owner]
  web_fetch:   [owner, member]
  web_search:  [owner, member, guest]
default: deny
```

Resolution precedence is user → workspace → default. The shipped
default policy is conservative: only `web_fetch` and `web_search` are
permitted to non-owners.

## 7. Audit

Every authentication, every policy decision, every administrative action
appends one row to `audit_log`. The application's database role has
`INSERT` permission only; no `UPDATE` or `DELETE`. Operators export
through `GET /v1/audit/export?format=jsonl|json|csv`. Watermarks are
fetched per decision through
`GET /v1/audit/decisions/<id>/watermark`.

## 8. Operational invariants

The following invariants are enforced at the code level. Each is
covered by a test in `tests/`.

| Invariant | Test |
|---|---|
| HMAC mismatch rejects ingress | `test_message_rejected_on_bad_signature` |
| Replayed nonce rejects ingress | `test_message_rejected_on_replayed_nonce` |
| Stale timestamp rejects ingress | `test_message_rejected_on_stale_timestamp` |
| Session bound to user A cannot accept user B | `test_session_owned_by_other_user_is_blocked` |
| Tool call without an active message is rejected | `test_unknown_session_blocked` |
| Tool call whose `X-Active-Message-Id` does not match the latest is rejected | `test_active_message_id_mismatch_blocked` |
| Default policy denies non-owner shell | `test_member_cannot_call_shell_default_policy` |
| Watermark is QR-coded and never contains plaintext | `test_host_image_does_not_carry_plaintext` |
| Watermark blob is stored encrypted in the DB by default | `test_watermark_blob_stored_in_db` |

## 9. Threat model

Out of scope (model-layer concerns):

- The agent's underlying model "deciding" not to call a destructive
  tool. The gateway treats the model as untrusted and gates any tool
  the model emits.
- Hallucinated tool results from the model when no tool was called.

In scope:

- Forgery of user identity in any platform channel. Defended by HMAC
  with per-user secret + nonce + timestamp. A spoofed display name in
  a new Discord channel cannot inherit an existing session.
- Replay of captured messages. Defended by Redis nonce SETNX with TTL.
- Cross-user session hijack within one workspace. Defended by binding
  every session to the user_id of its first HMAC-verified message.
- Active-message hijack (calling a tool against a session you
  previously had access to but no longer do). Defended by the
  Redis-stored `(session_id → user_id|message_id)` tag, refreshed on
  every ingress.
- Indirect prompt injection through fetched documents or peer-agent
  messages. The gateway does not "fix" prompt injection in the model;
  it limits the blast radius by ensuring that whatever the injected
  prompt asks for must still pass the active user's policy.
- Configuration drift on the agent host (chaos paper CS#10
  "constitution attack"). The gateway holds policy in a database the
  agent has no credentials for, so the agent cannot modify its own
  authorization.

## 10. Reference clients

- Python SDK: `aiauthz.sdk.aiAuthZ`. Computes HMAC client-side; calling
  code passes only `user_id`, `user_hmac_key_hex`, `content`, and
  `session_id`.
- MCP: every aiAuthZ tool is published through `POST /mcp` with the
  standard `tools/list` and `tools/call` JSON-RPC methods. Any MCP
  client (Claude Code, Cursor, OpenAI Agents SDK, LangChain MCP,
  AutoGen, CrewAI, Hermes, OpenClaw) connects with no code changes.
- HTTP function-calling: every aiAuthZ tool is also exposed as a
  POST endpoint, suitable for OpenAI Assistants tool definitions,
  Anthropic Messages tool blocks, and any custom ReAct loop.

The gateway serves its live OpenAPI schema at `GET /openapi.json` when running.
