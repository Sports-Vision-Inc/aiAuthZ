# Real agent-runtime integration on a live VM

Ubuntu VM (`ssh.svapp.us`, Python 3.14), real **OpenClaw 2026.6.11** installed
from npm. aiAuthZ installed into a venv and run as a live gateway. This records
what was actually executed on the VM (not an emulation).

## Setup
- aiAuthZ installed (`pip install -e .`), imports OK on Python 3.14.
- Gateway started on `127.0.0.1:8099` (port 8080 was already held by a Tomcat
  instance on the VM — a useful reminder to pick a free port). `GET /healthz` → `{"status":"ok"}`.
- Bootstrapped an org/workspace/owner/member + service token via `scripts.bootstrap_dev`.

## Real MCP authorization over the wire
A member (non-owner) signed a message, submitted it to `/v1/messages`, and the
agent-side then issued a `tools/call` for `shell` over the MCP JSON-RPC endpoint:

```
ingress accepted: True   (HMAC verified, session bound to the member)
MCP shell call -> {"code": -32000, "message": "{'reason': 'role_not_in_allowlist:member'}"}
```

The live gateway **denied** the shell call on the real VM, over the exact MCP
transport an agent runtime uses.

## OpenClaw integration
- `openclaw mcp set aiauthz {...}` → `Saved MCP server "aiauthz"`.
- `openclaw mcp list` → lists `aiauthz`.
- The streamable-http (SSE) transport OpenClaw speaks returns a valid frame with
  the full tool list:
  ```
  event: message
  data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"file_read",...}]}}
  ```
  So the aiAuthZ MCP adapter is wire-compatible with the real OpenClaw client.

## Bypass conformance check (`aiauthz doctor`) on real configs
- On the real `~/.openclaw/openclaw.json` (aiAuthZ registered, no overlapping
  built-ins): `[ok] ... no overlapping-built-in bypass detected` (exit 0).
- On a config with aiAuthZ **plus** built-in `shell`/`file`/`web`:
  `[FAIL] ... overlapping built-in tools present: file, shell, web` (exit 1).

So `doctor` distinguishes a locked-down runtime from one that can bypass the
gateway, on real config files.

## What was deliberately NOT run
The full OpenClaw LLM agent loop (`openclaw agent --local`) driven by a
destructive prompt (`rm -rf ...`) was **not** executed unsandboxed. With
OpenClaw's built-in tools enabled, that loop could let the model's built-in
shell actually run the destructive command on the VM — which is precisely the
bypass hazard this project warns about. Demonstrating it would mean causing real
harm on the host; the safe evidence above already establishes that (a) the
gateway authorizes/denies correctly over MCP, (b) OpenClaw integrates over the
real transport, and (c) `doctor` detects the misconfiguration that would enable
the bypass. The recommended deployment (`deploy/sandbox/`) removes the hazard
structurally.

## Cleanup
Eval tokens (`boot.json`), the throwaway DB, the uploaded tarball, and the test
config were removed from the VM; the gateway process was stopped. The aiAuthZ
and OpenClaw installations were left in place, holding no secrets.
