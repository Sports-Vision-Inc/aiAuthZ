# Integrating with aiAuthZ

aiAuthZ exposes two surfaces that any modern agent runtime can speak:

1. **HTTP/REST tool gateway.** The agent issues `POST /v1/tools/<name>`
   for each tool call, with a service token and the active session and
   message identifiers in headers. Used by anything that supports HTTP
   function calling (OpenAI Assistants, Anthropic Messages, OpenRouter,
   custom ReAct loops, Hermes API mode).

2. **MCP server.** aiAuthZ exposes the same tools through the Model
   Context Protocol JSON-RPC endpoint at `POST /mcp`. Used by Claude
   Code, Cursor, OpenAI Agents SDK, LangChain MCP, AutoGen, CrewAI, and
   the MCP transport in OpenClaw and Hermes.

Every integration follows the same three steps:

1. Issue a **service token** for the agent runtime
   (`POST /v1/auth/tokens` with scope `tools`).
2. Configure the runtime so its tool URLs (or MCP server) point at the
   aiAuthZ host.
3. Have the runtime forward the active message ID alongside each tool
   call (the message ID is returned by `POST /v1/messages` after the
   user's HMAC-signed message is verified).

The active message ID is what binds a tool call to a specific
authenticated user and prevents a non-owner from running tools through
an existing session.

---

## OpenClaw

OpenClaw supports MCP. Add an MCP server entry to the agent's workspace
configuration so its tools are routed through aiAuthZ:

```yaml
# agent workspace tool configuration
mcp_servers:
  aiauthz:
    url: https://aiauthz.example.internal/mcp
    headers:
      Authorization: Bearer ${AIAUTHZ_SERVICE_TOKEN}
      X-Session-Id: ${AIAUTHZ_SESSION_ID}
      X-Active-Message-Id: ${AIAUTHZ_ACTIVE_MESSAGE_ID}
```

Have the message ingress adapter (the code that bridges Discord/email/web
into OpenClaw) call `POST /v1/messages` with the user's HMAC, capture
the returned `message_id`, and inject it as `AIAUTHZ_ACTIVE_MESSAGE_ID`
before the agent turn fires.

## Hermes

Hermes runs in two modes. Either work as long as the runtime forwards the
active session and message headers.

### MCP mode

Same as OpenClaw above; point the MCP server at `/mcp`.

### HTTP mode

Register tools whose URLs are aiAuthZ tool routes. For example, in a
Hermes tool manifest:

```json
{
  "tools": [
    {
      "name": "shell",
      "url": "https://aiauthz.example.internal/v1/tools/shell",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer $AIAUTHZ_SERVICE_TOKEN",
        "X-Session-Id": "$AIAUTHZ_SESSION_ID",
        "X-Active-Message-Id": "$AIAUTHZ_ACTIVE_MESSAGE_ID"
      },
      "body_template": {"args": "$ARGS"}
    }
  ]
}
```

## OpenAI Assistants / Responses API

Define each tool as an HTTP function whose `function.parameters` mirror
the aiAuthZ `args` envelope. In your application server, when the
Assistant emits a `tool_call`, forward it to aiAuthZ:

```python
import httpx

def call_aiauthz_tool(tool_name, args, session_id, message_id):
    return httpx.post(
        f"{AIAUTHZ_URL}/v1/tools/{tool_name}",
        json={"args": args},
        headers={
            "Authorization": f"Bearer {AIAUTHZ_SERVICE_TOKEN}",
            "X-Session-Id": session_id,
            "X-Active-Message-Id": message_id,
        },
        timeout=30,
    ).json()
```

Submit the result back to the Assistant as the tool output. If
aiAuthZ returns 403, surface the `reason` to the Assistant so the
model can choose a different action.

## Anthropic Messages API

Tool use with Anthropic's Messages API works the same as OpenAI: the
model emits `tool_use` blocks, your server invokes aiAuthZ, and the
result becomes a `tool_result` block in the next turn.

```python
response = anthropic.messages.create(
    model="claude-3-7-sonnet-latest",
    tools=[{"name": "shell", "description": "...", "input_schema": {...}}],
    messages=[...],
)
for block in response.content:
    if block.type == "tool_use":
        result = call_aiauthz_tool(block.name, block.input, session_id, message_id)
```

## Claude Code / Cursor / VS Code agents

Add aiAuthZ as an MCP server in the editor's settings:

```json
{
  "mcpServers": {
    "aiauthz": {
      "url": "https://aiauthz.example.internal/mcp",
      "headers": {
        "Authorization": "Bearer $AIAUTHZ_SERVICE_TOKEN",
        "X-Session-Id": "$AIAUTHZ_SESSION_ID",
        "X-Active-Message-Id": "$AIAUTHZ_ACTIVE_MESSAGE_ID"
      }
    }
  }
}
```

## LangChain / LangGraph

Use the MCP tool loader and point it at the aiAuthZ MCP endpoint, or
wrap each aiAuthZ tool URL as a `Tool` in your chain. The MCP loader
preserves the tool schemas published by aiAuthZ's `tools/list`.

## Custom ReAct loops

If you've written a tool-using loop yourself, the only changes required
are:

1. Replace any direct tool execution with `POST /v1/tools/<name>`.
2. Carry `session_id` and the latest verified `message_id` through every
   reasoning step.

A reference Python client is provided in [`aiauthz.sdk`](../aiauthz/sdk).

---

## Identity model on the user side

A platform adapter (the code that bridges Discord, Slack, email, or your
web app into the agent) must:

1. Hold the user's HMAC key (issued by `/v1/auth/enroll`).
2. Compute `HMAC_SHA256(user_key, canonical_payload)` over
   `{user_id, session_id, sha256(content), nonce, timestamp}` and submit
   the signature with `X-Signature`, `X-Nonce`, `X-Timestamp`.
3. Use a per-user, per-platform mapping so a Discord display name change
   cannot bind to a different user's HMAC key. aiAuthZ treats display
   names as cosmetic; only the HMAC key proves identity.

The Python SDK in `aiauthz.sdk` performs this signing for you:

```python
from aiauthz.sdk import aiAuthZ

ag = aiAuthZ(api_url="https://aiauthz.example.internal",
                service_token=AIAUTHZ_SERVICE_TOKEN)
result = ag.messages.create(
    user_id="alice",
    user_hmac_key_hex=ALICE_KEY_HEX,
    content="please summarize my inbox",
    session_id="sess-...",
    platform="discord",
)
message_id = result["message_id"]
```
