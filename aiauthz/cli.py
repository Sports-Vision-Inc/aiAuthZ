# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import typer
import uvicorn

from aiauthz.config import get_settings

app = typer.Typer(help="aiAuthZ CLI")


@app.command()
def serve(host: str | None = None, port: int | None = None, reload: bool = False):
    """Start the aiAuthZ FastAPI server."""
    s = get_settings()
    uvicorn.run(
        "aiauthz.api.app:app",
        host=host or s.host,
        port=port or s.port,
        reload=reload,
    )


@app.command()
def init():
    """Initialize the database (create tables)."""
    from aiauthz.db import init_db
    init_db()
    typer.echo("ok: database initialized")


@app.command()
def doctor(config: str | None = None):
    """Check an agent-runtime config for the overlapping-built-in-tools
    misconfiguration that silently bypasses the gateway.

    The gateway only governs tool calls routed *through* it. If the runtime
    keeps its own shell/file/web tools enabled alongside the aiAuthZ MCP
    server, the agent can perform the same actions via the built-ins and never
    touch the gateway. This scans Hermes / OpenClaw / Claude Code / Cursor
    style config files and fails loudly if that hole is present.
    """
    import json
    from pathlib import Path

    # (path, loader) candidates for the common runtimes.
    candidates = [config] if config else [
        "~/.hermes/config.yaml",
        "~/.openclaw/openclaw.json",
        "~/.cursor/mcp.json",
        "~/.claude/settings.json",
        "./.mcp.json",
    ]
    # Built-in tool names that overlap with what the gateway mediates.
    overlapping = {
        "shell", "bash", "terminal", "exec", "run_command",
        "file", "file_read", "file_write", "read_file", "write_file", "fs",
        "web", "web_fetch", "http", "fetch", "browser",
    }

    findings, checked = [], []
    for cand in candidates:
        p = Path(cand).expanduser()
        if not p.exists():
            continue
        checked.append(str(p))
        try:
            text = p.read_text()
            data = json.loads(text) if p.suffix == ".json" else _try_yaml(text)
        except Exception as exc:  # noqa: BLE001
            findings.append(("warn", str(p), f"could not parse: {exc}"))
            continue
        blob = json.dumps(data).lower() if isinstance(data, (dict, list)) else str(data).lower()
        has_aiauthz = "aiauthz" in blob
        hit = sorted({t for t in overlapping if f'"{t}"' in blob or f"'{t}'" in blob})
        if has_aiauthz and hit:
            findings.append(("fail", str(p),
                             f"aiAuthZ registered but overlapping built-in tools present: "
                             f"{', '.join(hit)} — disable these so all tool calls route "
                             f"through the gateway."))
        elif has_aiauthz:
            findings.append(("ok", str(p), "aiAuthZ registered; no overlapping built-ins detected."))

    if not checked:
        typer.echo("no known agent-runtime config found (looked in Hermes/OpenClaw/Cursor/Claude paths).")
        raise typer.Exit(0)

    fail = False
    for level, path, msg in findings:
        mark = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}[level]
        typer.echo(f"[{mark}] {path}: {msg}")
        fail = fail or level == "fail"
    if fail:
        typer.echo("\nInsecure: the agent can bypass aiAuthZ via built-in tools. "
                   "See docs/INTEGRATIONS.md for the recommended lockdown.")
        raise typer.Exit(1)
    typer.echo("\nok: no overlapping-built-in bypass detected.")


def _try_yaml(text: str):
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return text


if __name__ == "__main__":
    app()
