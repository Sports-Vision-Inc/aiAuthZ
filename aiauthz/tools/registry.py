# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Tool executor registry.

aiAuthZ is an authorization gateway. It does **not** execute tools; it
decides whether a tool call should be permitted, scopes any inputs, and
records the decision for audit.

Each tool resolves to one of three executors via ``tools.yaml`` (path set by
``AIAUTHZ_TOOLS_CONFIG``):

  * ``decision``   default. Return the policy decision and echo the
                   (possibly scoped) arguments. The calling agent is
                   expected to perform the underlying action.
  * ``forward``    proxy the call to a customer-supplied URL. Puts the gateway
                   in the data path for response-side redaction, post-hoc
                   audit, and credential brokering — ``{{secret:NAME}}``
                   placeholders in the URL/headers are resolved from the
                   gateway's secret store after authorization, so the agent
                   host never holds the credential (see core.secrets).
  * ``mock``       deterministic no-op used by the test suite.

Operators may extend the registry at runtime via :func:`register_executor`,
which is the supported integration point for customer-built executors that
wrap their own SDKs.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

from aiauthz.config import get_settings


@dataclass
class ToolResult:
    decided: bool
    tool_name: str
    args: dict[str, Any]
    result: Any
    note: str = ""

    @property
    def executed(self) -> bool:
        return self.decided


ExecutorFn = Callable[[dict[str, Any]], ToolResult]


TOOL_NAMES: list[str] = [
    "file_read",
    "file_write",
    "file_delete",
    "shell",
    "send_email",
    "web_fetch",
    "web_search",
    "env_read",
]


def _decision_factory(tool_name: str, _cfg: dict) -> ExecutorFn:
    def runner(args: dict[str, Any]) -> ToolResult:
        return ToolResult(
            decided=True,
            tool_name=tool_name,
            args=args,
            result={"authorized": True, "args": args},
            note="decision",
        )
    return runner


def _forward_factory(tool_name: str, cfg: dict) -> ExecutorFn:
    url = cfg.get("url")
    timeout = float(cfg.get("timeout_seconds") or 10)
    headers = cfg.get("headers") or {}
    if not url:
        raise ValueError(f"executor=forward requires `url` for tool {tool_name}")

    def runner(args: dict[str, Any]) -> ToolResult:
        from aiauthz.core import secrets as secret_broker
        # Credential broker: resolve {{secret:NAME}} placeholders in the URL and
        # headers here, on the gateway, after authorization. The agent supplies
        # only the placeholder name; the real credential never leaves this host.
        resolved_url = secret_broker.resolve(url)
        resolved_headers = secret_broker.resolve_mapping(headers)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(resolved_url, json={"tool": tool_name, "args": args}, headers=resolved_headers)
            try:
                payload: Any = response.json()
            except ValueError:
                payload = {"text": response.text[:8192]}
            return ToolResult(
                decided=True,
                tool_name=tool_name,
                args=args,
                result={"status": response.status_code, "body": payload},
                note="forward",
            )
        except httpx.HTTPError as exc:
            return ToolResult(
                decided=True,
                tool_name=tool_name,
                args=args,
                result={"error": str(exc)},
                note="forward_error",
            )
    return runner


def _mock_factory(tool_name: str, _cfg: dict) -> ExecutorFn:
    def runner(args: dict[str, Any]) -> ToolResult:
        return ToolResult(
            decided=False,
            tool_name=tool_name,
            args=args,
            result={"mock": True, "echo": args},
            note="mock",
        )
    return runner


def _python_factory(tool_name: str, _cfg: dict, dotted: str) -> ExecutorFn:
    module_path, _, attr = dotted.partition(":")
    if not (module_path and attr):
        raise ValueError(f"executor='python:{dotted}' must be 'module.path:callable'")
    module = importlib.import_module(module_path)
    fn = getattr(module, attr)

    def runner(args: dict[str, Any]) -> ToolResult:
        result = fn(args)
        if isinstance(result, ToolResult):
            return result
        return ToolResult(True, tool_name, args, result, f"python:{dotted}")
    return runner


_DEFAULT_TOOLS_YAML = """\
file_read:    { executor: decision }
file_write:   { executor: decision }
file_delete:  { executor: decision }
shell:        { executor: decision }
send_email:   { executor: decision }
web_fetch:    { executor: decision }
web_search:   { executor: decision }
env_read:     { executor: decision }
"""


def _load_yaml() -> dict[str, dict]:
    settings = get_settings()
    path = settings.tools_config
    if path and Path(path).is_file():
        return yaml.safe_load(Path(path).read_text()) or {}
    return yaml.safe_load(_DEFAULT_TOOLS_YAML)


def _build_executor(tool_name: str, cfg: dict) -> ExecutorFn:
    spec = (cfg or {}).get("executor", "decision")
    if spec == "decision":
        return _decision_factory(tool_name, cfg)
    if spec == "forward":
        return _forward_factory(tool_name, cfg)
    if spec == "mock":
        return _mock_factory(tool_name, cfg)
    if spec.startswith("python:"):
        return _python_factory(tool_name, cfg, spec.removeprefix("python:"))
    raise ValueError(f"unknown executor '{spec}' for tool '{tool_name}'")


_REGISTRY: dict[str, ExecutorFn] = {}


def _ensure_loaded() -> None:
    if _REGISTRY:
        return
    config = _load_yaml()
    for name in TOOL_NAMES:
        _REGISTRY[name] = _build_executor(name, config.get(name, {"executor": "decision"}))
    for name, cfg in config.items():
        if name not in TOOL_NAMES:
            _REGISTRY[name] = _build_executor(name, cfg)


def get_executor(tool_name: str) -> ExecutorFn:
    _ensure_loaded()
    if tool_name in _REGISTRY:
        return _REGISTRY[tool_name]
    return _decision_factory(tool_name, {})


def register_executor(tool_name: str, executor: ExecutorFn) -> None:
    """Override or add a tool executor at runtime."""
    _ensure_loaded()
    _REGISTRY[tool_name] = executor


def reset_registry() -> None:
    _REGISTRY.clear()
