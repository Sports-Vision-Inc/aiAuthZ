# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Reproduce every result in docs/WHITEPAPER.md from a single command.

    .venv/bin/python -m scripts.reproduce_all            # everything
    .venv/bin/python -m scripts.reproduce_all --offline  # skip API-backed steps

Steps:
  1. Test suite (offline)                     -> pass/fail count
  2. Provenance bake-off (offline)            -> experiments/provenance/
  3. Model benchmark (needs OPENROUTER_API_KEY) -> experiments/models/
  4. Long-context degradation (API)          -> experiments/context/
  5. Real MCP end-to-end (API)               -> experiments/mcp_e2e/

Each step is independent; a failure in one is reported and the rest continue.
API steps are skipped with a clear message when no key is present or --offline.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
if not Path(PY).exists():
    PY = sys.executable


def _run(label: str, cmd: list[str], env: dict | None = None) -> bool:
    print(f"\n{'=' * 70}\n▶ {label}\n{'=' * 70}")
    try:
        r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **(env or {})})
        ok = r.returncode == 0
    except Exception as exc:  # noqa: BLE001
        print(f"  error launching: {exc}")
        ok = False
    print(f"  -> {'OK' if ok else 'FAILED'}")
    return ok


def _has_key() -> bool:
    if os.environ.get("OPENROUTER_API_KEY"):
        return True
    env = ROOT / ".env.local"
    return env.exists() and "OPENROUTER_API_KEY=" in env.read_text()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="skip API-backed steps")
    args = ap.parse_args()

    results: dict[str, bool | None] = {}

    # 1. Tests (offline). Fresh DB so the isolated test engine binds cleanly.
    (ROOT / "data" / "aiauthz.db").unlink(missing_ok=True)
    results["tests"] = _run("1/5 Test suite", [PY, "-m", "pytest", "-q"])

    # 2. Provenance bake-off (offline).
    results["provenance"] = _run(
        "2/5 Provenance bake-off", [PY, str(ROOT / "experiments" / "provenance" / "bakeoff.py")]
    )

    # Offline, no API: the defense head-to-head (policy logic) and figures.
    results["comparison"] = _run("Defense comparison (aiAuthZ vs OAP/AIP)", [PY, "-m", "scripts.defense_comparison"])
    results["figures"] = _run("Regenerate figures", [PY, "-m", "scripts.make_figures"])

    api = _has_key() and not args.offline
    if not api:
        why = "--offline" if args.offline else "OPENROUTER_API_KEY not set"
        for step in ("3/5 Model benchmark", "4/5 Long-context", "5/5 MCP e2e"):
            print(f"\n▶ {step}\n  -> SKIPPED ({why})")
        results.update({"model_benchmark": None, "context": None, "mcp_e2e": None})
    else:
        results["model_benchmark"] = _run("3/6 Model benchmark", [PY, "-m", "scripts.model_benchmark"])
        results["chaos"] = _run("4/6 Agents of Chaos 11 case studies", [PY, "-m", "scripts.chaos_benchmark"])
        results["context"] = _run("5/6 Long-context degradation", [PY, "-m", "scripts.context_benchmark"])
        e2e_env = {
            "AIAUTHZ_DATABASE_URL": "sqlite:////tmp/aiauthz_reproduce_e2e.db",
            "AIAUTHZ_REDIS_URL": "",
            "AIAUTHZ_MASTER_KEY": os.environ.get("AIAUTHZ_MASTER_KEY", "reproduce-key-32-bytes-padding-zzz="),
        }
        Path("/tmp/aiauthz_reproduce_e2e.db").unlink(missing_ok=True)
        results["mcp_e2e"] = _run("6/6 Real MCP end-to-end", [PY, "-m", "scripts.mcp_e2e"], env=e2e_env)

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    for name, ok in results.items():
        mark = "SKIP" if ok is None else ("OK" if ok else "FAIL")
        print(f"  {name:18s} {mark}")
    print("\nOutputs under experiments/. See docs/WHITEPAPER.md for the reference numbers.")
    if any(ok is False for ok in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
