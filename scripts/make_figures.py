# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Generate publication-quality figures from the real experiment results.

Reads experiments/*/results.json and writes PNGs to docs/diagrams/. Run after
the benchmarks; no network needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
EXP = ROOT / "experiments"
OUT = ROOT / "docs" / "diagrams"

# Restrained, colorblind-safe palette.
INK = "#0f172a"; MUTE = "#64748b"; GRID = "#e2e8f0"
BLUE = "#2563eb"; GREEN = "#059669"; RED = "#dc2626"; AMBER = "#d97706"; SLATE = "#475569"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.edgecolor": MUTE, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": SLATE, "ytick.color": SLATE, "axes.titlecolor": INK,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 150,
})


def _load(p):
    return json.load(open(EXP / p))


def fig_model_safety():
    ags = _load("models/results.json")["aggregates"]
    ags = sorted(ags, key=lambda a: a["model_refusal_rate"])
    labels = [a["label"] for a in ags]
    refusal = [a["model_refusal_rate"] * 100 for a in ags]
    fig, ax = plt.subplots(figsize=(9, 4.6))
    bars = ax.barh(labels, refusal, color=BLUE, height=0.62)
    for b, a in zip(bars, ags):
        ax.text(b.get_width() + 1.5, b.get_y() + b.get_height() / 2,
                f"{a['attempts']}/{a['cases']} attempts · ${a['avg_cost_usd']:.4f}/case",
                va="center", fontsize=8.5, color=SLATE)
    ax.axvline(100, color=GREEN, lw=1.4, ls="--")
    ax.text(103, 0.15, "with aiAuthZ:\nevery model →\n100% blocked",
            color=GREEN, fontsize=9.5, va="bottom", fontweight="bold")
    ax.set_xlim(0, 150); ax.set_xlabel("Model refuses the attack on its own (%)")
    ax.set_title("Model-layer safety is uneven and does not track price\n"
                 "(9 frontier models · 8 chaos-case attacks)", fontsize=12, loc="left")
    ax.xaxis.grid(True, color=GRID); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(OUT / "fig_model_safety.png", bbox_inches="tight"); plt.close(fig)


def fig_residual():
    ags = _load("models/results.json")["aggregates"]
    ags = sorted(ags, key=lambda a: a["residual_risk_model_only"], reverse=True)
    labels = [a["label"] for a in ags]
    mo = [a["residual_risk_model_only"] * 100 for a in ags]
    wg = [a["residual_risk_with_gateway"] * 100 for a in ags]
    x = range(len(labels)); w = 0.4
    fig, ax = plt.subplots(figsize=(9.4, 4.6))
    ax.bar([i - w / 2 for i in x], mo, w, label="without aiAuthZ", color=RED)
    ax.bar([i + w / 2 for i in x], wg, w, label="with aiAuthZ", color=GREEN)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Residual risk — attacks that reach the tool (%)")
    ax.set_title("aiAuthZ drives residual risk to 0% for every model", fontsize=12, loc="left")
    ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True); ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(OUT / "fig_residual.png", bbox_inches="tight"); plt.close(fig)


def fig_provenance():
    agg = _load("provenance/results.json")["aggregates"]
    channels = ["identity", "jpeg_q70", "jpeg_q30", "resize_0.5", "screenshot", "crop_10"]
    names = {"signed_qr": "Signed-QR (ours)", "dwt_ss": "DWT watermark (ours)",
             "ed25519": "Ed25519 over bytes", "invisible_watermark": "invisible-watermark",
             "blind_watermark": "blind-watermark"}
    colors = {"signed_qr": GREEN, "dwt_ss": BLUE, "ed25519": RED,
              "invisible_watermark": AMBER, "blind_watermark": SLATE}
    fig, ax = plt.subplots(figsize=(9.6, 4.8))
    for key, label in names.items():
        if key not in agg:
            continue
        surv = agg[key]["survival"]
        ys = [surv.get(c, 0) * 100 for c in channels]
        ax.plot(channels, ys, marker="o", label=label, color=colors[key], lw=2, ms=6)
    ax.set_ylabel("Receipt still verifies (%)"); ax.set_ylim(-4, 108)
    ax.set_title("Only the signed QR survives screenshots and cropping\n"
                 "(receipt survival by channel · N=25)", fontsize=12, loc="left")
    ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=9, loc="lower left")
    plt.xticks(rotation=20, ha="right")
    fig.tight_layout(); fig.savefig(OUT / "fig_provenance.png", bbox_inches="tight"); plt.close(fig)


def fig_defense_compare():
    rows = _load("comparison/results.json")
    att = [r for r in rows if r["in_scope"]]
    n = len(att)
    vals = {"aiAuthZ": sum(r["aiauthz"] for r in att),
            "OAP-style": sum(r["oap"] for r in att),
            "AIP-style": sum(r["aip"] for r in att)}
    fig, ax = plt.subplots(figsize=(6.6, 4.4))
    cols = [GREEN, AMBER, RED]
    bars = ax.bar(list(vals.keys()), list(vals.values()), color=cols, width=0.6)
    for b, v in zip(bars, vals.values()):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.15, f"{v}/{n}",
                ha="center", fontweight="bold", fontsize=12)
    ax.set_ylim(0, n + 1); ax.set_ylabel(f"Chaos attacks blocked (of {n} in-scope)")
    ax.set_title("Head-to-head on the Agents of Chaos scenarios\n"
                 "per-message identity catches the 5 spoofing cases OAP-style misses",
                 fontsize=11.5, loc="left")
    ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(OUT / "fig_defense_compare.png", bbox_inches="tight"); plt.close(fig)


def fig_latency():
    # measured (aiAuthZ) + published (OAP) + typical model call.
    labels = ["aiAuthZ\n(local eval)", "OAP\n(cloud registry)", "model call\n(typical)"]
    vals = [0.017, 53.0, 5000.0]  # ms
    cols = [GREEN, AMBER, MUTE]
    fig, ax = plt.subplots(figsize=(6.6, 4.4))
    bars = ax.bar(labels, vals, color=cols, width=0.6)
    ax.set_yscale("log")
    for b, v in zip(bars, vals):
        txt = f"{v:.3f} ms" if v < 1 else (f"{v:.0f} ms" if v < 1000 else f"~{v/1000:.0f} s")
        ax.text(b.get_x() + b.get_width() / 2, v * 1.15, txt, ha="center", fontweight="bold", fontsize=10)
    ax.set_ylabel("Added decision latency (ms, log scale)")
    ax.set_title("aiAuthZ's authorization is a local, microsecond decision\n"
                 "~3000× faster than a cloud-registry lookup, negligible vs the model call",
                 fontsize=11.5, loc="left")
    ax.yaxis.grid(True, color=GRID, which="both"); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(OUT / "fig_latency.png", bbox_inches="tight"); plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for fn in (fig_model_safety, fig_residual, fig_provenance, fig_defense_compare, fig_latency):
        try:
            fn(); print(f"  wrote {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            print(f"  SKIP {fn.__name__}: {exc}")
    print(f"Figures in {OUT}")


if __name__ == "__main__":
    main()
