"""
rerun_exp5_only.py
==================
Rerun ONLY Experiment 5 (cross-domain sharing) with the realistic costs:
  - ABPRE rekey now performs a pairing (delegation-token verification)
  - Scheme [27] cross-domain now does the source-side ABE decrypt before
    re-encryption (the realistic MediCrypt-DDT workflow)

We keep all other experiments' results intact.
"""
import py_ecc_patch  # noqa: F401  — must come before any py_ecc import

import csv
import gc
import sys
import time
from pathlib import Path

sys.setrecursionlimit(50000)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from run_real_experiments import (
    FlexHarness, Scheme25Harness, Scheme27Harness, Scheme31Harness,
    COLORS, MARKERS, RESULTS_DIR, REPEATS,
)


def _median_cross_domain(h, n: int, repeats: int = REPEATS):
    """Run cross_domain_n `repeats` times; return median ms (or None if unsupported)."""
    samples = []
    for _ in range(repeats):
        gc.collect()
        v = h.cross_domain_n(n)
        if v is None:
            return None
        samples.append(v)
    return float(np.median(samples))


def main():
    print("Setting up harnesses for Exp 5 refresh...")
    print("  flex...", flush=True)
    flex = FlexHarness()
    print("  s25...", flush=True)
    s25 = Scheme25Harness()
    print("  s27...", flush=True)
    s27 = Scheme27Harness()
    print("  s31...", flush=True)
    s31 = Scheme31Harness()

    harnesses = {
        "Scheme [25]":   s25,
        "Scheme [27]":   s27,
        "Scheme [31]":   s31,
        "FLEX-DIAM-EHR": flex,
    }

    # Dense x-sampling. Scheme [27] is ~14s per record so we cap at 15.
    xs = [1, 2, 3, 4, 5, 7, 10, 12, 15]
    rows = [["n_records"] + list(harnesses.keys())]
    series = {n: [] for n in harnesses.keys()}

    print(f"\n(repeats={REPEATS}, median reported)")
    print(f"{'n':>4s}  " + "  ".join(f"{n:>16s}" for n in harnesses.keys()))
    print("-" * (6 + 18 * len(harnesses)))
    for n in xs:
        row = [n]
        line = [f"{n:>4d}"]
        for sname, h in harnesses.items():
            try:
                ms = _median_cross_domain(h, n)
            except Exception as e:
                ms = None
                print(f"  ERR {sname}@{n}: {e}")
            if ms is None:
                row.append("")
                series[sname].append(float("nan"))
                line.append(f"{'N/A':>16s}")
            else:
                row.append(f"{ms:.3f}")
                series[sname].append(ms)
                line.append(f"{ms:>16.2f}")
        rows.append(row)
        print("  " + "  ".join(line))

    # Overwrite the CSV
    with open(RESULTS_DIR / "exp5_cross_domain.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerows(rows)

    # Overwrite the plot
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    for sname, ys in series.items():
        if all(np.isnan(ys)): continue
        ax.plot(xs, ys, marker=MARKERS[sname], color=COLORS[sname],
                label=sname, linewidth=1.7, markersize=7)
    ax.set_yscale("log")
    ax.set_xlabel("Number of cross-domain records")
    ax.set_ylabel("Cumulative latency (ms, log)")
    ax.set_title("Experiment 5 — Cross-Domain Sharing\n(realistic ABPRE rekey vs ABE re-encryption vs per-event consensus)")
    ax.legend(loc="best", frameon=True)
    plt.savefig(RESULTS_DIR / "fig5_cross_domain.png")
    plt.close(fig)
    print("\nExp 5 refreshed.")


if __name__ == "__main__":
    main()
