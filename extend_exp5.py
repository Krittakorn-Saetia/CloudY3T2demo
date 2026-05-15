"""
extend_exp5.py
==============
Extend Experiment 5 (Cross-Domain Sharing) to higher record counts so the
FLEX-DIAM-EHR "flat vs linear" advantage becomes visible past the existing
N <= 15 sweep. New x values: 20, 25, 30, 50, 75.

For Scheme [27] (~14s per record, full ABE decrypt+re-encrypt), we cap the
sweep at N=20 — the trend is already overwhelmingly clear and continuing to
larger N would add ~25 minutes per data point without changing the picture.

Output:
  results/exp5_cross_domain.csv  -- appended with the new rows
  results/fig5_cross_domain.png  -- regenerated with the combined sweep
"""
from __future__ import annotations
import py_ecc_patch  # noqa: F401 — must precede any py_ecc import

import csv
import gc
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.setrecursionlimit(50000)

from run_real_experiments import (
    FlexHarness, Scheme25Harness, Scheme27Harness, Scheme31Harness,
    RESULTS_DIR, COLORS, MARKERS,
)


# x values we want ADDED on top of the existing sweep [1..15].
NEW_XS = [20, 25, 30, 50, 75]
# Scheme [27] is too slow to run past this — skip and write blank.
SCHEME27_CAP = 20
REPEATS = 1  # match the existing smoke-run; bump to 3 for paper-quality


def median(samples):
    return float(np.median(samples))


def time_fn(harness, n, repeats):
    samples = []
    for _ in range(repeats):
        gc.collect()
        v = harness.cross_domain_n(n)
        if v is None:
            return None
        samples.append(v)
    return median(samples)


def main():
    print("Initializing four harnesses (this takes a few minutes)...\n")
    print("  FlexHarness...", flush=True)
    flex = FlexHarness()
    print("  Scheme25Harness...", flush=True)
    s25 = Scheme25Harness()
    print("  Scheme27Harness...", flush=True)
    s27 = Scheme27Harness()
    print("  Scheme31Harness...", flush=True)
    s31 = Scheme31Harness()

    harnesses = {
        "Scheme [25]":    s25,
        "Scheme [27]":    s27,
        "Scheme [31]":    s31,
        "FLEX-DIAM-EHR":  flex,
    }

    # Run new sweep
    print(f"\n--- Extended Exp 5 sweep: x in {NEW_XS} (repeats={REPEATS}) ---")
    print(f"{'x':>6}  " + "  ".join(f"{k:>16s}" for k in harnesses.keys()))
    new_rows = []
    for x in NEW_XS:
        row = [x]
        line = [f"{x:>6}"]
        for name, h in harnesses.items():
            if name == "Scheme [27]" and x > SCHEME27_CAP:
                row.append("")
                line.append(f"{'(skipped)':>16s}")
                continue
            try:
                t0 = time.time()
                v = time_fn(h, x, REPEATS)
                dur = time.time() - t0
            except Exception as e:
                print(f"\n  ERROR in {name} at x={x}: {e}")
                v = None
                dur = 0
            if v is None:
                row.append("")
                line.append(f"{'N/A':>16s}")
            else:
                row.append(f"{v:.3f}")
                line.append(f"{v:>13.2f} ms")
        new_rows.append(row)
        print("  " + "  ".join(line), flush=True)

    # -- Merge with existing CSV --
    csv_path = RESULTS_DIR / "exp5_cross_domain.csv"
    existing_rows = []
    header = None
    if csv_path.exists():
        with open(csv_path, "r", newline="") as f:
            r = csv.reader(f)
            header = next(r)
            for row in r:
                if row and row[0].strip():
                    existing_rows.append(row)
    if header is None:
        header = ["x"] + list(harnesses.keys())

    # Deduplicate by x value (new rows take precedence)
    new_xs_set = {int(r[0]) for r in new_rows}
    merged = [r for r in existing_rows if int(r[0]) not in new_xs_set] + [
        [str(c) for c in r] for r in new_rows
    ]
    merged.sort(key=lambda r: int(r[0]))

    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(merged)
    print(f"\nWrote {csv_path}")

    # -- Regenerate the plot --
    fig, ax = plt.subplots(figsize=(8.0, 5.0))
    xs = [int(r[0]) for r in merged]
    for i, name in enumerate(harnesses.keys()):
        ys = []
        for r in merged:
            v = r[i + 1]
            ys.append(float(v) if v not in ("", None) else float("nan"))
        if all(np.isnan(y) for y in ys):
            continue
        ax.plot(xs, ys, marker=MARKERS[name], color=COLORS[name],
                label=name, linewidth=1.7, markersize=7)
    ax.set_yscale("log")
    ax.set_xlabel("Number of cross-domain records")
    ax.set_ylabel("Cumulative latency (ms, log)")
    ax.set_title("Experiment 5 — Cross-Domain Sharing (extended sweep)")
    ax.legend(loc="best", frameon=True)
    ax.grid(True, which="both", alpha=0.3, linestyle="--")
    fig_path = RESULTS_DIR / "fig5_cross_domain.png"
    fig.savefig(fig_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {fig_path}")

    # -- Crossover analysis --
    print("\n--- Crossover analysis (x where FLEX-DIAM-EHR becomes the fastest) ---")
    print(f"{'x':>6}  {'Scheme [25]':>14s}  {'Scheme [27]':>14s}  {'Scheme [31]':>14s}  {'FLEX':>14s}  {'FLEX wins?':>12s}")
    for r in merged:
        x = int(r[0])
        vals = []
        for i in range(1, 5):
            v = r[i]
            vals.append(float(v) if v not in ("", None) else float("nan"))
        flex = vals[3]
        beats = ["Y" if not np.isnan(v) and flex < v else "" for v in vals[:3]]
        print(f"{x:>6}  " + "  ".join(f"{v:>14.2f}" if not np.isnan(v) else f"{'-':>14s}" for v in vals)
              + f"  {'/'.join(b for b in beats if b) or 'no':>12s}")


if __name__ == "__main__":
    main()
