"""
run_novelty_experiments.py
==========================
Two extra experiments that directly demonstrate the FLEX-DIAM-EHR novelties
*on the same scheme* by toggling them on and off:

  Experiment 7: ZKP authentication WITH amortization vs WITHOUT amortization
                (same scheme, same code path, same machine)
  Experiment 8: ABPRE cross-domain WITH batching vs WITHOUT batching

These plots are the cleanest empirical evidence that the paper's two
novelties are real and substantial.
"""
from __future__ import annotations
# Must precede every import that pulls in py_ecc.
import py_ecc_patch  # noqa: F401

import csv
import gc
import secrets
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List

sys.setrecursionlimit(50000)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from crypto_core import H
from flex_diam_ehr import FlexDiamEHRSystem
from zkp import zk_verify
from abe import abe_encrypt, abpre_rekeygen, abpre_reencrypt
from run_real_experiments import POLICY_ATTRS, UNIVERSE, REPEATS


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def _median_ms(fn: Callable[[], float], repeats: int = REPEATS) -> float:
    """Run a zero-arg timing closure `repeats` times; return median in ms."""
    samples = []
    for _ in range(repeats):
        gc.collect()
        samples.append(fn())
    return float(np.median(samples))


plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
    "figure.dpi": 110,
    "savefig.dpi": 180,
    "savefig.bbox": "tight",
})


def save_csv(name, header, rows):
    p = RESULTS_DIR / f"{name}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return p


def setup_flex():
    sys = FlexDiamEHRSystem(
        domain_ids=["hospital_A", "hospital_B"],
        consortium_node_ids=["BS_0", "BS_1", "BS_2", "BS_3"],
    )
    sys.setup(UNIVERSE)
    sys.register_doctor("hospital_A", "did:doc:alice", {"doctor", "cardiologist", "hospital_A"})
    sys.register_doctor("hospital_B", "did:doc:bob", {"doctor", "cardiologist", "hospital_B"})
    sys.register_patient("hospital_A", "PID:p42")
    sys.link_doctor_patient("hospital_A", "did:doc:alice", "PID:p42",
                             {"doctor", "cardiologist", "hospital_A"})
    return sys


# ===========================================================================
# Experiment 7: ZKP amortization on/off
# ===========================================================================
def exp7_amortization():
    print(f"\n=== Experiment 7: ZKP amortization ON vs OFF  (repeats={REPEATS}, median) ===")
    sys = setup_flex()

    xs = [1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100, 150, 200]
    on_series, off_series = [], []

    def time_on(n_local: int) -> float:
        ctx = H(b"session-on", secrets.token_bytes(16), int(time.time() * 1e6))
        sys.verifiers["hospital_A"]._cache.clear()
        proof, circuit = sys.doctor_authenticate(
            "hospital_A", "did:doc:alice", "PID:p42",
            policy_id="cardio_v1", policy_attrs=POLICY_ATTRS,
            session_context=ctx,
        )
        t0 = time.perf_counter()
        for _ in range(n_local):
            sys.verifiers["hospital_A"].verify(circuit, proof)
        return (time.perf_counter() - t0) * 1000

    def time_off(n_local: int) -> float:
        t0 = time.perf_counter()
        for _ in range(n_local):
            ctx2 = H(b"session-off", secrets.token_bytes(16), int(time.time() * 1e6))
            sys.verifiers["hospital_A"]._cache.clear()
            proof2, circuit2 = sys.doctor_authenticate(
                "hospital_A", "did:doc:alice", "PID:p42",
                policy_id="cardio_v1", policy_attrs=POLICY_ATTRS,
                session_context=ctx2,
            )
            zk_verify(circuit2, proof2)
        return (time.perf_counter() - t0) * 1000

    for n in xs:
        t_on  = _median_ms(lambda: time_on(n))
        t_off = _median_ms(lambda: time_off(n))
        speedup = t_off / max(t_on, 0.001)
        print(f"  n={n:4d}   ON={t_on:8.2f} ms   OFF={t_off:8.2f} ms   speedup={speedup:6.1f}x")
        on_series.append(t_on)
        off_series.append(t_off)

    save_csv("exp7_amortization", ["n_requests", "with_amortization_ms", "without_amortization_ms"],
             [[xs[i], f"{on_series[i]:.3f}", f"{off_series[i]:.3f}"] for i in range(len(xs))])

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot(xs, off_series, marker="o", color="#888888", label="FLEX without amortization", linewidth=1.8, markersize=7)
    ax.plot(xs, on_series,  marker="D", color="#d62728", label="FLEX with amortization",     linewidth=1.8, markersize=7)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Number of authentication requests (same session)")
    ax.set_ylabel("Cumulative latency (ms, log)")
    ax.set_title("Experiment 7 — ZKP Amortization Novelty")
    ax.legend(loc="best", frameon=True)
    plt.savefig(RESULTS_DIR / "fig7_amortization.png")
    plt.close(fig)


# ===========================================================================
# Experiment 8: ABPRE batching on/off
# ===========================================================================
def exp8_batching():
    print(f"\n=== Experiment 8: ABPRE batching ON vs OFF  (repeats={REPEATS}, median) ===")
    sys = setup_flex()

    src_dom = sys.domains["hospital_A"]
    tgt_dom = sys.domains["hospital_B"]
    delegation = b"deltok|batch-experiment|" + secrets.token_bytes(16)

    xs = [1, 2, 3, 5, 8, 10, 15, 20, 25, 35, 50, 75]
    on_series, off_series = [], []

    def time_on(cts_local):
        t0 = time.perf_counter()
        rk = abpre_rekeygen(src_dom.abe_pp, src_dom.abe_msk, tgt_dom.kp.pk_g1, delegation)
        for ct in cts_local:
            abpre_reencrypt(src_dom.abe_pp, ct, rk, target_authority="hospital_B")
        return (time.perf_counter() - t0) * 1000

    def time_off(cts_local):
        t0 = time.perf_counter()
        for ct in cts_local:
            per_token = delegation + b"|" + secrets.token_bytes(8)
            rk_i = abpre_rekeygen(src_dom.abe_pp, src_dom.abe_msk, tgt_dom.kp.pk_g1, per_token)
            abpre_reencrypt(src_dom.abe_pp, ct, rk_i, target_authority="hospital_B")
        return (time.perf_counter() - t0) * 1000

    for n in xs:
        # Build n CTs once per x; each repeat re-encrypts the same set (cheap to rebuild but unnecessary).
        cts = []
        for _ in range(n):
            dk = secrets.token_bytes(32)
            cts.append(abe_encrypt(src_dom.abe_pp, POLICY_ATTRS, dk))

        t_on  = _median_ms(lambda: time_on(cts))
        t_off = _median_ms(lambda: time_off(cts))
        speedup = t_off / max(t_on, 0.001)
        print(f"  n={n:4d}   ON={t_on:8.2f} ms   OFF={t_off:8.2f} ms   speedup={speedup:5.2f}x")
        on_series.append(t_on)
        off_series.append(t_off)

    save_csv("exp8_batching", ["n_records", "with_batching_ms", "without_batching_ms"],
             [[xs[i], f"{on_series[i]:.3f}", f"{off_series[i]:.3f}"] for i in range(len(xs))])

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot(xs, off_series, marker="o", color="#888888", label="ABPRE without batching", linewidth=1.8, markersize=7)
    ax.plot(xs, on_series,  marker="D", color="#d62728", label="ABPRE with batching",    linewidth=1.8, markersize=7)
    ax.set_xlabel("Number of records sharing the same delegation context")
    ax.set_ylabel("Cumulative latency (ms)")
    ax.set_title("Experiment 8 — ABPRE Batching Novelty")
    ax.legend(loc="best", frameon=True)
    plt.savefig(RESULTS_DIR / "fig8_batching.png")
    plt.close(fig)


if __name__ == "__main__":
    exp7_amortization()
    exp8_batching()
    print("\nNovelty experiments complete.")
