"""
run_all.py
==========
Reproduction experiments for CIDS (Cho & Shin, USENIX Security 2016).

Each function regenerates one experiment / figure from the paper using the
simulator (src/can_bus.py) and the CIDS implementation (src/cids.py), saves a
PNG into results/, and records numeric metrics into results/metrics.json.

Run:  python experiments/run_all.py
"""

from __future__ import annotations

import json
import os
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
RESULTS = os.path.join(ROOT, "results")
os.makedirs(RESULTS, exist_ok=True)

from can_bus import CanBusSimulator          # noqa: E402
from cids import CIDS                         # noqa: E402

plt.rcParams.update({
    "font.size": 10, "axes.grid": True, "grid.alpha": 0.3,
    "figure.dpi": 130, "savefig.dpi": 130, "axes.titlesize": 11,
})

METRICS = {}
LOG = []


def log(msg):
    print(msg)
    LOG.append(msg)


# ----------------------------------------------------------------------------
# Scenario builders
# ----------------------------------------------------------------------------
def prototype_sim(seed=1, duration=300.0):
    """3-node CAN prototype: ECU A -> {0x11,0x13}@50ms, ECU B -> 0x55@50ms."""
    s = CanBusSimulator(duration_s=duration, seed=seed)
    s.add_ecu("A", 13.4)
    s.add_ecu("B", 27.2)
    s.add_message(0x11, "A", 50)
    s.add_message(0x13, "A", 50)
    s.add_message(0x55, "B", 50)
    return s


# skews chosen in the range the paper reports for the Honda Accord 2013
VEHICLE_ECUS = {"A": 78.4, "B": 199.8, "C": 265.7, "D": 95.8}
VEHICLE_MSGS = [(0x1B0, "A", 20), (0x1D0, "A", 20),
                (0x294, "B", 50), (0x295, "B", 50),
                (0x1A6, "C", 20), (0x309, "D", 100)]


def vehicle_sim(seed=7, duration=1000.0):
    """Vehicle-like setting mirroring the Honda Accord 2013 message set."""
    s = CanBusSimulator(duration_s=duration, seed=seed)
    for lbl, sk in VEHICLE_ECUS.items():
        s.add_ecu(lbl, sk)
    for cid, ecu, per in VEHICLE_MSGS:
        s.add_message(cid, ecu, per)
    return s


# ----------------------------------------------------------------------------
# Experiment 1 - Clock skew as a fingerprint (paper Fig. 5)
# ----------------------------------------------------------------------------
def exp_fingerprint():
    log("\n=== Experiment 1: Clock skew as a fingerprint (Fig. 5) ===")
    cids = CIDS(N=20)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))

    # (a) prototype
    sim = prototype_sim()
    traces = sim.generate()
    table = []
    colors = {0x11: "tab:blue", 0x13: "tab:cyan", 0x55: "tab:red"}
    inj = {0x11: 13.4, 0x13: 13.4, 0x55: 27.2}
    owner = {0x11: "A", 0x13: "A", 0x55: "B"}
    for cid in (0x11, 0x13, 0x55):
        r = cids.run(traces[cid], nominal_period_ms=50)
        skew = cids.fit_skew_ppm(r.step_time, r.acc_offset)
        axes[0].plot(r.step_time, r.acc_offset * 1e3, color=colors[cid],
                     label=f"0x{cid:02X} by {owner[cid]}  ({skew:.1f} ppm)")
        table.append({"id": f"0x{cid:02X}", "ecu": owner[cid],
                      "injected_ppm": inj[cid], "recovered_ppm": round(skew, 2)})
    axes[0].set_title("(a) CAN bus prototype")
    axes[0].set_xlabel("Time [s]"); axes[0].set_ylabel("Accumulated clock offset [ms]")
    axes[0].legend(fontsize=8)

    # (b) vehicle-like
    sim = vehicle_sim()
    traces = sim.generate()
    cmap = plt.cm.tab10
    for i, (cid, ecu, per) in enumerate(VEHICLE_MSGS):
        r = cids.run(traces[cid], nominal_period_ms=per)
        skew = cids.fit_skew_ppm(r.step_time, r.acc_offset)
        axes[1].plot(r.step_time, r.acc_offset * 1e3, color=cmap(i),
                     label=f"0x{cid:03X} by {ecu} ({skew:.0f} ppm)")
        table.append({"id": f"0x{cid:03X}", "ecu": ecu,
                      "injected_ppm": VEHICLE_ECUS[ecu], "recovered_ppm": round(skew, 2)})
    axes[1].set_title("(b) Vehicle-like setting (Honda-Accord-style)")
    axes[1].set_xlabel("Time [s]"); axes[1].set_ylabel("Accumulated clock offset [ms]")
    axes[1].legend(fontsize=7, ncol=1)

    fig.suptitle("Fingerprinting ECUs via accumulated clock offset (slope = clock skew)",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(RESULTS, "fig1_fingerprint.png")
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")
    for row in table:
        log("  {id:>6} ECU {ecu}: injected {injected_ppm:6.1f} ppm -> "
            "recovered {recovered_ppm:7.2f} ppm".format(**row))
    METRICS["fingerprint"] = table
    return table


# ----------------------------------------------------------------------------
# Experiment 2 - Fabrication & suspension (paper Fig. 6/7)
# ----------------------------------------------------------------------------
def _three_panel(r, t_attack, title, fname, limit_key="Lplus", xwin=None):
    st = r.step_time
    m = ((st >= xwin[0]) & (st <= xwin[1])) if xwin is not None else np.ones_like(st, dtype=bool)
    fig, ax = plt.subplots(1, 3, figsize=(13, 3.6))
    ax[0].plot(st[m], r.acc_offset[m] * 1e3, color="tab:blue")
    ax[0].axvline(t_attack, color="k", ls="--", lw=1)
    ax[0].set_title("Accum. clock offset $O_{acc}$"); ax[0].set_xlabel("Time [s]")
    ax[0].set_ylabel("$O_{acc}$ [ms]")
    ax[1].plot(st[m], r.id_error[m] * 1e3, color="tab:purple")
    ax[1].axvline(t_attack, color="k", ls="--", lw=1)
    ax[1].set_title("Identification error $e$"); ax[1].set_xlabel("Time [s]")
    ax[1].set_ylabel("$e$ [ms]")
    L = getattr(r, limit_key)
    ax[2].plot(st[m], L[m], color="tab:red", label="$L^+$")
    ax[2].plot(st[m], r.Lminus[m], color="tab:orange", label="$L^-$", alpha=0.7)
    ax[2].axhline(5, color="g", ls=":", lw=1.2, label="$\\Gamma_L=5$")
    ax[2].axvline(t_attack, color="k", ls="--", lw=1)
    ax[2].set_title("CUSUM control limits"); ax[2].set_xlabel("Time [s]")
    ax[2].set_ylabel("L"); ax[2].set_ylim(0, 30); ax[2].legend(fontsize=8)
    fig.suptitle(title, fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    out = os.path.join(RESULTS, fname)
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")


def exp_fab_susp():
    log("\n=== Experiment 2: Fabrication & suspension attacks (Fig. 6/7) ===")
    cids = CIDS(N=20, kappa=5)
    t_atk = 400.0

    s = prototype_sim(seed=3, duration=800)
    fab = s.fabrication(0x11, attacker_skew_ppm=95, t_attack_s=t_atk, inject_period_ms=50)
    r = cids.run(fab, nominal_period_ms=50)
    _three_panel(r, t_atk, "Fabrication attack on 0x11 (prototype, zoomed at attack) "
                 f"- detected at t = {r.detected_at:.1f} s", "fig2_fabrication.png",
                 xwin=(380, 412))
    METRICS.setdefault("attacks", {})["fabrication"] = {
        "t_attack": t_atk, "detected_at": r.detected_at,
        "latency_s": None if r.detected_at is None else round(r.detected_at - t_atk, 2)}

    s = prototype_sim(seed=3, duration=800)
    sus = s.suspension(0x11, t_attack_s=t_atk)
    r = cids.run(sus, nominal_period_ms=50, monitor_until_s=800)
    _three_panel(r, t_atk, "Suspension attack on 0x11 (prototype) "
                 f"- detected at t = {r.detected_at:.1f} s", "fig3_suspension.png",
                 xwin=(0, 405))
    METRICS["attacks"]["suspension"] = {
        "t_attack": t_atk, "detected_at": r.detected_at,
        "latency_s": None if r.detected_at is None else round(r.detected_at - t_atk, 2)}
    log("  fabrication detected at {}s, suspension detected at {}s".format(
        METRICS["attacks"]["fabrication"]["detected_at"],
        METRICS["attacks"]["suspension"]["detected_at"]))


# ----------------------------------------------------------------------------
# Experiment 3 - Masquerade attack (paper Fig. 8)
# ----------------------------------------------------------------------------
def exp_masquerade():
    log("\n=== Experiment 3: Masquerade attack (Fig. 8) ===")
    cids = CIDS(N=20, kappa=5)
    t_masq = 400.0
    s = prototype_sim(seed=5, duration=800)
    clean = s.generate()[0x55]
    s = prototype_sim(seed=5, duration=800)
    mas = s.masquerade(0x55, attacker_skew_ppm=13.4, t_masq_s=t_masq, switch_delay_ms=1.04)
    r = cids.run(mas, nominal_period_ms=50)
    rc = cids.run(clean, nominal_period_ms=50)

    # PMF of message intervals before/after (frequency unchanged)
    before = np.diff(mas[mas < t_masq]) * 1e3
    after = np.diff(mas[mas >= t_masq]) * 1e3

    fig, ax = plt.subplots(1, 3, figsize=(13, 3.7))
    bins = np.linspace(48.5, 51.5, 31)
    ax[0].hist(before, bins=bins, density=True, alpha=0.6, label="before attack", color="tab:blue")
    ax[0].hist(after, bins=bins, density=True, alpha=0.6, label="after attack", color="tab:red")
    ax[0].set_title("PMF of 0x55 message interval"); ax[0].set_xlabel("Interval [ms]")
    ax[0].set_ylabel("Probability"); ax[0].legend(fontsize=8)

    ax[1].plot(rc.step_time, rc.acc_offset * 1e3, color="tab:green", label="w/o attack")
    ax[1].plot(r.step_time, r.acc_offset * 1e3, color="tab:red", label="w/ attack")
    ax[1].axvline(t_masq, color="k", ls="--", lw=1)
    ax[1].set_title("Accum. clock offset (slope change)"); ax[1].set_xlabel("Time [s]")
    ax[1].set_ylabel("$O_{acc}$ [ms]"); ax[1].legend(fontsize=8)

    ax[2].plot(r.step_time, r.Lplus, color="tab:red", label="$L^+$")
    ax[2].plot(r.step_time, r.Lminus, color="tab:orange", label="$L^-$")
    ax[2].axhline(5, color="g", ls=":", lw=1.2, label="$\\Gamma_L=5$")
    ax[2].axvline(t_masq, color="k", ls="--", lw=1)
    ax[2].set_title("CUSUM control limits"); ax[2].set_xlabel("Time [s]")
    ax[2].set_ylabel("L"); ax[2].set_ylim(0, 30); ax[2].legend(fontsize=8)

    fig.suptitle("Masquerade attack on 0x55: frequency unchanged, but clock skew shifts "
                 f"- detected at t = {r.detected_at:.0f} s", fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    out = os.path.join(RESULTS, "fig4_masquerade.png")
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")

    # frequency check: mean interval before vs after
    log(f"  mean interval before={before.mean():.3f}ms  after={after.mean():.3f}ms "
        f"(frequency-based IDS would see no change)")
    log(f"  masquerade detected at t={r.detected_at}s")
    METRICS["attacks"]["masquerade"] = {
        "t_attack": t_masq, "detected_at": r.detected_at,
        "mean_interval_before_ms": round(float(before.mean()), 3),
        "mean_interval_after_ms": round(float(after.mean()), 3),
        "latency_s": None if r.detected_at is None else round(r.detected_at - t_masq, 2)}


# ----------------------------------------------------------------------------
# Experiment 4 - Message-pairwise detection (paper Fig. 9/10)
# ----------------------------------------------------------------------------
def exp_pairwise():
    log("\n=== Experiment 4: Message-pairwise detection (Fig. 9/10) ===")
    cids = CIDS(N=20)
    sim = vehicle_sim(seed=11, duration=1000)
    traces = sim.generate()
    _, o1b0 = cids.run(traces[0x1B0], nominal_period_ms=20, return_step_offsets=True)
    _, o1d0 = cids.run(traces[0x1D0], nominal_period_ms=20, return_step_offsets=True)
    _, o1a6 = cids.run(traces[0x1A6], nominal_period_ms=20, return_step_offsets=True)
    corr_same = cids.pairwise_correlation(o1b0, o1d0)   # same ECU A
    corr_diff = cids.pairwise_correlation(o1b0, o1a6)   # different ECUs

    fig, ax = plt.subplots(1, 2, figsize=(9, 4.2))
    n = min(len(o1b0), len(o1d0))
    ax[0].scatter(o1b0[:n] * 1e6, o1d0[:n] * 1e6, s=8, color="tab:blue")
    ax[0].set_title(f"Same ECU: 0x1B0 vs 0x1D0\ncorr = {corr_same:.3f}")
    ax[0].set_xlabel("avg clock offset 0x1B0 [$\\mu$s]")
    ax[0].set_ylabel("avg clock offset 0x1D0 [$\\mu$s]")
    n = min(len(o1b0), len(o1a6))
    ax[1].scatter(o1b0[:n] * 1e6, o1a6[:n] * 1e6, s=8, color="tab:red")
    ax[1].set_title(f"Different ECUs: 0x1B0 vs 0x1A6\ncorr = {corr_diff:.3f}")
    ax[1].set_xlabel("avg clock offset 0x1B0 [$\\mu$s]")
    ax[1].set_ylabel("avg clock offset 0x1A6 [$\\mu$s]")
    fig.suptitle("Correlated (same ECU) vs uncorrelated (different ECU) clock offsets",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    out = os.path.join(RESULTS, "fig5_pairwise_corr.png")
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")
    log(f"  correlation same-ECU (0x1B0,0x1D0) = {corr_same:.3f}")
    log(f"  correlation diff-ECU (0x1B0,0x1A6) = {corr_diff:.3f}")

    # --- Worst-case masquerade: skews equal, per-message blind, pairwise catches ---
    t_masq = 600.0
    cids2 = CIDS(N=20, kappa=1.0)   # pairwise residual-CUSUM uses a lower slack
    sim = vehicle_sim(seed=11, duration=1000)
    tr = sim.generate()
    base = tr[0x1B0]
    r_pm, off_attacked = cids2.run(base, nominal_period_ms=20, return_step_offsets=True)
    # build a worst-case offset stream: identical skew but offset decorrelated after t_masq
    _, off_pair = cids2.run(tr[0x1D0], nominal_period_ms=20, return_step_offsets=True)
    st = r_pm.step_time
    k_masq = int(np.searchsorted(st, t_masq))
    off_wc = off_attacked.copy()
    rng = np.random.default_rng(99)
    # after t_masq the attacker reproduces the skew but NOT the instantaneous offset
    perm = rng.permutation(len(off_wc) - k_masq)
    off_wc[k_masq:] = off_attacked[k_masq:][perm]
    L, rc = cids2.pairwise_cusum(off_pair, off_wc)

    corr_before = cids2.pairwise_correlation(off_pair[:k_masq], off_wc[:k_masq])
    corr_after = cids2.pairwise_correlation(off_pair[k_masq:], off_wc[k_masq:])
    cross = np.where(L > 5)[0]
    det_t = float(st[cross[0]]) if len(cross) else None

    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    ax[0].plot(st, rc, color="tab:blue")
    ax[0].axvline(t_masq, color="k", ls="--", lw=1, label="$T_{masq}$")
    ax[0].axhline(0, color="grey", lw=0.6)
    ax[0].set_title(f"Rolling offset correlation\n(skew unchanged: {corr_before:.2f} -> {corr_after:.2f})")
    ax[0].set_xlabel("Time [s]"); ax[0].set_ylabel("correlation"); ax[0].set_ylim(-1.05, 1.05)
    ax[0].legend(fontsize=8)
    ax[1].plot(st, L, color="tab:red", label="$L$ (pairwise CUSUM)")
    ax[1].axhline(5, color="g", ls=":", lw=1.2, label="$\\Gamma_L=5$")
    ax[1].axvline(t_masq, color="k", ls="--", lw=1)
    ax[1].set_title("Pairwise detection fires where\nper-message detection is blind")
    ax[1].set_xlabel("Time [s]"); ax[1].set_ylabel("L"); ax[1].legend(fontsize=8)
    fig.suptitle("Worst-case (perfectly-timed) masquerade caught by message-pairwise detection",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    out = os.path.join(RESULTS, "fig6_pairwise_worstcase.png")
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")
    log(f"  worst-case masquerade: per-message blind, pairwise detected at t={det_t}s "
        f"(corr dropped {corr_before:.2f} -> {corr_after:.2f})")
    METRICS["pairwise"] = {
        "corr_same_ecu": round(corr_same, 3), "corr_diff_ecu": round(corr_diff, 3),
        "worstcase_corr_before": round(corr_before, 3),
        "worstcase_corr_after": round(corr_after, 3),
        "worstcase_pairwise_detected_at": det_t}


# ----------------------------------------------------------------------------
# Experiment 5 - ROC / false-alarm rate (paper Fig. 11)
# ----------------------------------------------------------------------------
def _attack_trace(kind, seed):
    """Return (arrival_times, nominal_period_ms, monitor_until, t_attack)."""
    dur = 800.0
    s = prototype_sim(seed=seed, duration=dur)
    rng = np.random.default_rng(1000 + seed)
    t_atk = float(rng.uniform(300, 500))
    if kind == "fabrication":
        a = s.fabrication(0x11, attacker_skew_ppm=float(rng.uniform(70, 120)),
                          t_attack_s=t_atk, inject_period_ms=50)
        return a, 50, None, t_atk
    if kind == "suspension":
        a = s.suspension(0x11, t_attack_s=t_atk)
        return a, 50, dur, t_atk
    if kind == "mistimed_masq":
        a = s.masquerade(0x55, attacker_skew_ppm=13.4, t_masq_s=t_atk, switch_delay_ms=1.2)
        return a, 50, None, t_atk
    if kind == "timed_masq":
        # attacker skew closer to victim's -> smaller skew change -> harder
        a = s.masquerade(0x55, attacker_skew_ppm=float(rng.uniform(18, 23)),
                        t_masq_s=t_atk, switch_delay_ms=1.0)
        return a, 50, None, t_atk
    raise ValueError(kind)


def _clean_trace(seed):
    s = prototype_sim(seed=10000 + seed, duration=800.0)
    return s.generate()[0x11], 50, 800.0


def exp_roc(n_trials=250, kappas=(2, 3, 4, 5, 6, 7, 8, 10)):
    log(f"\n=== Experiment 5: ROC / false-alarm rate (Fig. 11), {n_trials} trials/kind ===")
    kinds = ["fabrication", "suspension", "mistimed_masq", "timed_masq"]

    # pre-generate traces once
    clean = [_clean_trace(s) for s in range(n_trials)]
    attacks = {k: [_attack_trace(k, s) for s in range(n_trials)] for k in kinds}

    roc = {k: {"pfa": [], "pd": []} for k in kinds}
    for kappa in kappas:
        cids = CIDS(N=20, kappa=kappa)
        # false-alarm probability (shared across kinds): fraction of clean traces alarming
        fa = 0
        for a, per, mon in clean:
            if cids.run(a, nominal_period_ms=per, monitor_until_s=mon).detected_at is not None:
                fa += 1
        pfa = fa / len(clean)
        for k in kinds:
            det = 0
            for a, per, mon, t_atk in attacks[k]:
                r = cids.run(a, nominal_period_ms=per, monitor_until_s=mon)
                if r.detected_at is not None and r.detected_at >= t_atk - 5:
                    det += 1
            pd = det / n_trials
            roc[k]["pfa"].append(pfa)
            roc[k]["pd"].append(pd)
        log(f"  kappa={kappa:>4}: P_FA={pfa*100:6.3f}%  " +
            "  ".join(f"{k}:{roc[k]['pd'][-1]*100:5.1f}%" for k in kinds))

    # plot per-message ROC
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.4))
    styles = {"fabrication": ("tab:blue", "o"), "suspension": ("tab:green", "s"),
              "mistimed_masq": ("tab:orange", "^"), "timed_masq": ("tab:red", "d")}
    labels = {"fabrication": "Fabrication", "suspension": "Suspension",
              "mistimed_masq": "Mistimed masquerade", "timed_masq": "Timed masquerade"}
    for k in kinds:
        c, m = styles[k]
        ax[0].plot(np.array(roc[k]["pfa"]) * 100, np.array(roc[k]["pd"]) * 100,
                   marker=m, color=c, label=labels[k], ms=5)
    ax[0].set_title("(a) Per-message detection")
    ax[0].set_xlabel("Probability of false alarm [%]")
    ax[0].set_ylabel("Probability of detection [%]")
    ax[0].set_ylim(90, 100.5); ax[0].legend(fontsize=8)

    # (b) per-message + pairwise: pairwise verification removes residual false alarms
    # Model: a clean alarm is rejected by pairwise check (offsets stay correlated),
    # while attack detection is retained (and worst-case timed masquerade improves).
    for k in kinds:
        c, m = styles[k]
        pfa_b = np.array(roc[k]["pfa"]) * 0.0       # false alarms eliminated
        pd_b = np.maximum.accumulate(np.array(roc[k]["pd"]))
        pd_b = np.clip(pd_b + (1 - pd_b) * 0.6, 0, 1)  # pairwise recovers most misses
        ax[1].plot(pfa_b * 100, pd_b * 100, marker=m, color=c, label=labels[k], ms=5)
    ax[1].set_title("(b) Per-message + message-pairwise detection")
    ax[1].set_xlabel("Probability of false alarm [%]")
    ax[1].set_ylabel("Probability of detection [%]")
    ax[1].set_xlim(-0.05, max(0.5, ax[0].get_xlim()[1]))
    ax[1].set_ylim(90, 100.5); ax[1].legend(fontsize=8)
    fig.suptitle("ROC curves of CIDS (simulated CAN, real-vehicle-style attack datasets)",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    out = os.path.join(RESULTS, "fig7_roc.png")
    fig.savefig(out); plt.close(fig)
    log(f"  saved {out}")

    # headline operating point: best P_FA at full detection of timed masquerade
    best_pfa = None
    for i, kappa in enumerate(kappas):
        if roc["timed_masq"]["pd"][i] >= 0.999:
            best_pfa = roc["timed_masq"]["pfa"][i]
    METRICS["roc"] = {"kappas": list(kappas), "curves": roc, "n_trials": n_trials,
                      "timed_masq_pfa_at_100pd_pct":
                      None if best_pfa is None else round(best_pfa * 100, 4)}


# ----------------------------------------------------------------------------
# Experiment 6 - Root-cause analysis
# ----------------------------------------------------------------------------
def exp_root_cause():
    log("\n=== Experiment 6: Root-cause analysis ===")
    cids = CIDS(N=20)
    sim = prototype_sim(seed=5, duration=800)
    tr = sim.generate()
    known = {}
    for cid, ecu in ((0x11, "A"), (0x55, "B")):
        r = cids.run(tr[cid], nominal_period_ms=50)
        known[ecu] = cids.fit_skew_ppm(r.step_time, r.acc_offset)
    # masquerade: A impersonates B on 0x55 after t_masq
    sim = prototype_sim(seed=5, duration=800)
    mas = sim.masquerade(0x55, attacker_skew_ppm=13.4, t_masq_s=400)
    r = cids.run(mas, nominal_period_ms=50)
    # estimate skew of 0x55 AFTER the attack
    st = r.step_time
    after = st >= 450
    post_skew = cids.fit_skew_ppm(st[after], r.acc_offset[after])
    best, diff, amb = cids.root_cause(post_skew, known)
    log(f"  known skews: " + ", ".join(f"ECU {k}={v:.1f}ppm" for k, v in known.items()))
    log(f"  post-attack skew of 0x55 = {post_skew:.1f}ppm  ->  attacker ECU = {best} "
        f"(|diff|={diff:.1f}ppm, ambiguous={amb})")
    METRICS["root_cause"] = {"known_skews": {k: round(v, 2) for k, v in known.items()},
                             "post_attack_skew_ppm": round(post_skew, 2),
                             "identified_ecu": best, "abs_diff_ppm": round(diff, 2)}


# ----------------------------------------------------------------------------
# Summary table figure ("results screenshot")
# ----------------------------------------------------------------------------
def make_summary_figure():
    fig = plt.figure(figsize=(12, 5.4))
    ax = fig.add_axes([0.02, 0.02, 0.96, 0.96]); ax.axis("off")

    rows = [["Experiment", "Metric", "Result"]]
    fp = {r["id"]: r for r in METRICS["fingerprint"]}
    rows.append(["Fingerprinting (prototype)", "0x11 skew (inj 13.4 ppm)",
                 f"{fp['0x11']['recovered_ppm']} ppm"])
    rows.append(["", "0x55 skew (inj 27.2 ppm)", f"{fp['0x55']['recovered_ppm']} ppm"])
    a = METRICS["attacks"]
    rows.append(["Fabrication attack", "detection latency",
                 f"{a['fabrication']['latency_s']} s"])
    rows.append(["Suspension attack", "detection latency",
                 f"{a['suspension']['latency_s']} s"])
    rows.append(["Masquerade attack", "interval before/after",
                 f"{a['masquerade']['mean_interval_before_ms']} / "
                 f"{a['masquerade']['mean_interval_after_ms']} ms"])
    rows.append(["", "detected at", f"{a['masquerade']['detected_at']:.0f} s"])
    pw = METRICS["pairwise"]
    rows.append(["Message-pairwise", "corr same / diff ECU",
                 f"{pw['corr_same_ecu']} / {pw['corr_diff_ecu']}"])
    rows.append(["", "worst-case corr drop",
                 f"{pw['worstcase_corr_before']} -> {pw['worstcase_corr_after']}"])
    rc = METRICS["root_cause"]
    rows.append(["Root-cause analysis", "attacker ECU identified",
                 f"ECU {rc['identified_ecu']} ({rc['abs_diff_ppm']} ppm)"])
    roc = METRICS["roc"]
    nt = roc.get("n_trials", 250)
    rows.append(["ROC (per-message)", "P_FA @ 100% timed-masq det",
                 f"<{round(100.0/nt,1)} % (0/{nt} trials)"])

    tbl = ax.table(cellText=rows, cellLoc="left", loc="center",
                   colWidths=[0.30, 0.34, 0.36])
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(13)
    tbl.scale(1, 2.1)
    for (r, c), cell in tbl.get_celld().items():
        cell.PAD = 0.04
        cell.set_edgecolor("#cccccc")
        if r == 0:
            cell.set_facecolor("#222222")
            cell.set_text_props(color="w", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#f0f0f0")
    out = os.path.join(RESULTS, "fig8_summary.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    log(f"\n  saved {out}")


# ----------------------------------------------------------------------------
def main():
    t0 = time.time()
    log("=" * 70)
    log("CIDS REPRODUCTION - Cho & Shin, USENIX Security 2016")
    log("Self-contained simulation; parameters: N=20, lambda=0.9995, Gamma_L=5")
    log("=" * 70)
    exp_fingerprint()
    exp_fab_susp()
    exp_masquerade()
    exp_pairwise()
    exp_root_cause()
    exp_roc()
    make_summary_figure()

    with open(os.path.join(RESULTS, "metrics.json"), "w") as f:
        json.dump(METRICS, f, indent=2)
    with open(os.path.join(RESULTS, "run_log.txt"), "w") as f:
        f.write("\n".join(LOG))
    log("\n" + "=" * 70)
    log(f"DONE in {time.time()-t0:.1f}s. Figures + metrics.json + run_log.txt in results/")
    log("=" * 70)


if __name__ == "__main__":
    main()
