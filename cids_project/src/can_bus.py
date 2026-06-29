"""
can_bus.py
==========
A CAN-bus traffic generator that reproduces the timing model used by CIDS
(Cho & Shin, "Fingerprinting Electronic Control Units for Vehicle Intrusion
Detection", USENIX Security 2016), specifically the message-arrival timing
analysis of Fig. 3.

Physical model
--------------
Every ECU schedules a periodic message every ``period`` seconds *according to
its own quartz clock*.  Because each crystal runs slightly fast or slow, the
true (receiver-side) inter-departure time is ``period * (1 + skew)`` where
``skew`` is a small, ECU-specific constant expressed in parts-per-million
(ppm).  This constant skew is exactly the hardware fingerprint CIDS exploits.

The arrival timestamp recorded by the receiver R for the i-th message is

    a_i = i * period * (1 + skew)        # ideal periodic schedule on ECU clock
        + sched_jitter_i                 # ECU scheduling jitter  (zero-mean)
        + bus_delay_i                    # queueing / arbitration / frame time
        + quant_noise_i                  # receiver timestamp quantisation

which is the decomposition  a_i = i*T + O_i + d_i + n_i  of Eq.(1)/Fig.3 in the
paper (O_i is the accumulated clock offset i*T*skew).

The skews assigned below are *simulation parameters*, deliberately chosen in
the same numerical range the paper reports for its CAN-bus prototype and the
Honda Accord, so that the regenerated figures are visually comparable to the
originals.  They are NOT measurements from real hardware.
"""

from __future__ import annotations

import numpy as np


# ---------------------------------------------------------------------------
# Message / ECU specification
# ---------------------------------------------------------------------------
class Message:
    """One periodic CAN message stream produced by a given ECU."""

    def __init__(self, can_id, ecu, period_ms):
        self.can_id = can_id            # e.g. 0x11
        self.ecu = ecu                  # owning ECU label, e.g. "A"
        self.period_ms = period_ms      # nominal transmission period [ms]


class ECU:
    """An electronic control unit with a constant clock skew (its fingerprint)."""

    def __init__(self, label, skew_ppm):
        self.label = label
        self.skew_ppm = skew_ppm        # constant clock skew [ppm]


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------
class CanBusSimulator:
    """
    Generates per-message arrival-timestamp traces for a set of ECUs/messages.

    Parameters
    ----------
    duration_s : float
        Length of the trace in seconds.
    sched_jitter_us : float
        Std-dev of the transmitter's scheduling jitter [microseconds].
    bus_delay_us : float
        Mean bus/transmission delay [microseconds] (frame time + light load).
    bus_delay_jitter_us : float
        Std-dev of the bus-delay component [microseconds].
    quant_us : float
        Receiver timestamp quantisation step [microseconds].
    seed : int
        RNG seed for reproducibility.
    """

    def __init__(self, duration_s=300.0, sched_jitter_us=20.0,
                 bus_delay_us=300.0, bus_delay_jitter_us=15.0,
                 quant_us=10.0, seed=0):
        self.duration_s = duration_s
        self.sched_jitter_us = sched_jitter_us
        self.bus_delay_us = bus_delay_us
        self.bus_delay_jitter_us = bus_delay_jitter_us
        self.quant_us = quant_us
        self.rng = np.random.default_rng(seed)

        self.ecus = {}      # label -> ECU
        self.messages = []  # list[Message]
        self._walk = {}     # label -> (grid_t, offset_walk)  shared per-ECU offset
        self.walk_us = 30.0  # std-dev scale of the shared per-ECU offset drift [us]

    # -- configuration ------------------------------------------------------
    def add_ecu(self, label, skew_ppm):
        self.ecus[label] = ECU(label, skew_ppm)
        return self.ecus[label]

    def _ecu_offset_walk(self, label):
        """
        Lazily build a slow, shared per-ECU clock-offset fluctuation (seconds),
        modelling temperature/workload-driven jitter common to every message a
        given ECU sends.  Messages from the SAME ECU therefore share these
        fluctuations (-> correlated offsets, Fig. 9); different ECUs do not.
        """
        if label not in self._walk:
            dt = 0.5                                   # 0.5 s grid
            n = int(self.duration_s / dt) + 4
            grid = np.arange(n) * dt
            # bounded, smooth, always-varying "temperature/workload" drift, modelled
            # as a sum of slow sinusoids with ECU-specific random amplitude/phase.
            # All of an ECU's messages share this exact process -> their offsets
            # correlate strongly and stably (the condition for pairwise detection),
            # while different ECUs draw independent processes.
            periods = [37.0, 71.0, 113.0, 197.0]       # seconds
            walk = np.zeros(n)
            for per in periods:
                amp = self.rng.uniform(0.5, 1.0)
                ph = self.rng.uniform(0, 2 * np.pi)
                walk += amp * np.sin(2 * np.pi * grid / per + ph)
            walk *= self.walk_us * 1e-6 / (np.std(walk) + 1e-18)
            walk -= walk.mean()
            self._walk[label] = (grid, walk)
        return self._walk[label]

    def add_message(self, can_id, ecu_label, period_ms):
        self.messages.append(Message(can_id, ecu_label, period_ms))

    # -- trace generation ---------------------------------------------------
    def _arrival_times(self, msg, duration_s=None, t_start=0.0,
                       skew_ppm_override=None):
        """
        Produce the arrival-timestamp vector (seconds) for one message stream.

        Returns a strictly increasing 1-D numpy array of receiver timestamps.
        """
        if duration_s is None:
            duration_s = self.duration_s
        ecu = self.ecus[msg.ecu]
        if skew_ppm_override is None:
            # small per-message perturbation (deterministic per ID): emulates the
            # aggregate of finite-window estimation error and bus-scheduling bias
            # so recovered skews show realistic scatter instead of the exact
            # injected value.  Same ECU -> still close; different ECUs -> distinct.
            pert = np.random.default_rng(int(msg.can_id) * 7919 + 11).normal(0.0, 0.02)
            skew = ecu.skew_ppm * (1.0 + pert) * 1e-6
        else:
            skew = skew_ppm_override * 1e-6
        T = msg.period_ms * 1e-3                      # nominal period [s]
        n = int(np.ceil(duration_s / T)) + 1
        idx = np.arange(1, n + 1)

        # ideal periodic schedule on the (skewed) ECU clock
        ideal = idx * T * (1.0 + skew)

        # shared per-ECU offset fluctuation (sampled at the message times); an
        # injected/attacker stream gets its OWN independent fluctuation process
        walk_key = (msg.ecu if skew_ppm_override is None
                    else "_atk:" + str(skew_ppm_override))
        grid, walk = self._ecu_offset_walk(walk_key)
        shared = np.interp(t_start + ideal, grid, walk)

        # zero-mean transmitter scheduling jitter
        sched = self.rng.normal(0.0, self.sched_jitter_us * 1e-6, size=n)
        # bus / transmission delay (mean + jitter), always positive
        delay = (self.bus_delay_us
                 + self.rng.normal(0.0, self.bus_delay_jitter_us, size=n)) * 1e-6
        delay = np.clip(delay, 0.0, None)

        a = t_start + ideal + shared + sched + delay
        # receiver timestamp quantisation
        if self.quant_us > 0:
            q = self.quant_us * 1e-6
            a = np.round(a / q) * q
        a = np.maximum.accumulate(a)                  # enforce monotonicity
        return a

    def generate(self):
        """Return {can_id: arrival_times[np.ndarray]} for all clean messages."""
        return {m.can_id: self._arrival_times(m) for m in self.messages}

    # -- attack injectors ---------------------------------------------------
    def fabrication(self, can_id, attacker_skew_ppm, t_attack_s, inject_period_ms=None):
        """
        Fabrication attack: a strong attacker ECU injects extra messages with a
        spoofed `can_id` starting at `t_attack_s`, *in addition* to the genuine
        traffic.  Returns the merged (sorted) arrival timestamps.
        """
        msg = self._msg(can_id)
        genuine = self._arrival_times(msg)
        # attacker uses its OWN clock skew -> a separate, denser stream
        atk_period = inject_period_ms if inject_period_ms else msg.period_ms
        atk_msg = Message(can_id, "_attacker", atk_period)
        self.ecus.setdefault("_attacker", ECU("_attacker", attacker_skew_ppm))
        atk = self._arrival_times(atk_msg, skew_ppm_override=attacker_skew_ppm)
        atk = atk[atk >= t_attack_s]
        merged = np.sort(np.concatenate([genuine, atk]))
        return merged

    def suspension(self, can_id, t_attack_s):
        """
        Suspension attack: the genuine ECU stops transmitting `can_id` at
        `t_attack_s`.  CIDS sees the message simply disappear.
        """
        msg = self._msg(can_id)
        genuine = self._arrival_times(msg)
        return genuine[genuine < t_attack_s]

    def masquerade(self, can_id, attacker_skew_ppm, t_masq_s,
                   switch_delay_ms=1.0):
        """
        Masquerade attack: until t_masq the genuine ECU sends `can_id`; after
        t_masq a *different* ECU (the strong attacker, distinct skew) sends it
        at the same nominal period.  Message frequency is unchanged -> invisible
        to frequency-based IDSs, but the clock skew (slope) changes.
        """
        msg = self._msg(can_id)
        before = self._arrival_times(msg)
        before = before[before < t_masq_s]
        if len(before):
            t0 = before[-1] + switch_delay_ms * 1e-3
        else:
            t0 = t_masq_s
        # attacker continues the stream with ITS skew, starting just after t_masq
        atk_msg = Message(can_id, "_masq", msg.period_ms)
        self.ecus.setdefault("_masq", ECU("_masq", attacker_skew_ppm))
        remaining = self.duration_s - t0
        after = self._arrival_times(atk_msg, duration_s=max(remaining, 0.0),
                                    t_start=t0, skew_ppm_override=attacker_skew_ppm)
        return np.sort(np.concatenate([before, after]))

    def _msg(self, can_id):
        for m in self.messages:
            if m.can_id == can_id:
                return m
        raise KeyError(f"message {can_id:#x} not configured")
