"""
cids.py
=======
Implementation of CIDS (Clock-based Intrusion Detection System) from
Cho & Shin, USENIX Security 2016.

The module implements, faithfully to the paper:

  * Clock-skew estimation from message arrival timestamps using the Recursive
    Least Squares (RLS) formulation of Algorithm 1 and Eq.(3):
        O_acc[k] = S[k] * t[k] + e[k]
    where O_acc is the accumulated clock offset, S the regression parameter
    (= estimated clock skew), t the elapsed time, e the identification error.

  * CUSUM change-point detection on the identification error e (Eq.(4)) with
    control limits L+ / L- and threshold Gamma_L.

  * Message-pairwise detection via the correlation of per-step average clock
    offsets of two message IDs.

  * Root-cause analysis: matching an attacked ID's skew to a known ECU.

Default parameters follow the paper: N = 20, lambda = 0.9995, Gamma_L = 5.
"""

from __future__ import annotations

import numpy as np


class CIDSResult:
    """Container for the per-step time-series produced by per-message detection."""

    def __init__(self):
        self.step_time = []     # elapsed time t[k] at each step [s]
        self.mu_T = []          # average timestamp interval per step [s]
        self.avg_offset = []    # per-step average clock offset O[k] [s]
        self.acc_offset = []    # accumulated clock offset O_acc[k] [s]
        self.skew = []          # RLS-estimated skew S[k] (slope, dimensionless)
        self.id_error = []      # identification error e[k]
        self.Lplus = []         # CUSUM upper control limit
        self.Lminus = []        # CUSUM lower control limit
        self.detected_at = None # step time of first alarm, or None

    def as_arrays(self):
        for k, v in list(self.__dict__.items()):
            if isinstance(v, list):
                setattr(self, k, np.asarray(v))
        return self

    @property
    def skew_ppm(self):
        """Final estimated clock skew in ppm."""
        return float(self.skew[-1]) * 1e6 if len(self.skew) else float("nan")


class CIDS:
    """
    Per-message clock-based detector.

    Parameters
    ----------
    N : int
        Batch size -- offsets/skews are updated every N messages (paper: 20).
    lam : float
        RLS forgetting factor lambda (paper: 0.9995).
    kappa : float
        CUSUM slack/sensitivity parameter (number of std-devs allowed before
        accumulation).  Tuned over a range to draw ROC curves.
    Gamma_L : float
        CUSUM detection threshold (paper rule of thumb: 4-5; paper uses 5).
    delta : float
        RLS covariance initialisation P[0] = delta * I.
    """

    def __init__(self, N=20, lam=0.9995, kappa=4.0, Gamma_L=5.0, delta=1.0):
        self.N = N
        self.lam = lam
        self.kappa = kappa
        self.Gamma_L = Gamma_L
        self.delta = delta

    # ------------------------------------------------------------------ #
    #  Per-message detection (Algorithm 1 + CUSUM, Eq.(3)-(4))            #
    # ------------------------------------------------------------------ #
    def run(self, arrival_times, nominal_period_ms=None, train=100,
            monitor_until_s=None, timeout_factor=6.0, warmup_steps=60,
            return_step_offsets=False):
        """
        Run per-message CIDS on a single message ID's arrival-timestamp vector.

        Parameters
        ----------
        nominal_period_ms : float or None
            Design transmission period of the message.  If None it is estimated
            from a clean training window and rounded to the nearest 1 ms (CAN
            periods are integer-millisecond design constants).
        train : int
            Number of leading (assumed-clean) messages used to learn the
            nominal period.
        monitor_until_s : float or None
            If set, CIDS keeps a watchdog: if the message stops arriving for
            longer than `timeout_factor` periods before this time (a suspension
            attack, Algorithm 1 lines 11-15), synthetic "missed" steps with a
            large offset are emitted so the detector fires.

        Returns a CIDSResult.  If `return_step_offsets` is True, also returns
        the per-step (de-trended) average offsets used by pairwise detection.
        """
        a = np.asarray(arrival_times, dtype=float)
        N = self.N
        res = CIDSResult()
        if len(a) < 2 * N:
            return (res.as_arrays(), np.array([])) if return_step_offsets else res.as_arrays()

        # --- nominal period (seconds) ---
        if nominal_period_ms is not None:
            T_nom = nominal_period_ms * 1e-3
        else:
            med = float(np.median(np.diff(a[:min(train, len(a))])))
            T_nom = max(round(med * 1e3) * 1e-3, 1e-3)   # round to nearest 1 ms

        a0 = a[0]
        n_steps = len(a) // N
        global_idx = np.arange(len(a))                  # how many periods elapsed

        # RLS state
        S, P, lam = 0.0, self.delta, self.lam

        # ---- Pass 1: build the per-step time-series with RLS ----
        T_, MU_, OFF_, OACC_, SK_, E_ = [], [], [], [], [], []
        last_ts = a0
        for k in range(n_steps):
            sl = slice(k * N, (k + 1) * N)
            batch = a[sl]
            idx = global_idx[sl]
            mu_T = float(np.mean(np.diff(batch)))

            # suspension watchdog: a large gap before this batch -> "missed" step
            gap = batch[0] - last_ts
            if gap > timeout_factor * T_nom:
                t_gap = float(batch[0] - a0)
                O_big = (abs(OACC_[-1]) if OACC_ else 0.0) + gap
                T_.append(t_gap); MU_.append(gap); OFF_.append(gap)
                OACC_.append(O_big); SK_.append(S); E_.append(O_big - S * t_gap)
            last_ts = batch[-1]

            # accumulated clock offset vs nominal-period grid (Fig. 3):
            # offset_i = a_i - (a0 + i*T_nom) = transmitter clock drift at msg i
            offset = batch - (a0 + idx * T_nom)
            O_acc = float(np.mean(offset))
            t = float(batch[-1] - a0)
            e = O_acc - S * t                          # identification error (Eq.3)

            # RLS skew update (Algorithm 1, lines 3-5)
            G = (lam ** -1 * P * t) / (1.0 + lam ** -1 * t * t * P)
            P = lam ** -1 * (P - G * t * P)
            S = S + G * e

            T_.append(t); MU_.append(mu_T); OFF_.append(O_acc)
            OACC_.append(O_acc); SK_.append(S); E_.append(e)

        # suspension watchdog: stream falls silent before the monitoring horizon.
        # Fire one timeout interval after the last received message (not at the
        # far horizon), so detection latency reflects the watchdog timeout.
        if monitor_until_s is not None and T_:
            last_msg = a[-1] - a0                       # true last received message
            silence = monitor_until_s - last_msg
            if silence > timeout_factor * T_nom:
                t_fire = last_msg + timeout_factor * T_nom
                O_big = abs(OACC_[-1]) + timeout_factor * T_nom
                T_.append(float(t_fire)); MU_.append(timeout_factor * T_nom)
                OFF_.append(timeout_factor * T_nom)
                OACC_.append(O_big); SK_.append(S); E_.append(O_big - S * t_fire)

        T_ = np.asarray(T_); E_ = np.asarray(E_)

        # ---- Pass 2: CUSUM detection with a baseline learned on warm-up ----
        Lp = Lm = 0.0
        Lp_s, Lm_s = [], []
        w = min(warmup_steps, max(2, len(E_) // 2))
        base = E_[max(1, w // 3):w]                     # skip RLS transient
        mu_e = float(np.mean(base)) if len(base) else 0.0
        var_e = float(np.var(base)) + 1e-18 if len(base) else 1.0
        b = 0.01                                        # EWMA adaptation rate
        for k in range(len(E_)):
            sigma = np.sqrt(max(var_e, 1e-18))
            z = (E_[k] - mu_e) / sigma
            if k >= w:
                Lp = max(0.0, Lp + z - self.kappa)
                Lm = max(0.0, Lm - z - self.kappa)
                if abs(z) < 3.0:                        # in-control: adapt baseline
                    d = E_[k] - mu_e
                    mu_e += b * d
                    var_e = (1 - b) * var_e + b * d * d
                if res.detected_at is None and (Lp > self.Gamma_L or Lm > self.Gamma_L):
                    res.detected_at = float(T_[k])
            Lp_s.append(Lp); Lm_s.append(Lm)

        res.step_time = T_; res.mu_T = np.asarray(MU_); res.avg_offset = np.asarray(OFF_)
        res.acc_offset = np.asarray(OACC_); res.skew = np.asarray(SK_)
        res.id_error = E_; res.Lplus = np.asarray(Lp_s); res.Lminus = np.asarray(Lm_s)
        # de-trended per-step offsets (skew removed) for pairwise correlation
        if return_step_offsets:
            st, ao = res.step_time, res.acc_offset
            if len(st) >= 2:
                trend = np.polyval(np.polyfit(st, ao, 1), st)
                step_offsets = ao - trend
            else:
                step_offsets = np.array([])
            return res, step_offsets
        return res

    # ------------------------------------------------------------------ #
    #  Skew via robust linear fit (for clean fingerprint reporting)      #
    # ------------------------------------------------------------------ #
    @staticmethod
    def fit_skew_ppm(step_time, acc_offset):
        """Least-squares slope of accumulated offset vs time, expressed in ppm."""
        st = np.asarray(step_time, float)
        ao = np.asarray(acc_offset, float)
        if len(st) < 2:
            return float("nan")
        slope = np.polyfit(st, ao, 1)[0]    # [s of offset] per [s of time]
        return slope * 1e6                  # -> ppm

    # ------------------------------------------------------------------ #
    #  Message-pairwise detection (offset correlation)                   #
    # ------------------------------------------------------------------ #
    def pairwise_correlation(self, offsets_a, offsets_b):
        """Pearson correlation between two messages' per-step average offsets."""
        n = min(len(offsets_a), len(offsets_b))
        if n < 3:
            return float("nan")
        a = np.asarray(offsets_a[:n], float)
        b = np.asarray(offsets_b[:n], float)
        if np.std(a) < 1e-15 or np.std(b) < 1e-15:
            return 0.0
        return float(np.corrcoef(a, b)[0, 1])

    def pairwise_cusum(self, offsets_a, offsets_b, warmup=150, window=50):
        """
        Message-pairwise detector (paper Sec. 4.3).  Two messages from the same
        ECU obey a linear relationship O_B = alpha*O_A + e_corr.  CIDS fits that
        model on clean (warm-up) traffic and then watches the residual e_corr.
        A silent transmitter swap (masquerade) breaks the relationship: the
        residual's *magnitude* jumps even though its mean stays ~0.  We therefore
        run an upper-sided CUSUM on the standardised residual magnitude, with the
        normaliser fixed from the warm-up so brief low-variance windows do not
        cause false alarms.

        Returns (L, rolling_corr): the CUSUM control limit and a rolling
        correlation series (for visualisation; NaN during the first window).
        """
        a = np.asarray(offsets_a, float)
        b = np.asarray(offsets_b, float)
        n = min(len(a), len(b))
        a, b = a[:n], b[:n]
        w = min(warmup, max(3, n // 2))

        # fixed linear model fitted on the clean warm-up window
        alpha, beta = np.polyfit(a[:w], b[:w], 1)
        resid = b - (alpha * a + beta)
        sigma0 = float(np.std(resid[:w])) + 1e-18
        z = np.abs(resid) / sigma0                 # |standardised residual|
        h = 0.8                                     # E|N(0,1)| in-control mean

        L = 0.0
        L_series = []
        for k in range(n):
            if k >= w:
                L = max(0.0, L + z[k] - h - self.kappa)
            L_series.append(L)

        # rolling correlation, for the figure only
        rc = np.full(n, np.nan)
        for k in range(window, n):
            aa, bb = a[k - window:k], b[k - window:k]
            if np.std(aa) > 1e-18 and np.std(bb) > 1e-18:
                rc[k] = np.corrcoef(aa, bb)[0, 1]
        return np.asarray(L_series), rc

    # ------------------------------------------------------------------ #
    #  Root-cause analysis                                               #
    # ------------------------------------------------------------------ #
    @staticmethod
    def root_cause(target_skew_ppm, known_skews, tol_ppm=10.0):
        """
        Identify which known ECU most likely produced a message with
        `target_skew_ppm`.  `known_skews` maps ECU label -> skew[ppm].
        Returns (best_label, abs_diff_ppm, ambiguous_flag).
        """
        labels = list(known_skews.keys())
        diffs = {lbl: abs(target_skew_ppm - known_skews[lbl]) for lbl in labels}
        best = min(diffs, key=diffs.get)
        ordered = sorted(diffs.values())
        ambiguous = len(ordered) > 1 and (ordered[1] - ordered[0]) < tol_ppm
        return best, diffs[best], ambiguous
