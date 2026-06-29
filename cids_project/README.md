# CIDS Reproduction — Clock-Based Intrusion Detection for the CAN Bus

A practical, self-contained reproduction of:

> K.-T. Cho and K. G. Shin, *Fingerprinting Electronic Control Units for Vehicle
> Intrusion Detection*, USENIX Security Symposium, 2016.

CIDS fingerprints in-vehicle ECUs by the clock skew visible in the timing of
periodic CAN messages, and detects intrusions (fabrication, suspension,
masquerade) as abrupt changes in that fingerprint.

This project recreates the **method** in simulation — no vehicle hardware or
proprietary CAN logs are needed. Everything regenerates from one command.

## Structure

```
src/can_bus.py        CAN traffic generator (clock-skew timing model + attacks)
src/cids.py           CIDS detector: RLS skew estimation, CUSUM, pairwise, root-cause
experiments/run_all.py    runs all six experiments, writes figures + metrics.json
experiments/render_console.py   renders the run log as a terminal screenshot
results/                  generated figures, metrics.json, run_log.txt
report/CIDS_Reproduction_Report.pdf   the final paper
```

## Reproduce

```bash
pip install numpy scipy matplotlib
python experiments/run_all.py          # ~4-5 min (the ROC sweep dominates)
python experiments/render_console.py   # terminal-style screenshot of the run
```

## Key parameters (from the paper)

`N = 20` messages per step, RLS forgetting factor `λ = 0.9995`, CUSUM threshold
`Γ_L = 5`; the CUSUM slack `κ` is swept to trace the ROC curves.

## What is reproduced

1. Clock skew as a stable, per-ECU fingerprint (recovered within ~1–4 % of injected).
2. Detection of fabrication and suspension attacks (sub-second latency).
3. Detection of the masquerade attack with **unchanged message frequency**
   (invisible to frequency/entropy IDSs).
4. Message-pairwise detection of the worst-case, skew-matched masquerade.
5. Root-cause analysis (naming the impersonating ECU).
6. ROC / false-alarm trade-off across attack types.

See `report/CIDS_Reproduction_Report.pdf` for the full write-up, including a
discussion of one important subtlety in the paper's offset definition that the
reproduction surfaced.

> Note: the per-ECU clock skews are **simulation parameters** chosen in the same
> range the paper reports; they are not measurements from real hardware. Results
> differ from the original in the expected ways for a simulated reproduction
> (platform, finite trial counts), as discussed in the report.
