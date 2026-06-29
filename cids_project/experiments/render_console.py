"""
render_console.py
=================
Render the captured run log (results/run_log.txt) as a terminal-style PNG so it
can be embedded in the report as a screenshot of the actual test run.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "results")

with open(os.path.join(RESULTS, "run_log.txt"), encoding="utf-8") as f:
    lines = f.read().splitlines()

# keep it readable: drop the noisy "saved ..." path lines
shown = [ln for ln in lines if "saved C:" not in ln]
text = "\n".join(shown)

n = len(shown)
fig_h = max(4.0, 0.205 * n)
fig = plt.figure(figsize=(11.5, fig_h), dpi=130)
fig.patch.set_facecolor("#0c0c0c")
ax = fig.add_axes([0, 0, 1, 1]); ax.axis("off")
ax.set_facecolor("#0c0c0c")

# title bar
ax.text(0.012, 0.992, "  CIDS reproduction  -  python experiments/run_all.py",
        va="top", ha="left", family="monospace", fontsize=10,
        color="#9cdcfe", transform=ax.transAxes)
ax.text(0.012, 0.965, text, va="top", ha="left", family="monospace",
        fontsize=8.6, color="#d4d4d4", transform=ax.transAxes)

out = os.path.join(RESULTS, "fig0_console.png")
fig.savefig(out, facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.15)
print("Wrote", out)
