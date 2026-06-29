# Cyber-Physical Systems and IoT Security — Reproduction Projects

**Author:** Saeid Abbasnejad (Student No. 2154285)

This repository contains my practical reproduction projects for the course
*Cyber-Physical Systems and IoT Security*. Each project recreates the core
method of a reference paper in a self-contained simulation (no special
hardware or proprietary datasets), runs the experiments, and produces a written
report following the course template.

## Projects

### 1. `cids_project/` — Clock-Based Intrusion Detection for the CAN Bus
Reproduction of **K.-T. Cho and K. G. Shin, "Fingerprinting Electronic Control
Units for Vehicle Intrusion Detection," USENIX Security 2016.** A CAN-bus
simulator plus the full CIDS pipeline (RLS clock-skew estimation, CUSUM
detection, message-pairwise detection, root-cause analysis), evaluated against
fabrication, suspension and masquerade attacks.

### 2. `modbus_project/` — Modbus/TCP Attack Taxonomy
Reproduction of **Huitsing, Chandia, Papa and Shenoi, "Attack taxonomies for
the Modbus protocols," IJCIP 2008.** A pure-Python Modbus/TCP master–slave with
a simulated process, and an attack toolkit that demonstrates one representative
attack per category of the taxonomy.

## Layout (same in every project)

```
<project>/
  src/           core implementation
  experiments/   scripts that run the experiments and produce the figures
  results/       generated figures, metrics.json and the run log
  report/        the final report (PDF)
  README.md      project-specific instructions
```

## Running a project

```bash
pip install numpy scipy matplotlib
cd <project>
python experiments/run_all.py     # runs the experiments, writes results/
```

See each project's own `README.md` for details.
