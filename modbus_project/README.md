# Modbus Attack-Taxonomy Reproduction

A practical, self-contained reproduction of:

> P. Huitsing, R. Chandia, M. Papa and S. Shenoi, *Attack taxonomies for the
> Modbus protocols*, International Journal of Critical Infrastructure
> Protection, vol. 1, pp. 37–44, 2008.

The reference paper is an **analytical taxonomy** — it classifies 20 serial and
28 TCP Modbus attacks along *threat category* (interception, interruption,
modification, fabrication) × *target asset* (master, field device,
communication link / network path, message) but reports **no experiments**.

This project turns the taxonomy into a **live testbed**: a from-scratch Modbus
TCP master/slave driving a simulated tank/pumping process, plus an attack
toolkit. It then runs one representative attack from every threat category and
measures the real effect. No PLC/RTU or industrial hardware is needed; the
Modbus wire protocol is implemented from the spec (no `pymodbus`) so the attack
toolkit can also craft malformed/spoofed frames. Everything regenerates from
one command.

## Structure

```
src/modbus_protocol.py   Modbus TCP wire format (MBAP + PDU encode/decode)
src/process_model.py     simulated tank/pump physical process
src/modbus_server.py     Modbus TCP slave / server (spec-conformant, trusting)
src/modbus_client.py     Modbus TCP master / client (legit SCADA loop)
src/attacks.py           attack toolkit (B1/B2/B4/B6/B9/B14/S1/S4/S5/T10)
experiments/run_all.py        runs all 7 scenarios -> figures + metrics.json
experiments/render_console.py renders the run log as a terminal screenshot
results/                      generated figures, metrics.json, run_log.txt
report/Modbus_Reproduction_Report.pdf   the final paper
```

## Reproduce

```bash
pip install numpy matplotlib
python experiments/run_all.py          # ~90 s (live TCP scenarios)
python experiments/render_console.py   # terminal-style screenshot of the run
```

## Attacks reproduced (mapped to the paper's taxonomy)

| Code | Attack | Threat | Observed effect |
|------|--------|--------|-----------------|
| B6/S5/B9 | Network Scan / Report Server ID / Passive Recon | Interception | full asset map + identity recovered, no auth |
| B4 | Direct Slave Control | Modification/Fabrication | master overridden, tank overflow |
| B2 | Baseline Response Replay (via MITM B14) | Modification | operator blinded (large awareness gap) |
| T10 | TCP Pool Exhaustion | Interruption (DoS) | legitimate master locked out |
| S4 | Remote Restart (FC08/0x01) | Interruption | multi-second comms outage |
| S1 | Diagnostic Register Reset (FC08/0x0A) | Modification | diagnostic counters wiped (anti-forensics) |
| B1 | Broadcast Message Spoofing (unit id 0) | Fabrication | silent write, no response |

## What is reproduced

1. Normal Modbus TCP master/slave communication (cleartext, unauthenticated).
2. A representative attack from **every** threat category in the taxonomy.
3. Real, measured effects (overflow latency, awareness gap, DoS lock-out point,
   outage duration) recorded in `results/metrics.json`.
4. A mapping of every result back onto the paper's threat × target taxonomy and
   the three control objectives (loss of confidentiality / awareness / control).

See `report/Modbus_Reproduction_Report.pdf` for the full write-up, including the
comparison with the paper, a critical evaluation and limitations.

> Note: the testbed is a localhost Modbus **TCP** simulation. Absolute numbers
> (pool size, restart timer, process rates) are testbed parameters, not
> measurements of real hardware; the reference paper reports no numbers, so the
> reproduction makes the taxonomy concrete rather than chasing matching figures.
> Results differ from a hardware setup in the expected ways, as discussed in the
> report.
