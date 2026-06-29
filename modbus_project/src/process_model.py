"""
process_model.py
================
A tiny physical-process simulation so that Modbus attacks have a *visible*
consequence, mirroring the paper's pipeline / oil-and-gas framing.

The slave (a simulated PLC/RTU) controls a water/fluid storage tank:

    inlet valve --> [ T A N K ] --> outlet valve
                       pump

State exposed over Modbus
-------------------------
Coils (read/write, FC01/05):
    0  PUMP_RUN        pump motor on/off
    1  INLET_VALVE     inlet valve open/closed
    2  OUTLET_VALVE    outlet valve open/closed
    3  HIGH_ALARM      high-level alarm (set by PLC logic)

Discrete inputs (read-only, FC02):
    0  LEVEL_OK        1 when level is within the safe band

Holding registers (read/write, FC03/06/16):
    0  PUMP_SPEED_SP   commanded pump speed [0..1000]
    1  LEVEL_SETPOINT  desired tank level   [0..1000] (= 0..100.0 %)

Input registers (read-only, FC04):
    0  TANK_LEVEL      measured level    [0..1000] (= 0..100.0 %)
    1  INLET_PRESSURE  measured pressure [0..1000]
    2  FLOW_RATE       measured flow     [0..1000]

The register *values* are scaled integers (tenths of a percent / unit), which
is exactly how real Modbus field devices encode engineering units.
"""

from __future__ import annotations

import threading

# coil indices
PUMP_RUN, INLET_VALVE, OUTLET_VALVE, HIGH_ALARM = 0, 1, 2, 3
# discrete input
LEVEL_OK = 0
# holding registers
PUMP_SPEED_SP, LEVEL_SETPOINT = 0, 1
# input registers
TANK_LEVEL, INLET_PRESSURE, FLOW_RATE = 0, 1, 2

HIGH_LIMIT = 900     # 90.0 %  -> alarm / overflow risk
LOW_LIMIT = 100      # 10.0 %  -> dry-running risk


class TankProcess:
    """Time-stepped tank model whose state lives in the Modbus data store."""

    def __init__(self, store, dt=0.05):
        self.store = store
        self.dt = dt
        self._lock = threading.Lock()
        # initial conditions: half-full, pumping in, controlled band
        store.input_registers[TANK_LEVEL] = 500
        store.input_registers[INLET_PRESSURE] = 420
        store.input_registers[FLOW_RATE] = 0
        store.holding_registers[PUMP_SPEED_SP] = 600
        store.holding_registers[LEVEL_SETPOINT] = 500
        store.coils[PUMP_RUN] = True
        store.coils[INLET_VALVE] = True
        store.coils[OUTLET_VALVE] = True
        store.coils[HIGH_ALARM] = False
        store.discrete_inputs[LEVEL_OK] = True

    def step(self):
        """Advance the physics by one dt and update measured registers."""
        with self._lock:
            s = self.store
            level = s.input_registers[TANK_LEVEL]
            speed = s.holding_registers[PUMP_SPEED_SP]

            inflow = 0.0
            if s.coils[PUMP_RUN] and s.coils[INLET_VALVE]:
                inflow = 0.020 * speed            # pump speed drives inflow
            outflow = 0.0
            if s.coils[OUTLET_VALVE]:
                outflow = 6.0                     # gravity-fed constant draw

            level += (inflow - outflow) * self.dt * 10.0
            level = max(0, min(1000, int(round(level))))
            s.input_registers[TANK_LEVEL] = level

            # pressure tracks pump speed when running; flow tracks valves
            s.input_registers[INLET_PRESSURE] = (
                int(0.7 * speed) if s.coils[PUMP_RUN] else 0)
            s.input_registers[FLOW_RATE] = int(inflow * 10) if inflow else 0

            # PLC-side safety logic: raise alarm + LEVEL_OK flags
            s.coils[HIGH_ALARM] = level >= HIGH_LIMIT
            s.discrete_inputs[LEVEL_OK] = LOW_LIMIT <= level <= HIGH_LIMIT

    def level_percent(self):
        return self.store.input_registers[TANK_LEVEL] / 10.0
