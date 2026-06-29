"""
modbus_client.py
================
A minimal Modbus TCP master / client.  It is what a legitimate SCADA control
centre would use to poll and command the slave; the experiments also use it as
the honest baseline against which attacks are measured.
"""

from __future__ import annotations

import socket
import struct

import modbus_protocol as mb


class ModbusClient:
    def __init__(self, host="127.0.0.1", port=5020, unit_id=1, timeout=3.0):
        self.host, self.port, self.unit_id, self.timeout = host, port, unit_id, timeout
        self._tid = 0
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *a):
        self.close()

    def _next_tid(self):
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def _transact(self, pdu: bytes) -> bytes:
        tid = self._next_tid()
        self.sock.sendall(mb.build_adu(tid, self.unit_id, pdu))
        frame = mb.recv_frame(self.sock, timeout=self.timeout)
        if not frame:
            raise ConnectionError("no response (connection closed)")
        _, resp_pdu = mb.parse_adu(frame)
        return resp_pdu

    # ---------------------------------------------------------------- reads
    def read_holding_registers(self, address, count):
        pdu = mb.pdu_read(mb.READ_HOLDING_REGISTERS, address, count)
        return mb.parse_read_registers_response(self._transact(pdu))

    def read_input_registers(self, address, count):
        pdu = mb.pdu_read(mb.READ_INPUT_REGISTERS, address, count)
        return mb.parse_read_registers_response(self._transact(pdu))

    def read_coils(self, address, count):
        pdu = mb.pdu_read(mb.READ_COILS, address, count)
        return mb.parse_read_bits_response(self._transact(pdu), count)

    def read_discrete_inputs(self, address, count):
        pdu = mb.pdu_read(mb.READ_DISCRETE_INPUTS, address, count)
        return mb.parse_read_bits_response(self._transact(pdu), count)

    # ---------------------------------------------------------------- writes
    def write_coil(self, address, on):
        return self._transact(mb.pdu_write_single_coil(address, on))

    def write_register(self, address, value):
        return self._transact(mb.pdu_write_single_register(address, value))

    def write_registers(self, address, values):
        return self._transact(mb.pdu_write_multiple_registers(address, values))

    # ---------------------------------------------------------------- diagnostics
    def report_server_id(self):
        pdu = self._transact(mb.pdu_report_server_id())
        length = pdu[1]
        return pdu[3:3 + length - 1].decode(errors="replace")

    def diagnostic(self, sub_function, data=0x0000):
        return self._transact(mb.pdu_diagnostic(sub_function, data))
