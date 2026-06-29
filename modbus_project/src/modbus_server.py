"""
modbus_server.py
================
A real (localhost) Modbus TCP slave / server, written from the spec.  It is a
faithful enough target that all of the paper's protocol-level attacks work
against it exactly as the taxonomy predicts:

  * no authentication / no authorisation on any function code   (enables B4)
  * unit-id 0 broadcast writes are accepted with no response    (enables B1)
  * FC 08 diagnostics can restart comms / clear counters        (enables S4/S1)
  * a bounded TCP connection pool that can be exhausted         (enables T10)
  * cleartext framing that can be sniffed / replayed            (enables B9/B2)

The server keeps a small datastore, a diagnostic counter block, and a
background thread that advances the TankProcess physics.
"""

from __future__ import annotations

import socket
import threading
import time

import modbus_protocol as mb
from process_model import TankProcess


class DataStore:
    def __init__(self, n=64):
        self.coils = [False] * n
        self.discrete_inputs = [False] * n
        self.holding_registers = [0] * n
        self.input_registers = [0] * n


class ModbusServer:
    def __init__(self, host="127.0.0.1", port=5020, unit_id=1,
                 max_connections=8, server_id="TULSA-RTU-1", on_event=None):
        self.host, self.port, self.unit_id = host, port, unit_id
        self.max_connections = max_connections          # the TCP "connection pool"
        self.server_id = server_id
        self.store = DataStore()
        self.process = TankProcess(self.store)
        self.on_event = on_event or (lambda *a, **k: None)

        # diagnostic counters (FC08) — the assets attack S1 clears
        self.counters = {"bus_messages": 0, "bus_errors": 0, "exceptions": 0,
                         "slave_messages": 0}
        self.online = True            # set False by Remote Restart (S4)
        self._restart_until = 0.0

        self._sock = None
        self._stop = threading.Event()
        self._conns = []
        self._conn_lock = threading.Lock()
        self.rejected_connections = 0
        self.peak_connections = 0

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self._sock.settimeout(0.2)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._physics_loop, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _physics_loop(self):
        while not self._stop.is_set():
            if self.online:
                self.process.step()
            time.sleep(self.process.dt)

    # ------------------------------------------------------------------ accept
    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._conn_lock:
                active = len(self._conns)
                # Bounded connection pool (Modbus TCP impl. guide): refuse when full.
                if active >= self.max_connections:
                    self.rejected_connections += 1
                    conn.close()
                    continue
                self._conns.append(conn)
                self.peak_connections = max(self.peak_connections, len(self._conns))
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn, addr):
        try:
            while not self._stop.is_set():
                try:
                    frame = mb.recv_frame(conn, timeout=30)
                except (ValueError, OSError):
                    self.counters["bus_errors"] += 1
                    break
                if not frame:
                    break
                resp = self._handle_frame(frame)
                if resp is not None:
                    conn.sendall(resp)
        finally:
            with self._conn_lock:
                if conn in self._conns:
                    self._conns.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def active_connections(self):
        with self._conn_lock:
            return len(self._conns)

    # ------------------------------------------------------------------ dispatch
    def _handle_frame(self, frame: bytes):
        self.counters["bus_messages"] += 1
        try:
            mbap, pdu = mb.parse_adu(frame)
        except ValueError:
            # Irregular framing (paper attack T5): drop / count as bus error
            self.counters["bus_errors"] += 1
            return None

        # honour a pending Remote Restart (S4): device is "powering up"
        if self._restart_until and time.time() < self._restart_until:
            return None
        self._restart_until = 0.0

        broadcast = (mbap.unit_id == 0)
        self.counters["slave_messages"] += 1
        function = pdu[0]
        try:
            resp_pdu = self._dispatch(function, pdu)
        except _Exc as e:
            self.counters["exceptions"] += 1
            resp_pdu = mb.pdu_exception(function, e.code)

        if broadcast:
            return None          # broadcast: action taken, no reply (enables B1)
        return mb.build_adu(mbap.transaction_id, mbap.unit_id, resp_pdu,
                            mbap.protocol_id)

    def _dispatch(self, function, pdu):
        import struct
        s = self.store
        if function in (mb.READ_COILS, mb.READ_DISCRETE_INPUTS):
            _, addr, count = struct.unpack(">BHH", pdu[:5])
            src = s.coils if function == mb.READ_COILS else s.discrete_inputs
            self._check(addr, count, len(src))
            bits = src[addr:addr + count]
            nbytes = (count + 7) // 8
            raw = bytearray(nbytes)
            for i, b in enumerate(bits):
                if b:
                    raw[i // 8] |= (1 << (i % 8))
            return struct.pack(">BB", function, nbytes) + bytes(raw)

        if function in (mb.READ_HOLDING_REGISTERS, mb.READ_INPUT_REGISTERS):
            _, addr, count = struct.unpack(">BHH", pdu[:5])
            src = (s.holding_registers if function == mb.READ_HOLDING_REGISTERS
                   else s.input_registers)
            self._check(addr, count, len(src))
            regs = src[addr:addr + count]
            return (struct.pack(">BB", function, count * 2)
                    + b"".join(struct.pack(">H", r) for r in regs))

        if function == mb.WRITE_SINGLE_COIL:
            _, addr, value = struct.unpack(">BHH", pdu[:5])
            self._check(addr, 1, len(s.coils))
            s.coils[addr] = (value == 0xFF00)
            self.on_event("write_coil", addr=addr, value=s.coils[addr])
            return pdu[:5]

        if function == mb.WRITE_SINGLE_REGISTER:
            _, addr, value = struct.unpack(">BHH", pdu[:5])
            self._check(addr, 1, len(s.holding_registers))
            s.holding_registers[addr] = value
            self.on_event("write_register", addr=addr, value=value)
            return pdu[:5]

        if function == mb.WRITE_MULTIPLE_REGS:
            _, addr, count, _bc = struct.unpack(">BHHB", pdu[:6])
            self._check(addr, count, len(s.holding_registers))
            vals = struct.unpack(">" + "H" * count, pdu[6:6 + count * 2])
            s.holding_registers[addr:addr + count] = list(vals)
            return struct.pack(">BHH", function, addr, count)

        if function == mb.DIAGNOSTICS:
            _, sub, data = struct.unpack(">BHH", pdu[:5])
            if sub == mb.DIAG_RESTART_COMM:                  # S4 Remote Restart
                self._restart_until = time.time() + 2.0
                self.online = True
                self.on_event("diag_restart")
                return pdu[:5]
            if sub == mb.DIAG_CLEAR_COUNTERS:                # S1 Diagnostic Reset
                for k in self.counters:
                    self.counters[k] = 0
                self.on_event("diag_clear")
                return pdu[:5]
            return pdu[:5]                                    # echo (return query)

        if function == mb.REPORT_SERVER_ID:                  # S5 Slave Reconnaissance
            ident = self.server_id.encode()
            body = struct.pack(">BBB", function, len(ident) + 1, 0xFF) + ident
            return body

        raise _Exc(mb.EXC_ILLEGAL_FUNCTION)

    def _check(self, addr, count, n):
        if addr < 0 or count < 1 or addr + count > n:
            raise _Exc(mb.EXC_ILLEGAL_DATA_ADDRESS)


class _Exc(Exception):
    def __init__(self, code):
        self.code = code
