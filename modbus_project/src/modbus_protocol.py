"""
modbus_protocol.py
==================
A small, self-contained implementation of the Modbus TCP wire format used by
the reproduction.  It encodes/decodes the MBAP header and the application PDU
for the function codes we exercise, and provides exception responses.

This is deliberately written from the specification (MODBUS Application
Protocol v1.1b and the Messaging on TCP/IP Implementation Guide) rather than a
library, so that the attack toolkit can also build *malformed* and *spoofed*
frames that a normal client library would refuse to produce.

Modbus TCP frame layout
-----------------------
    +-----------------------------------------------+-------------------+
    |                MBAP header (7 bytes)          |     PDU           |
    | transId(2) | protoId(2) | length(2) | unit(1) | func(1) | data... |
    +-----------------------------------------------+-------------------+

The length field counts the unit-id byte plus the PDU.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# ----------------------------------------------------------------- function codes
READ_COILS              = 0x01
READ_DISCRETE_INPUTS    = 0x02
READ_HOLDING_REGISTERS  = 0x03
READ_INPUT_REGISTERS    = 0x04
WRITE_SINGLE_COIL       = 0x05
WRITE_SINGLE_REGISTER   = 0x06
WRITE_MULTIPLE_COILS    = 0x0F
WRITE_MULTIPLE_REGS     = 0x10
DIAGNOSTICS             = 0x08
REPORT_SERVER_ID        = 0x11

FUNCTION_NAMES = {
    0x01: "Read Coils", 0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers", 0x04: "Read Input Registers",
    0x05: "Write Single Coil", 0x06: "Write Single Register",
    0x0F: "Write Multiple Coils", 0x10: "Write Multiple Registers",
    0x08: "Diagnostics", 0x11: "Report Server ID",
}

# Diagnostic sub-function codes (FC 08) used by the paper's S1 / S4 attacks
DIAG_RETURN_QUERY   = 0x0000   # echo
DIAG_RESTART_COMM   = 0x0001   # Remote Restart  (paper attack S4)
DIAG_CLEAR_COUNTERS = 0x000A   # Diagnostic Register Reset (paper attack S1)

# ----------------------------------------------------------------- exceptions
EXC_ILLEGAL_FUNCTION       = 0x01
EXC_ILLEGAL_DATA_ADDRESS   = 0x02
EXC_ILLEGAL_DATA_VALUE     = 0x03
EXC_SERVER_DEVICE_FAILURE  = 0x04

EXCEPTION_NAMES = {
    0x01: "Illegal Function", 0x02: "Illegal Data Address",
    0x03: "Illegal Data Value", 0x04: "Server Device Failure",
}

PROTOCOL_ID = 0x0000


@dataclass
class MBAP:
    transaction_id: int
    protocol_id: int
    unit_id: int


def build_adu(transaction_id: int, unit_id: int, pdu: bytes,
              protocol_id: int = PROTOCOL_ID) -> bytes:
    """Wrap a PDU in an MBAP header to form a complete Modbus TCP frame (ADU)."""
    length = len(pdu) + 1                       # unit id + PDU
    header = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    return header + pdu


def parse_adu(frame: bytes):
    """Return (MBAP, pdu).  Raises ValueError on a structurally broken frame."""
    if len(frame) < 8:
        raise ValueError("frame shorter than MBAP+function")
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
    pdu = frame[7:]
    if length - 1 != len(pdu):
        # length field disagrees with the actual payload (e.g. Irregular Framing)
        raise ValueError(f"length mismatch: header says {length-1}, got {len(pdu)}")
    return MBAP(transaction_id, protocol_id, unit_id), pdu


def recv_frame(sock, timeout=None) -> bytes:
    """Read exactly one Modbus TCP frame from a stream socket using the MBAP
    length field.  Returns b'' if the peer closed the connection."""
    if timeout is not None:
        sock.settimeout(timeout)
    head = _recv_n(sock, 7)
    if not head:
        return b""
    _, _, length, _ = struct.unpack(">HHHB", head)
    body = _recv_n(sock, length - 1)
    return head + body


def _recv_n(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""           # connection closed
        buf += chunk
    return buf


# ------------------------------------------------------------- request PDUs
def pdu_read(function: int, address: int, count: int) -> bytes:
    return struct.pack(">BHH", function, address, count)


def pdu_write_single_coil(address: int, on: bool) -> bytes:
    return struct.pack(">BHH", WRITE_SINGLE_COIL, address, 0xFF00 if on else 0x0000)


def pdu_write_single_register(address: int, value: int) -> bytes:
    return struct.pack(">BHH", WRITE_SINGLE_REGISTER, address, value & 0xFFFF)


def pdu_write_multiple_registers(address: int, values) -> bytes:
    body = struct.pack(">BHHB", WRITE_MULTIPLE_REGS, address, len(values), len(values) * 2)
    body += b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    return body


def pdu_diagnostic(sub_function: int, data: int = 0x0000) -> bytes:
    return struct.pack(">BHH", DIAGNOSTICS, sub_function, data)


def pdu_report_server_id() -> bytes:
    return struct.pack(">B", REPORT_SERVER_ID)


def pdu_exception(function: int, code: int) -> bytes:
    return struct.pack(">BB", function | 0x80, code)


# ------------------------------------------------------------- response parsing
def parse_read_registers_response(pdu: bytes):
    """Decode a Read Holding/Input Registers response PDU -> list[int]."""
    function = pdu[0]
    if function & 0x80:
        raise ModbusException(function & 0x7F, pdu[1])
    byte_count = pdu[1]
    values = list(struct.unpack(">" + "H" * (byte_count // 2), pdu[2:2 + byte_count]))
    return values


def parse_read_bits_response(pdu: bytes, count: int):
    """Decode a Read Coils/Discrete Inputs response PDU -> list[bool]."""
    function = pdu[0]
    if function & 0x80:
        raise ModbusException(function & 0x7F, pdu[1])
    byte_count = pdu[1]
    raw = pdu[2:2 + byte_count]
    bits = []
    for i in range(count):
        bits.append(bool((raw[i // 8] >> (i % 8)) & 1))
    return bits


class ModbusException(Exception):
    def __init__(self, function, code):
        self.function = function
        self.code = code
        super().__init__(f"Modbus exception on FC {function}: "
                         f"{EXCEPTION_NAMES.get(code, code)}")


def hexdump(frame: bytes) -> str:
    return " ".join(f"{b:02X}" for b in frame)
