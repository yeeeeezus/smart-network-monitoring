#!/usr/bin/env python3
"""
snmp_lite.py — A dependency-free SNMPv2c implementation (client + agent helpers).

Implements the protocol stack a network-monitoring engineer should know:
  * BER/ASN.1 encoding (the wire format of every SNMP message)
  * GET / GETNEXT request + response PDUs
  * SNMPv2c Trap PDUs (sent by agents, received by the manager)
  * Standard exceptions: noSuchObject (0x80), noSuchInstance (0x81),
    endOfMibView (0x82)

Zero third-party dependencies: Python standard library only.

Wire format of an SNMPv2c message (RFC 3416):

  Message ::= SEQUENCE {
      version   INTEGER (1 = v2c),
      community OCTET STRING,
      data      PDU
  }
  PDU ::= [context tag] SEQUENCE {
      request-id   INTEGER,
      error-status INTEGER,
      error-index  INTEGER,
      var-bind-list SEQUENCE OF VarBind
  }
  VarBind ::= SEQUENCE { name OBJECT IDENTIFIER, value ANY }
"""

import socket
import time

# ---------------------------------------------------------------- BER / TLV

TAG_INTEGER = 0x02
TAG_OCTET = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQ = 0x30
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_COUNTER64 = 0x46

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_TRAPV2 = 0xA7

EXC_NOSUCHOBJECT = 0x80
EXC_NOSUCHINSTANCE = 0x81
EXC_ENDOFMIBVIEW = 0x82

SNMPV2C = 1


def enc_len(n: int) -> bytes:
    """BER length: short form < 128, else long form 0x81/0x82..."""
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(payload)) + payload


def enc_int(n: int) -> bytes:
    """Two's-complement, minimal-length INTEGER."""
    if n == 0:
        return tlv(TAG_INTEGER, b"\x00")
    if n > 0:
        length = (n.bit_length() + 8) // 8
        payload = n.to_bytes(length, "big")
    else:
        length = 1
        while n < -(1 << (8 * length - 1)):
            length += 1
        payload = n.to_bytes(length, "big", signed=True)
    return tlv(TAG_INTEGER, payload)


def enc_uint(tag: int, n: int) -> bytes:
    """Unsigned application types: Counter32/Gauge32/TimeTicks."""
    if n == 0:
        return tlv(tag, b"\x00")
    payload = []
    while n:
        payload.insert(0, n & 0xFF)
        n >>= 8
    if payload[0] & 0x80:
        payload.insert(0, 0)
    return tlv(tag, bytes(payload))


def enc_str(s: str) -> bytes:
    return tlv(TAG_OCTET, s.encode("utf-8"))


def enc_oid(dotted: str) -> bytes:
    """OBJECT IDENTIFIER: first two arcs packed as 40*a+b, rest base-128."""
    parts = [int(p) for p in dotted.strip(".").split(".")]
    payload = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            payload.append(0)
            continue
        stack = []
        while p:
            stack.insert(0, p & 0x7F)
            p >>= 7
        for i in range(1, len(stack)):
            stack[i] |= 0x80  # continuation bit on all but final byte
        payload.extend(stack)
    return tlv(TAG_OID, bytes(payload))


# ---------------------------------------------------------------- decoding

class BERError(ValueError):
    pass


def _read_tlv(data: bytes, pos: int):
    """Return (tag, value_bytes, next_pos)."""
    if pos >= len(data):
        raise BERError("truncated TLV")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise BERError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or pos + n > len(data):
            raise BERError("bad long-form length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise BERError("value overruns buffer")
    return tag, data[pos:pos + length], pos + length


def dec_int(payload: bytes) -> int:
    if not payload:
        raise BERError("empty integer")
    if payload[0] & 0x80:  # negative: sign-extend
        val = int.from_bytes(payload, "big")
        return val - (1 << (len(payload) * 8))
    return int.from_bytes(payload, "big")


def dec_oid(payload: bytes) -> str:
    if not payload:
        raise BERError("empty OID")
    arcs = [payload[0] // 40, payload[0] % 40]
    val = 0
    for b in payload[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(val)
            val = 0
    if payload[-1] & 0x80:
        raise BERError("truncated OID sub-identifier")
    return ".".join(str(a) for a in arcs)


def dec_str(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- messages

def _varbind_raw(oid: str, encoded_value: bytes) -> bytes:
    return tlv(TAG_SEQ, enc_oid(oid) + encoded_value)


def _pdu(ptype: int, req_id: int, varbinds: bytes, err: int = 0, erridx: int = 0) -> bytes:
    return tlv(ptype, enc_int(req_id) + enc_int(err) + enc_int(erridx) + tlv(TAG_SEQ, varbinds))


def _message(community: str, pdu_bytes: bytes) -> bytes:
    return tlv(TAG_SEQ, enc_int(SNMPV2C) + enc_str(community) + pdu_bytes)


def build_get(community: str, req_id: int, oids) -> bytes:
    vb = b"".join(_varbind_raw(o, tlv(TAG_NULL, b"")) for o in oids)
    return _message(community, _pdu(PDU_GET, req_id, vb))


def build_getnext(community: str, req_id: int, oids) -> bytes:
    vb = b"".join(_varbind_raw(o, tlv(TAG_NULL, b"")) for o in oids)
    return _message(community, _pdu(PDU_GETNEXT, req_id, vb))


def build_response(community: str, req_id: int, varbinds, err: int = 0, erridx: int = 0) -> bytes:
    """varbinds: list of (oid, encoded_value_tlv_bytes)."""
    vb = b"".join(_varbind_raw(o, v) for o, v in varbinds)
    return _message(community, _pdu(PDU_RESPONSE, req_id, vb, err, erridx))


def build_trap(community: str, varbinds) -> bytes:
    """SNMPv2c Trap-PDU. varbinds: list of (oid, encoded_value_tlv_bytes)."""
    req_id = int(time.time()) & 0x7FFFFFFF
    vb = b"".join(_varbind_raw(o, v) for o, v in varbinds)
    return _message(community, _pdu(PDU_TRAPV2, req_id, vb))


class VarBind:
    __slots__ = ("oid", "tag", "value")

    def __init__(self, oid, tag, value):
        self.oid, self.tag, self.value = oid, tag, value

    def __repr__(self):
        tagnames = {TAG_INTEGER: "Integer", TAG_OCTET: "String", TAG_NULL: "Null",
                    TAG_OID: "OID", TAG_COUNTER32: "Counter32", TAG_GAUGE32: "Gauge32",
                    TAG_TIMETICKS: "TimeTicks", EXC_NOSUCHOBJECT: "noSuchObject",
                    EXC_NOSUCHINSTANCE: "noSuchInstance", EXC_ENDOFMIBVIEW: "endOfMibView"}
        return f"<VarBind {self.oid} {tagnames.get(self.tag, hex(self.tag))}: {self.value!r}>"


def parse_message(data: bytes):
    """Parse an SNMP message -> dict(community, pdu_type, req_id, error_status,
    error_index, varbinds: list[VarBind])."""
    tag, body, pos = _read_tlv(data, 0)
    if tag != TAG_SEQ:
        raise BERError("outer SEQUENCE expected")
    tag, ver, pos = _read_tlv(body, 0)
    if tag != TAG_INTEGER:
        raise BERError("version INTEGER expected")
    if dec_int(ver) != SNMPV2C:
        raise BERError("only SNMPv2c is supported")
    tag, comm, pos = _read_tlv(body, pos)
    if tag != TAG_OCTET:
        raise BERError("community OCTET STRING expected")
    community = dec_str(comm)
    ptag, pbody, _ = _read_tlv(body, pos)   # PDU: tag A0/A1/A2/A7 + content
    tag, rid, pos = _read_tlv(pbody, 0)
    req_id = dec_int(rid)
    tag, es, pos = _read_tlv(pbody, pos)
    error_status = dec_int(es)
    tag, ei, pos = _read_tlv(pbody, pos)
    error_index = dec_int(ei)
    tag, vbl, _ = _read_tlv(pbody, pos)
    varbinds = []
    i = 0
    while i < len(vbl):
        tag, vb, i = _read_tlv(vbl, i)
        t2, oidb, j = _read_tlv(vb, 0)
        oid = dec_oid(oidb)
        t3, valb, _ = _read_tlv(vb, j)
        if t3 == TAG_INTEGER:
            value = dec_int(valb)
        elif t3 in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS):
            value = int.from_bytes(valb, "big")
        elif t3 == TAG_OCTET:
            value = dec_str(valb)
        elif t3 == TAG_OID:
            value = dec_oid(valb)
        else:  # TAG_NULL and SNMPv2 exceptions carry empty payloads
            value = None
        varbinds.append(VarBind(oid, t3, value))
    return {"community": community, "pdu_type": ptag, "req_id": req_id,
            "error_status": error_status, "error_index": error_index,
            "varbinds": varbinds}


# ---------------------------------------------------------------- client API

class SnmpClient:
    """Blocking SNMPv2c client with timeout support."""

    def __init__(self, host: str, port: int, community: str = "public", timeout: float = 2.0):
        self.addr = (host, port)
        self.community = community
        self.timeout = timeout
        self._req_id = int(time.time() * 1000) & 0x7FFFFF

    def _transact(self, packet: bytes) -> dict:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, self.addr)
            data, _ = s.recvfrom(65535)
        msg = parse_message(data)
        if msg["community"] != self.community:
            raise BERError("community mismatch in response")
        return msg

    def get(self, oids):
        """GET one or more OIDs -> list[VarBind]."""
        self._req_id += 1
        msg = self._transact(build_get(self.community, self._req_id, oids))
        if msg["error_status"]:
            raise BERError(f"error-status={msg['error_status']} index={msg['error_index']}")
        return msg["varbinds"]

    def getnext(self, oid: str):
        """GETNEXT a single OID -> VarBind."""
        self._req_id += 1
        msg = self._transact(build_getnext(self.community, self._req_id, [oid]))
        return msg["varbinds"][0]

    def walk(self, root: str, max_reps: int = 64):
        """Lexicographic walk of a subtree -> list[VarBind]."""
        out, cur = [], root
        for _ in range(max_reps):
            vb = self.getnext(cur)
            if vb.tag == EXC_ENDOFMIBVIEW or not vb.oid.startswith(root + "."):
                break
            out.append(vb)
            cur = vb.oid
        return out


# ---------------------------------------------------------------- self-test

if __name__ == "__main__":
    assert dec_oid(enc_oid("1.3.6.1.2.1.1.3.0")[2:]) == "1.3.6.1.2.1.1.3.0"
    assert enc_oid("1.3.6.1.2.1.1.3.0")[:2] == b"\x06\x08", "OID DER header"
    assert dec_int(enc_int(0)[2:]) == 0
    for n in (1, 127, 128, 255, 256, 32767, -1, -128, -129):
        assert dec_int(enc_int(n)[2:]) == n, f"int roundtrip {n}"
    for n in (0, 42, 100000, 2**31 - 1):
        for tag in (TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER32):
            assert int.from_bytes(enc_uint(tag, n)[2:], "big") == n
    assert dec_str(enc_str("MonNet-RO")[2:]) == "MonNet-RO"

    pkt = build_get("MonNet-RO", 7, ["1.3.6.1.4.1.9.9.109.1.1.1.1.8.1"])
    msg = parse_message(pkt)
    assert msg["community"] == "MonNet-RO" and msg["req_id"] == 7
    assert msg["varbinds"][0].oid == "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1"

    resp = build_response("MonNet-RO", 7, [("1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", enc_uint(TAG_GAUGE32, 37))])
    m2 = parse_message(resp)
    assert m2["varbinds"][0].value == 37 and m2["varbinds"][0].tag == TAG_GAUGE32

    trap = build_trap("MonNet-RO", [
        ("1.3.6.1.2.1.1.3.0", enc_uint(TAG_TIMETICKS, 12345)),
        ("1.3.6.1.6.3.1.1.4.1.0", enc_oid("1.3.6.1.6.3.1.1.5.3")),
    ])
    m3 = parse_message(trap)
    assert m3["pdu_type"] == PDU_TRAPV2
    assert m3["varbinds"][1].value == "1.3.6.1.6.3.1.1.5.3"

    print("snmp_lite self-test: ALL PASS")
    print("sample GET bytes:", pkt.hex())
