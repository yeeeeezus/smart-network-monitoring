#!/usr/bin/env python3
"""
agent_sim.py — Simulated Cisco IOS SNMP agents for the graduation project.

Packet Tracer is a *simulator*: its devices are configured with SNMP but are
not reachable over real UDP/161 from the outside. This module provides the
live data plane: one SNMPv2c agent per lab device, exposing exactly the OIDs
a real Cisco router/switch would expose (cpu, memory pool, ifTable, sys
group), with realistic dynamic behaviour:

  * CPU  : random walk around a per-device baseline
  * MEM  : slow drift
  * ifTable : operStatus flips, octet counters grow with traffic
  * sysUpTime : real ticks since agent start
  * TRAPS: linkDown / linkUp / coldStart sent to the manager (default
           udp/1620) using genuine SNMPv2c Trap-PDUs

The poller (monitor.py) talks to these agents with the very same GET /
GETNEXT / trap-receive code it would use against production Cisco gear —
only the IP endpoints differ.

Usage:
    python3 agent_sim.py                # run all agents with demo scenario
    python3 agent_sim.py --no-scenario  # healthy network only
    python3 agent_sim.py --list         # print the simulated MIB
"""

import argparse
import random
import socket
import threading
import time

from snmp_lite import (build_response, build_trap, enc_int, enc_oid, enc_str,
                       enc_uint, parse_message, PDU_GET, PDU_GETNEXT,
                       TAG_GAUGE32, TAG_INTEGER, TAG_OCTET, TAG_OID,
                       TAG_TIMETICKS, TAG_COUNTER32, EXC_ENDOFMIBVIEW,
                       tlv)

# ---------------------------------------------------------------- Cisco OIDs

O = {
    "sysDescr":     "1.3.6.1.2.1.1.1.0",
    "sysObjectID":  "1.3.6.1.2.1.1.2.0",
    "sysUpTime":    "1.3.6.1.2.1.1.3.0",
    "sysContact":   "1.3.6.1.2.1.1.4.0",
    "sysName":      "1.3.6.1.2.1.1.5.0",
    "sysLocation":  "1.3.6.1.2.1.1.6.0",
    "ifIndex":      "1.3.6.1.2.1.2.2.1.1",
    "ifDescr":      "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets":   "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets":  "1.3.6.1.2.1.2.2.1.16",
    "cpu5min":      "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
    "memPoolUsed":  "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
    "memPoolFree":  "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    "snmpTrapOID":  "1.3.6.1.6.3.1.1.4.1.0",
}

TRAP_LINKDOWN = "1.3.6.1.6.3.1.1.5.3"
TRAP_LINKUP = "1.3.6.1.6.3.1.1.5.4"
TRAP_COLDSTART = "1.3.6.1.6.3.1.1.5.1"

IOS_DESCR = ("Cisco IOS Software, C2911 Software (C2911-UNIVERSALK9-M), "
             "Version 15.1(4)M4, RELEASE SOFTWARE (fc1)\n"
             "Technical Support: http://www.cisco.com/techsupport\n"
             "Compiled by prod_rel_team")
SWITCH_DESCR = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
                "Version 15.0(2)SE4, RELEASE SOFTWARE (fc1)\n"
                "Compiled by prod_rel_team")

# ---------------------------------------------------------------- device defs

DEVICES = [
    {"name": "R1-Core",   "port": 1161, "kind": "router", "location": "CORE-POP Damascus",
     "descr": IOS_DESCR, "cpu_base": 22, "mem_total": 524288,
     "ifaces": [("GigabitEthernet0/0", 1), ("GigabitEthernet0/1", 2), ("GigabitEthernet0/2", 3)]},
    {"name": "R2-Branch", "port": 1162, "kind": "router", "location": "BRANCH Aleppo",
     "descr": IOS_DESCR, "cpu_base": 15, "mem_total": 524288,
     "ifaces": [("GigabitEthernet0/0", 1), ("GigabitEthernet0/1", 2), ("GigabitEthernet0/2", 3)]},
    {"name": "R3-HQ",     "port": 1163, "kind": "router", "location": "HQ Damascus Building-A",
     "descr": IOS_DESCR, "cpu_base": 18, "mem_total": 524288,
     "ifaces": [("GigabitEthernet0/0", 1), ("GigabitEthernet0/0.10", 2),
                ("GigabitEthernet0/0.20", 3), ("GigabitEthernet0/1", 4), ("GigabitEthernet0/2", 5)]},
    {"name": "R4-ISP",    "port": 1164, "kind": "router", "location": "ISP-POP Damascus",
     "descr": IOS_DESCR, "cpu_base": 31, "mem_total": 262144,
     "ifaces": [("GigabitEthernet0/0", 1), ("Loopback0", 2)]},
    {"name": "SW-HQ",     "port": 1165, "kind": "switch", "location": "HQ-Closet-A Damascus",
     "descr": SWITCH_DESCR, "cpu_base": 9, "mem_total": 131072,
     "ifaces": [("FastEthernet0/1", 1), ("FastEthernet0/2", 2), ("FastEthernet0/3", 3),
                ("FastEthernet0/4", 4), ("FastEthernet0/5", 5), ("Vlan20", 20)]},
    {"name": "SW-Branch", "port": 1166, "kind": "switch", "location": "BRANCH-Closet Aleppo",
     "descr": SWITCH_DESCR, "cpu_base": 6, "mem_total": 131072,
     "ifaces": [("FastEthernet0/1", 1), ("FastEthernet0/2", 2), ("FastEthernet0/3", 3), ("Vlan1", 1)]},
]

COMMUNITY = "MonNet-RO"
MANAGER_ADDR = ("127.0.0.1", 1620)


# ---------------------------------------------------------------- agent

class SimAgent(threading.Thread):
    """One simulated Cisco device: UDP responder + dynamic MIB + traps."""

    def __init__(self, spec, scenario_events):
        super().__init__(daemon=True, name=f"agent-{spec['name']}")
        self.spec = spec
        self.name = spec["name"]
        self.start_time = time.time()
        self.events = scenario_events          # list of ScenarioEvent
        self.cpu = float(spec["cpu_base"])
        self.cpu_target = None
        self.cpu_target_until = 0.0
        self.mem_used = int(spec["mem_total"] * 0.45)
        self.ifaces = {}                       # ifIndex -> state dict
        for descr, idx in spec["ifaces"]:
            self.ifaces[idx] = {"descr": descr, "oper": 1,
                                "in": random.randrange(1_000_000, 5_000_000),
                                "out": random.randrange(1_000_000, 5_000_000),
                                "in_rate": random.randrange(2_000, 30_000),
                                "out_rate": random.randrange(2_000, 30_000)}
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", spec["port"]))
        self.sock.settimeout(0.5)
        self._boot_traps_sent = False

    # ---------------- MIB ----------------
    def uptime_ticks(self):
        return int((time.time() - self.start_time) * 100)

    def _mib_snapshot(self):
        """OID -> (tag, value) for the whole simulated MIB."""
        s = self.spec
        mib = {
            O["sysDescr"]: (TAG_OCTET, s["descr"]),
            O["sysObjectID"]: (TAG_OID, "1.3.6.1.4.1.9.1.1270" if s["kind"] == "router" else "1.3.6.1.4.1.9.1.696"),
            O["sysUpTime"]: (TAG_TIMETICKS, self.uptime_ticks()),
            O["sysContact"]: (TAG_OCTET, "netmon@monnet.lab"),
            O["sysName"]: (TAG_OCTET, s["name"]),
            O["sysLocation"]: (TAG_OCTET, s["location"]),
            O["cpu5min"]: (TAG_GAUGE32, int(self.cpu)),
            O["memPoolUsed"]: (TAG_GAUGE32, self.mem_used),
            O["memPoolFree"]: (TAG_GAUGE32, s["mem_total"] - self.mem_used),
        }
        for idx, st in self.ifaces.items():
            mib[f'{O["ifIndex"]}.{idx}'] = (TAG_INTEGER, idx)
            mib[f'{O["ifDescr"]}.{idx}'] = (TAG_OCTET, st["descr"])
            mib[f'{O["ifOperStatus"]}.{idx}'] = (TAG_INTEGER, st["oper"])
            mib[f'{O["ifInOctets"]}.{idx}'] = (TAG_COUNTER32, st["in"])
            mib[f'{O["ifOutOctets"]}.{idx}'] = (TAG_COUNTER32, st["out"])
        return mib

    # ---------------- dynamics ----------------
    def tick(self, elapsed):
        """Advance simulated physics for one second."""
        now = time.time() - self.start_time
        with self.lock:
            target = self.cpu_target if now < self.cpu_target_until else self.spec["cpu_base"]
            self.cpu += random.uniform(-3, 3)
            self.cpu = max(1, min(99, self.cpu))
            # mean reversion toward the *current* target (baseline or incident)
            self.cpu += (target - self.cpu) * 0.12
            # memory slow walk
            self.mem_used += int(random.uniform(-400, 700))
            self.mem_used = max(1000, min(self.spec["mem_total"] - 1000, self.mem_used))
            for st in self.ifaces.values():
                if st["oper"] == 1:
                    st["in"] = (st["in"] + st["in_rate"] + random.randrange(-800, 800)) % (2**32)
                    st["out"] = (st["out"] + st["out_rate"] + random.randrange(-800, 800)) % (2**32)

    # ---------------- scenarios ----------------
    def apply_event(self, ev):
        with self.lock:
            now = time.time() - self.start_time
            if ev.kind == "cpu":
                self.cpu_target = ev.value
                self.cpu_target_until = now + ev.hold
                self.cpu = ev.value          # spike lands immediately
            elif ev.kind == "cpu_cool":
                self.cpu_target = None
                self.cpu_target_until = 0.0
                self.cpu = min(self.cpu, self.spec["cpu_base"] + 12)
            elif ev.kind == "mem":
                self.mem_used = int(self.spec["mem_total"] * ev.value / 100.0)
            elif ev.kind == "link":
                st = self.ifaces[ev.ifindex]
                st["oper"] = 1 if ev.value == "up" else 2
            elif ev.kind == "traffic":
                st = self.ifaces[ev.ifindex]
                st["in_rate"] = ev.value
                st["out_rate"] = int(ev.value * 0.7)

    def send_trap(self, trap_oid, extra_varbinds):
        """Send via the agent's bound socket so the manager can map the
        source port back to this device (same idea as real agents sending
        from their well-known port)."""
        vbs = [(O["sysUpTime"], enc_uint(TAG_TIMETICKS, self.uptime_ticks())),
               (O["snmpTrapOID"], enc_oid(trap_oid))] + extra_varbinds
        pkt = build_trap(COMMUNITY, vbs)
        try:
            self.sock.sendto(pkt, MANAGER_ADDR)
        except OSError:
            pass

    def trap_link(self, ifindex, up):
        st = self.ifaces[ifindex]
        vbs = [(f'{O["ifIndex"]}.{ifindex}', enc_int(ifindex)),
               (f'{O["ifDescr"]}.{ifindex}', enc_str(st["descr"])),
               (f'{O["ifOperStatus"]}.{ifindex}', enc_int(1 if up else 2))]
        self.send_trap(TRAP_LINKUP if up else TRAP_LINKDOWN, vbs)

    def send_boot_trap(self):
        self.send_trap(TRAP_COLDSTART, [])

    # ---------------- UDP responder ----------------
    def run(self):
        while True:
            # handle scenario events whose time arrived
            now = time.time() - self.start_time
            for ev in self.events:
                if not ev.done and now >= ev.at:
                    ev.done = True
                    self.apply_event(ev)
                    if ev.kind == "link":
                        self.trap_link(ev.ifindex, ev.value == "up")
                    print(f"[agent_sim] {time.strftime('%H:%M:%S')} scenario on {self.name}: "
                          f"{ev.kind} {ev.detail}", flush=True)
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = parse_message(data)
                if msg["community"] != COMMUNITY:
                    continue
                if msg["pdu_type"] == PDU_GET:
                    self._on_get(msg, addr)
                elif msg["pdu_type"] == PDU_GETNEXT:
                    self._on_getnext(msg, addr)
            except Exception as e:  # malformed packet: drop silently
                print(f"[agent_sim] {self.name} dropped bad packet: {e}", flush=True)

    def _on_get(self, msg, addr):
        mib = self._mib_snapshot()
        out, err, erridx = [], 0, 0
        for i, vb in enumerate(msg["varbinds"], start=1):
            if vb.oid in mib:
                tag, val = mib[vb.oid]
                enc = {TAG_INTEGER: lambda v: enc_int(v),
                       TAG_GAUGE32: lambda v: enc_uint(TAG_GAUGE32, v),
                       TAG_TIMETICKS: lambda v: enc_uint(TAG_TIMETICKS, v),
                       TAG_COUNTER32: lambda v: enc_uint(TAG_COUNTER32, v),
                       TAG_OCTET: lambda v: enc_str(v),
                       TAG_OID: lambda v: enc_oid(v)}[tag](val)
                out.append((vb.oid, enc))
            else:
                err, erridx = 2, i  # noSuchName
                out.append((vb.oid, tlv(EXC_ENDOFMIBVIEW, b"")))
                break
        self.sock.sendto(build_response(COMMUNITY, msg["req_id"], out, err, erridx), addr)

    def _on_getnext(self, msg, addr):
        mib = self._mib_snapshot()
        keys = sorted(mib.keys(), key=lambda o: [int(p) for p in o.split(".")])
        out = []
        vb = msg["varbinds"][0]
        nxt = [k for k in keys if [int(p) for p in k.split(".")] > [int(p) for p in vb.oid.split(".")]]
        if nxt:
            k = nxt[0]
            tag, val = mib[k]
            enc = {TAG_INTEGER: lambda v: enc_int(v),
                   TAG_GAUGE32: lambda v: enc_uint(TAG_GAUGE32, v),
                   TAG_TIMETICKS: lambda v: enc_uint(TAG_TIMETICKS, v),
                   TAG_COUNTER32: lambda v: enc_uint(TAG_COUNTER32, v),
                   TAG_OCTET: lambda v: enc_str(v),
                   TAG_OID: lambda v: enc_oid(v)}[tag](val)
            out.append((k, enc))
        else:
            out.append((vb.oid, tlv(EXC_ENDOFMIBVIEW, b"")))
        self.sock.sendto(build_response(COMMUNITY, msg["req_id"], out), addr)


class ScenarioEvent:
    def __init__(self, at, kind, value=None, ifindex=None, hold=0, detail=""):
        self.at, self.kind, self.value, self.ifindex, self.detail = at, kind, value, ifindex, detail
        self.hold = hold          # seconds the target is sustained
        self.done = False


# ---------------------------------------------------------------- scenarios

def demo_scenario(scale: float = 1.0):
    """Timeline of realistic incidents (seconds after agent start).

    45s  R2-Branch CPU spikes (sustained)        -> WARNING then CRITICAL
    60s  R2-Branch CPU enters critical zone       -> CRITICAL alert
    80s  R3-HQ Gi0/0 goes down (linkDown trap)   -> immediate alert
    115s R1-Core memory pressure                 -> memory warning
    140s R3-HQ Gi0/0 recovers (linkUp trap)
    165s R2 CPU cools down                       -> recovery alert
    """
    def s(t):
        return t * scale

    return {
        "R2-Branch": [
            ScenarioEvent(s(45), "cpu", 78, hold=s(15), detail="cpu=78% sustained"),
            ScenarioEvent(s(60), "cpu", 93, hold=s(105), detail="cpu=93% sustained"),
            ScenarioEvent(s(165), "cpu_cool", detail="cooling to baseline"),
        ],
        "R3-HQ": [
            ScenarioEvent(s(80), "link", "down", ifindex=1, detail="Gi0/0 DOWN"),
            ScenarioEvent(s(140), "link", "up", ifindex=1, detail="Gi0/0 UP"),
        ],
        "R1-Core": [
            ScenarioEvent(s(115), "mem", 81, detail="memory pool 81%"),
        ],
    }


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-scenario", action="store_true", help="healthy network, no incidents")
    ap.add_argument("--scenario-speed", type=float, default=1.0,
                    help="time-scale factor for the scenario (0.5 = twice as fast)")
    ap.add_argument("--list", action="store_true", help="print simulated MIB of R1 and exit")
    args = ap.parse_args()

    if args.list:
        ag = SimAgent(DEVICES[0], [])
        for oid, (tag, val) in sorted(ag._mib_snapshot().items()):
            print(f"  {oid:<42} {val}")
        return

    scenario = {} if args.no_scenario else demo_scenario(args.scenario_speed)
    agents = []
    for spec in DEVICES:
        ag = SimAgent(spec, scenario.get(spec["name"], []))
        ag.start()
        agents.append(ag)
        print(f"[agent_sim] {spec['name']:<10} SNMPv2c agent on 127.0.0.1:{spec['port']} "
              f"({spec['kind']}, {len(spec['ifaces'])} interfaces)", flush=True)

    # dynamics ticker (always running — metrics must be live from t=0)
    def ticker():
        while True:
            time.sleep(1.0)
            for ag in agents:
                ag.tick(1)
    threading.Thread(target=ticker, daemon=True, name="sim-ticker").start()

    # coldStart traps ~10s after boot (gives the manager time to bind its
    # trap receiver — same "boot storms happen after NMS startup" reality)
    time.sleep(10.0)
    for ag in agents:
        ag.send_boot_trap()
    print("[agent_sim] coldStart traps dispatched to manager :1620", flush=True)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[agent_sim] stopped")


if __name__ == "__main__":
    main()
