#!/usr/bin/env python3
"""
monitor.py — Polling + threshold + alerting engine of the graduation project.

Architecture (3 planes):

  DATA PLANE    six SNMPv2c agents (agent_sim.py or REAL Cisco devices)
      |                GET every `interval` seconds
  ENGINE        this file: poller, threshold state machine, trap receiver
      |                HTTPS sendMessage
  NOTIFICATION  Telegram chat on the student's phone

Threshold engine rules
  * every (device, metric) pair has a state: ok / warning / critical
  * alert fires ONLY on a state TRANSITION (no spam while value stays high)
  * recovery notice fires when the state returns to ok
  * device unreachability is tracked separately (timeout on poll)

Trap plane
  * binds udp/<trap_bind> (default 127.0.0.1:1620)
  * authenticates the community string, maps the source port to a device
  * linkDown / linkUp / coldStart traps become instant alerts (no poll wait)

Usage:
    python3 monitor.py --once              # single poll, console table
    python3 monitor.py                     # continuous monitoring + alerts
    python3 monitor.py --duration 120      # stop after N seconds (testing)
    python3 monitor.py --no-telegram       # log alerts to file only
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime

import yaml

from snmp_lite import (SnmpClient, parse_message, PDU_TRAPV2, TAG_OCTET,
                       TAG_TIMETICKS, TAG_GAUGE32, TAG_COUNTER32, TAG_INTEGER)

HERE = os.path.dirname(os.path.abspath(__file__))

OID = {
    "sysName":      "1.3.6.1.2.1.1.5.0",
    "sysUpTime":    "1.3.6.1.2.1.1.3.0",
    "sysLocation":  "1.3.6.1.2.1.1.6.0",
    "ifDescr":      "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets":   "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets":  "1.3.6.1.2.1.2.2.1.16",
    "cpu5min":      "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
    "memPoolUsed":  "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
    "memPoolFree":  "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    "snmpTrapOID":  "1.3.6.1.6.3.1.1.4.1.0",
}

TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": ("COLD START", "info"),
    "1.3.6.1.6.3.1.1.5.3": ("LINK DOWN", "critical"),
    "1.3.6.1.6.3.1.1.5.4": ("LINK UP", "recovery"),
}


# ---------------------------------------------------------------- Telegram

class Telegram:
    """Queue-based Telegram sender with mute-window support."""

    def __init__(self, cfg, enabled=True):
        self.token = os.environ.get(cfg["token_env"], "")
        self.chat_id = os.environ.get(cfg["chat_id_env"], "")
        self.enabled = enabled and bool(self.token and self.chat_id)
        self.mute_file = os.path.join(HERE, cfg.get("mute_file", "bot_state.json"))
        self.queue = []
        self.cv = threading.Condition()
        self._stop = False
        if self.enabled:
            threading.Thread(target=self._sender, daemon=True, name="tg-sender").start()

    def muted(self):
        try:
            with open(self.mute_file) as f:
                until = json.load(f).get("muted_until", 0)
            return time.time() < until
        except Exception:
            return False

    def send(self, text):
        if not self.enabled:
            return
        with self.cv:
            self.queue.append(text)
            self.cv.notify()

    def _sender(self):
        import requests
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        while True:
            with self.cv:
                while not self.queue and not self._stop:
                    self.cv.wait(timeout=1.0)
                if self._stop:
                    return
                text = self.queue.pop(0)
            if self.muted():
                print("[monitor] alert suppressed (muted): %s" % text.splitlines()[0][:60])
                continue
            for attempt in range(3):
                try:
                    r = requests.post(url, json={"chat_id": self.chat_id, "text": text}, timeout=10)
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(2 * (attempt + 1))
            else:
                print("[monitor] TELEGRAM SEND FAILED: %s" % text.splitlines()[0][:60], flush=True)


# ---------------------------------------------------------------- engine

def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class Monitor:
    def __init__(self, cfg, telegram_enabled=True):
        self.cfg = cfg
        self.community = cfg["community"]
        self.interval = cfg.get("interval", 15)
        self.th = cfg["thresholds"]
        self.tg = Telegram(cfg["telegram"], enabled=telegram_enabled)
        self.alerts_path = os.path.join(HERE, cfg["files"]["alerts"])
        self.state_path = os.path.join(HERE, cfg["files"]["state"])
        self.port_map = {}          # agent UDP port -> device name (for traps)
        self.clients = {}           # device name -> SnmpClient
        self.ifaces = {}            # device name -> {ifIndex: descr}
        self.states = {}            # (device, metric) -> 'ok'|'warning'|'critical'
        self.reachable = {}         # device -> bool
        self.state = {"devices": {}, "last_update": 0}
        self._stop = False

        for d in cfg["devices"]:
            host, port = d["endpoint"].split(":")
            port = int(port)
            self.clients[d["name"]] = SnmpClient(host, port, self.community,
                                                 timeout=cfg.get("timeout", 2.0))
            self.port_map[port] = d["name"]
            self.reachable[d["name"]] = True
            for m in ("cpu", "memory"):
                self.states[(d["name"], m)] = "ok"

    # ---------------- alerts ----------------
    def record_alert(self, level, device, metric, value, message, event_time=None):
        entry = {"ts": time.time(), "event_ts": event_time or time.time(), "device": device,
                 "level": level, "metric": metric, "value": value, "message": message}
        with open(self.alerts_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        icon = {"critical": "🔴", "warning": "⚠️", "recovery": "✅", "info": "ℹ️"}.get(level, "•")
        print(f"[monitor] {fmt_ts(entry['ts'])} {icon} {message}", flush=True)
        self.tg.send(f"{icon} {message}")

    # ---------------- polling ----------------
    def discover_interfaces(self):
        for name, cli in self.clients.items():
            try:
                descs = cli.walk(OID["ifDescr"])
                self.ifaces[name] = {int(v.oid.split(".")[-1]): v.value for v in descs}
                print(f"[monitor] {name}: {len(self.ifaces[name])} interfaces discovered")
            except Exception as e:
                print(f"[monitor] {name}: interface discovery failed ({e})")

    def poll_device(self, name):
        cli = self.clients[name]
        oids = [OID["sysUpTime"], OID["cpu5min"], OID["memPoolUsed"], OID["memPoolFree"]]
        oids += [f'{OID["ifOperStatus"]}.{i}' for i in self.ifaces.get(name, {})]
        try:
            vbs = cli.get(oids)
            self.reachable[name] = True
        except Exception:
            self.reachable[name] = False
            return None
        vals = {v.oid: v.value for v in vbs}
        uptime = vals.get(OID["sysUpTime"], 0)
        cpu = vals.get(OID["cpu5min"], 0)
        used = vals.get(OID["memPoolUsed"], 0)
        free = vals.get(OID["memPoolFree"], 0)
        mem_pct = round(100.0 * used / max(1, used + free), 1)
        ifaces = {}
        for idx, descr in self.ifaces.get(name, {}).items():
            oper = vals.get(f'{OID["ifOperStatus"]}.{idx}', 1)
            ifaces[descr] = "up" if oper == 1 else "down"
        return {"cpu": cpu, "mem_pct": mem_pct, "mem_used": used, "mem_free": free,
                "uptime": uptime, "interfaces": ifaces,
                "last_poll": time.time()}

    def check_threshold(self, device, metric, value):
        limits = self.th[metric]
        key = (device, metric)
        old = self.states[key]
        if value >= limits["critical"]:
            new = "critical"
        elif value >= limits["warning"]:
            new = "warning"
        else:
            new = "ok"
        if new == old:
            return
        unit = "%"
        if new == "critical":
            self.record_alert("critical", device, metric, value,
                              f"CRITICAL — {device}: {metric.upper()} = {value}{unit} "
                              f"(threshold {limits['critical']}{unit})")
        elif new == "warning":
            self.record_alert("warning", device, metric, value,
                              f"WARNING — {device}: {metric.upper()} = {value}{unit} "
                              f"(threshold {limits['warning']}{unit})")
        else:
            self.record_alert("recovery", device, metric, value,
                              f"RESOLVED — {device}: {metric.upper()} back to {value}{unit}")
        self.states[key] = new

    def poll_cycle(self):
        for name in self.clients:
            snapshot = self.poll_device(name)
            if snapshot is None:
                if self.reachable.get(name, True) is False:
                    pass  # already flagged down
                else:
                    self.reachable[name] = False
                    self.record_alert("critical", name, "reachability", None,
                                      f"UNREACHABLE — {name} is not answering SNMP GETs")
                self.state["devices"][name] = {"reachable": False}
                continue
            if not self.reachable.get(name, True):
                self.reachable[name] = True
                self.record_alert("recovery", name, "reachability", None,
                                  f"REACHABLE AGAIN — {name} answers SNMP")
            self.check_threshold(name, "cpu", snapshot["cpu"])
            self.check_threshold(name, "memory", snapshot["mem_pct"])
            self.state["devices"][name] = {"reachable": True, **snapshot}
        self.state["last_update"] = time.time()
        with open(self.state_path, "w") as f:
            json.dump(self.state, f, indent=1)

    def poll_once_print(self):
        self.discover_interfaces()
        self.poll_cycle()
        print(f"\n{'DEVICE':<11}{'STATUS':<10}{'CPU':>5}{'MEM%':>7}{'UPTIME':>10}  INTERFACES")
        for name, d in self.state["devices"].items():
            if not d.get("reachable"):
                print(f"{name:<11}{'DOWN':<10}")
                continue
            ifs = ", ".join(f"{k}:{v}" for k, v in list(d["interfaces"].items())[:3])
            print(f"{name:<11}{'UP':<10}{d['cpu']:>4}%{d['mem_pct']:>6.1f}%"
                  f"{int(d['uptime']/100):>9}s  {ifs}")

    # ---------------- trap receiver ----------------
    def trap_loop(self):
        host, port = self.cfg["trap_bind"].split(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, int(port)))
        sock.settimeout(1.0)
        print(f"[monitor] trap receiver on {self.cfg['trap_bind']}", flush=True)
        while not self._stop:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = parse_message(data)
            except Exception:
                continue
            if msg["pdu_type"] != PDU_TRAPV2 or msg["community"] != self.community:
                continue
            device = self.port_map.get(addr[1], f"unknown@{addr[0]}:{addr[1]}")
            vbs = {v.oid: v.value for v in msg["varbinds"]}
            trap_oid = vbs.get(OID["snmpTrapOID"], "")
            label, level = TRAP_NAMES.get(trap_oid, (f"TRAP {trap_oid}", "info"))
            detail = ""
            for oid, val in vbs.items():
                if oid.startswith(OID["ifDescr"]):
                    detail = val
            uptime = vbs.get(OID["sysUpTime"], 0)
            self.record_alert(level, device, "trap", None,
                              f"{label} — {device} {detail} "
                              f"(agent uptime {int(uptime/100)}s)",
                              event_time=time.time())

    # ---------------- main loops ----------------
    def run(self, duration=None):
        print(f"[monitor] polling {len(self.clients)} devices every {self.interval}s — "
              f"thresholds cpu>{self.th['cpu']['warning']}%/{self.th['cpu']['critical']}%, "
              f"mem>{self.th['memory']['warning']}%/{self.th['memory']['critical']}%", flush=True)
        self.tg.send(f"🟢 Monitoring started\n"
                     f"Devices: {', '.join(self.clients)}\n"
                     f"Poll interval: {self.interval}s — alerts are ON")
        self.discover_interfaces()
        trap_t = threading.Thread(target=self.trap_loop, daemon=True, name="trap-rx")
        trap_t.start()
        started = time.time()
        while not self._stop:
            self.poll_cycle()
            if duration and time.time() - started >= duration:
                break
            time.sleep(self.interval)
        self.tg.send("🔴 Monitoring stopped")


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=os.path.join(HERE, "config.yaml"))
    ap.add_argument("--once", action="store_true", help="single polling cycle, print table")
    ap.add_argument("--duration", type=int, default=None, help="stop after N seconds")
    ap.add_argument("--no-telegram", action="store_true", help="disable Telegram sends")
    args = ap.parse_args()

    cfg = load_config(args.config)
    mon = Monitor(cfg, telegram_enabled=not args.no_telegram)

    def stop(*_):
        mon._stop = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if args.once:
        mon.poll_once_print()
        return
    mon.run(duration=args.duration)


if __name__ == "__main__":
    main()
