#!/usr/bin/env python3
"""
test_system.py — End-to-end verification of the whole monitoring system.

Phases
  1. Protocol self-test        snmp_lite BER/ASN.1 round-trips
  2. Agent bring-up            6 SNMPv2c agents, GET/WALK/dynamics
  3. Incident drill            full scenario at 2x speed, monitor engine with
                               5s polling: warnings, criticals, traps,
                               recoveries -> alerts.jsonl; measures the
                               event-to-alert latency of every notification
  4. Bot handler unit tests    command handlers with a fake Telegram sender

Exit code 0 = all pass. Results are printed as a table and written to
test_results.json for the project documentation.
"""

import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from snmp_lite import SnmpClient  # noqa: E402

RESULTS = {"phases": {}, "latencies": []}


def phase(name):
    print(f"\n{'=' * 64}\nPHASE {name}\n{'=' * 64}", flush=True)


def ok(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    RESULTS["phases"][f"{name}"] = status
    print(f"[{status}] {name} {detail}", flush=True)
    return cond


def main():
    # kill any orphaned agents from previous runs (a crashed test leaves them bound)
    subprocess.run(["pkill", "-f", "agent_sim.py"], capture_output=True)
    time.sleep(1.0)

    # ---------------- phase 1: protocol ----------------
    phase("1 protocol self-test")
    r = subprocess.run([sys.executable, os.path.join(HERE, "snmp_lite.py")],
                       capture_output=True, text=True, timeout=30)
    ok("1.1 BER/ASN.1 + PDU self-test", "ALL PASS" in r.stdout)

    # ---------------- phase 2: agents ----------------
    phase("2 agent bring-up")
    for f in ("alerts.jsonl", "state.json", "bot_state.json"):
        try:
            os.remove(os.path.join(HERE, f))
        except FileNotFoundError:
            pass

    speed = 0.5     # 2x faster scenario
    agent_proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "agent_sim.py"),
         "--scenario-speed", str(speed)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=HERE)
    agent_t0 = time.time()

    names = ["R1-Core", "R2-Branch", "R3-HQ", "R4-ISP", "SW-HQ", "SW-Branch"]
    probed = {}
    for _ in range(40):
        try:
            c = SnmpClient("127.0.0.1", 1161, "MonNet-RO", timeout=0.5)
            if c.get(["1.3.6.1.2.1.1.5.0"])[0].value == "R1-Core":
                break
        except Exception:
            time.sleep(0.25)
    for port in range(1161, 1167):
        c = SnmpClient("127.0.0.1", port, "MonNet-RO", timeout=2)
        probed[names[port - 1161]] = c.get(["1.3.6.1.2.1.1.5.0"])[0].value
    ok("2.1 all six agents answer GET sysName", probed == {n: n for n in names},
       str(probed))

    walk = SnmpClient("127.0.0.1", 1163, "MonNet-RO").walk("1.3.6.1.2.1.2.2.1.2")
    ok("2.2 GETNEXT walk returns R3-HQ interface table", len(walk) == 5,
       f"{len(walk)} ifDescr rows")

    a = SnmpClient("127.0.0.1", 1162, "MonNet-RO").get(["1.3.6.1.2.1.2.2.1.10.1"])[0].value
    time.sleep(3)
    b = SnmpClient("127.0.0.1", 1162, "MonNet-RO").get(["1.3.6.1.2.1.2.2.1.10.1"])[0].value
    ok("2.3 ifInOctets counter is live", b > a, f"{a} -> {b} B")

    # ---------------- phase 3: incident drill ----------------
    phase("3 incident drill (scenario at 2x speed, 5s polling)")
    test_cfg = {
        "community": "MonNet-RO", "interval": 5, "timeout": 1.0,
        "trap_bind": "127.0.0.1:1620",
        "thresholds": {"cpu": {"warning": 70, "critical": 85},
                       "memory": {"warning": 75, "critical": 90}},
        "devices": [{"name": n, "endpoint": f"127.0.0.1:{1161 + i}", "kind": "router"}
                    for i, n in enumerate(names)],
        "telegram": {"token_env": "X", "chat_id_env": "X", "mute_file": "bot_state.json"},
        "files": {"state": "state.json", "alerts": "alerts.jsonl"},
    }
    import yaml
    cfg_path = os.path.join(HERE, "test_config.yaml")
    with open(cfg_path, "w") as f:
        yaml.safe_dump(test_cfg, f)

    drill_duration = 115
    mon = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "monitor.py"),
         "--config", cfg_path, "--duration", str(drill_duration), "--no-telegram"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=HERE)
    mon_out = mon.communicate(timeout=drill_duration + 60)[0]
    print(mon_out[-2500:])

    with open(os.path.join(HERE, "alerts.jsonl")) as f:
        alerts = [json.loads(l) for l in f if l.strip()]

    # scenario event times (2x speed) relative to agent start; agent clock is
    # derived from the coldStart traps (they arrive at agent uptime 10s)
    cold = [a for a in alerts if "COLD START" in a["message"]]
    agent_clock0 = (sum(a["ts"] for a in cold) / len(cold) - 10.0) if cold else agent_t0
    speed = 0.5
    ev = {"cpu_warn": 45 * speed, "cpu_crit": 60 * speed, "link_down": 80 * speed,
          "mem_warn": 115 * speed, "link_up": 140 * speed, "cpu_recover": 165 * speed}

    def find(device, level, keyword):
        return next((a for a in alerts if a["device"] == device and a["level"] == level
                     and keyword in a["message"]), None)

    coldstarts = [a for a in alerts if a["level"] == "info" and "COLD START" in a["message"]]
    ok("3.1 coldStart traps received (one per device)", len(coldstarts) == 6,
       f"{len(coldstarts)} received")

    aw = find("R2-Branch", "warning", "CPU")
    ok("3.2 CPU WARNING fired (R2 78%)", aw is not None,
       aw["message"] if aw else "missing")
    if aw:
        RESULTS["latencies"].append({
            "incident": "R2 CPU 78% (warning)", "event": ev["cpu_warn"],
            "detection": aw["ts"] - agent_clock0,
            "latency_s": round(aw["ts"] - agent_clock0 - ev["cpu_warn"], 2)})

    ac = find("R2-Branch", "critical", "CPU")
    ok("3.3 CPU CRITICAL fired (R2 93%)", ac is not None,
       ac["message"] if ac else "missing")
    if ac:
        RESULTS["latencies"].append({
            "incident": "R2 CPU 93% (critical)", "event": ev["cpu_crit"],
            "detection": ac["ts"] - agent_clock0,
            "latency_s": round(ac["ts"] - agent_clock0 - ev["cpu_crit"], 2)})

    ld = find("R3-HQ", "critical", "LINK DOWN")
    ok("3.4 linkDown TRAP alert (R3 Gi0/0)", ld is not None,
       ld["message"] if ld else "missing")
    if ld:
        RESULTS["latencies"].append({
            "incident": "R3 Gi0/0 link down (trap)", "event": ev["link_down"],
            "detection": ld["ts"] - agent_clock0,
            "latency_s": round(ld["ts"] - agent_clock0 - ev["link_down"], 2)})

    mw = find("R1-Core", "warning", "MEMORY")
    ok("3.5 MEMORY warning fired (R1 81%)", mw is not None,
       mw["message"] if mw else "missing")
    if mw:
        RESULTS["latencies"].append({
            "incident": "R1 memory 81% (warning)", "event": ev["mem_warn"],
            "detection": mw["ts"] - agent_clock0,
            "latency_s": round(mw["ts"] - agent_clock0 - ev["mem_warn"], 2)})

    lu = find("R3-HQ", "recovery", "LINK UP")
    ok("3.6 linkUp TRAP recovery alert", lu is not None,
       lu["message"] if lu else "missing")

    rc = find("R2-Branch", "recovery", "CPU")
    ok("3.7 CPU recovery after cooldown", rc is not None,
       rc["message"] if rc else "missing")
    if rc:
        RESULTS["latencies"].append({
            "incident": "R2 CPU recovery", "event": ev["cpu_recover"],
            "detection": rc["ts"] - agent_clock0,
            "latency_s": round(rc["ts"] - agent_clock0 - ev["cpu_recover"], 2)})

    with open(os.path.join(HERE, "state.json")) as f:
        state = json.load(f)
    ok("3.8 state.json carries full device snapshot",
       len(state["devices"]) == 6 and all("cpu" in v for v in state["devices"].values() if v.get("reachable")))

    # duplicate suppression check: while CPU stays critical no repeated alerts
    crit_alerts = [a for a in alerts if a["device"] == "R2-Branch"
                   and a["level"] == "critical" and "CPU" in a["message"]]
    ok("3.9 no duplicate alerts while state persists", len(crit_alerts) == 1,
       f"{len(crit_alerts)} critical CPU alert(s)")

    # NOTE: agents stay alive for phase 4 — the bot's live commands need them

    # ---------------- phase 4: bot handlers ----------------
    phase("4 bot handler unit tests (fake sender)")
    import bot as botmod
    with open(os.path.join(HERE, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    cfg["telegram"]["token_env"] = "X"
    cfg["telegram"]["chat_id_env"] = "X"
    fake = botmod.Bot.__new__(botmod.Bot)      # skip __init__ (no token needed)
    fake.cfg = cfg
    fake.chat_id = "42"
    fake.dev_by_name = {d["name"]: d for d in cfg["devices"]}
    fake.state_path = os.path.join(HERE, "state.json")
    fake.alerts_path = os.path.join(HERE, "alerts.jsonl")
    fake.mute_path = os.path.join(HERE, "bot_state.json")

    replies = {}
    for label, chat_id, text in [
        ("4.1 /help", "42", "/help"),
        ("4.2 /status", "42", "/status"),
        ("4.3 /cpu R2-Branch", "42", "/cpu R2-Branch"),
        ("4.4 /ifaces R3-HQ", "42", "/ifaces R3-HQ"),
        ("4.5 /alerts", "42", "/alerts"),
        ("4.6 /mute 5", "42", "/mute 5"),
        ("4.7 /unmute", "42", "/unmute"),
        ("4.8 unauthorized chat refused", "999", "/status"),
    ]:
        replies[label] = fake.handle(chat_id, text)
        ok(label, bool(replies[label]) and ("Unauthorized" in replies[label] if "unauthorized" in label.lower()
                                            else "Unauthorized" not in replies[label]),
           replies[label].splitlines()[0][:60])
    ok("4.9 /mute writes shared mute file", os.path.exists(fake.mute_path))

    # terminate agents AFTER phase 4 (live bot commands needed them)
    agent_proc.terminate()
    agent_proc.wait(timeout=10)
    subprocess.run(["pkill", "-f", "agent_sim.py"], capture_output=True)

    # ---------------- summary ----------------
    fails = [k for k, v in RESULTS["phases"].items() if v == "FAIL"]
    RESULTS["overall"] = "PASS" if not fails else f"FAIL ({len(fails)})"
    RESULTS["alert_count"] = len(alerts)
    with open(os.path.join(HERE, "test_results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)

    print(f"\n{'=' * 64}\nSUMMARY: {RESULTS['overall']}  "
          f"({len(alerts)} alerts recorded)\n{'=' * 64}")
    if RESULTS["latencies"]:
        print(f"{'incident':<34}{'event@s':>9}{'detected@s':>11}{'latency':>9}")
        for l in RESULTS["latencies"]:
            print(f"{l['incident']:<34}{l['event']:>9.1f}{l['detection']:>11.1f}"
                  f"{l['latency_s']:>8.1f}s")
    print("\nbot replies preview:")
    for label in ("4.2 /status", "4.3 /cpu R2-Branch", "4.5 /alerts"):
        first = next((ln for ln in replies[label].splitlines() if ln.strip()), "")
        print(f"  {label:<22} -> {first[:76]}")

    # cleanup test artifacts
    for f in ("test_config.yaml",):
        try:
            os.remove(os.path.join(HERE, f))
        except FileNotFoundError:
            pass
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
