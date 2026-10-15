#!/usr/bin/env python3
"""
bot.py — Interactive Telegram control panel for the monitoring system.

The bot is the operator's remote control: from a phone, anywhere, you can
query device health, list interfaces, review the alert history and silence
notifications during maintenance.

Commands (chat with your bot, authorized chat only):
    /start            welcome + command list
    /help             same as /start
    /status           health table of every monitored device
    /cpu <device>     LIVE SNMP poll: cpu + memory of one device
    /ifaces <device>  LIVE SNMP walk: interface table with oper status
    /alerts [n]       last n alerts (default 10) from alerts.jsonl
    /mute <minutes>   silence alert notifications
    /unmute           re-enable notifications

Authorization: the bot only serves the chat id in TELEGRAM_CHAT_ID.
Everything else gets a polite refusal — never expose network state to
strangers.

Run together with monitor.py; the two processes share state.json /
alerts.jsonl / bot_state.json.
"""

import json
import os
import signal
import sys
import time
from datetime import datetime

import requests
import yaml

from snmp_lite import SnmpClient

HERE = os.path.dirname(os.path.abspath(__file__))

OID = {
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifDescr":     "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "cpu5min":     "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
    "memPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
    "memPoolFree": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
}


class Bot:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = os.environ.get(cfg["telegram"]["token_env"], "")
        self.chat_id = os.environ.get(cfg["telegram"]["chat_id_env"], "")
        if not self.token:
            sys.exit("TELEGRAM_BOT_TOKEN not set — create a bot with @BotFather first.")
        self.api = f"https://api.telegram.org/bot{self.token}"
        self.state_path = os.path.join(HERE, cfg["files"]["state"])
        self.alerts_path = os.path.join(HERE, cfg["files"]["alerts"])
        self.mute_path = os.path.join(HERE, cfg["telegram"].get("mute_file", "bot_state.json"))
        self.dev_by_name = {d["name"]: d for d in cfg["devices"]}
        self.offset = 0
        self._stop = False

    # ---------------- telegram plumbing ----------------
    def send(self, chat_id, text):
        for attempt in range(3):
            try:
                r = requests.post(f"{self.api}/sendMessage",
                                  json={"chat_id": chat_id, "text": text}, timeout=10)
                if r.status_code == 200:
                    return
                print(f"[bot] sendMessage -> HTTP {r.status_code}: {r.text[:120]}")
                return
            except Exception as e:
                print(f"[bot] sendMessage error: {e}")
                time.sleep(2 * (attempt + 1))

    def get_updates(self):
        r = requests.get(f"{self.api}/getUpdates",
                         params={"timeout": 25, "offset": self.offset}, timeout=30)
        r.raise_for_status()
        return r.json().get("result", [])

    # ---------------- data access ----------------
    def load_state(self):
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except Exception:
            return {"devices": {}, "last_update": 0}

    def load_alerts(self, n):
        try:
            with open(self.alerts_path) as f:
                return [json.loads(l) for l in f.readlines()[-n:]]
        except Exception:
            return []

    def live_device(self, name):
        """On-demand SNMP GET — the same call monitor.py uses."""
        d = self.dev_by_name[name]
        host, port = d["endpoint"].split(":")
        cli = SnmpClient(host, int(port), self.cfg["community"], timeout=self.cfg.get("timeout", 2.0))
        vbs = cli.get([OID["sysUpTime"], OID["cpu5min"], OID["memPoolUsed"], OID["memPoolFree"]])
        up, cpu, used, free = (v.value for v in vbs)
        return cpu, round(100.0 * used / max(1, used + free), 1), int(up / 100)

    def live_ifaces(self, name):
        d = self.dev_by_name[name]
        host, port = d["endpoint"].split(":")
        cli = SnmpClient(host, int(port), self.cfg["community"], timeout=self.cfg.get("timeout", 2.0))
        descs = cli.walk(OID["ifDescr"])
        out = []
        for v in descs:
            idx = v.oid.split(".")[-1]
            oper = cli.get([f'{OID["ifOperStatus"]}.{idx}'])[0].value
            out.append((v.value, "up" if oper == 1 else "DOWN"))
        return out

    # ---------------- command handlers ----------------
    def handle(self, chat_id, text):
        if str(chat_id) != str(self.chat_id):
            return "⛔️ Unauthorized chat. This bot serves the network operator only."
        parts = text.split()
        cmd = parts[0].split("@")[0].lower()

        if cmd in ("/start", "/help"):
            return ("🛰️ Smart Network Monitoring — control panel\n\n"
                    "/status — health of all devices\n"
                    "/cpu <device> — live CPU + memory\n"
                    "/ifaces <device> — live interface table\n"
                    "/alerts [n] — recent alert history\n"
                    "/mute <minutes> — silence notifications\n"
                    "/unmute — re-enable notifications\n\n"
                    f"Monitored: {', '.join(self.dev_by_name)}")

        if cmd == "/status":
            st = self.load_state()
            if not st.get("last_update"):
                return "⏳ No monitoring data yet — is monitor.py running?"
            lines = [f"🖥 Network status — updated {datetime.fromtimestamp(st['last_update']).strftime('%H:%M:%S')}\n"]
            for name, d in sorted(st["devices"].items()):
                if d.get("reachable"):
                    lines.append(f"🟢 {name:<10} cpu {d['cpu']:>3}%   mem {d['mem_pct']:>5.1f}%   "
                                 f"up {int(d['uptime']/100)}s")
                else:
                    lines.append(f"🔴 {name:<10} UNREACHABLE")
            try:
                with open(self.mute_path) as f:
                    muted_until = json.load(f).get("muted_until", 0)
                if time.time() < muted_until:
                    lines.append(f"\n🔕 Notifications muted until "
                                 f"{datetime.fromtimestamp(muted_until).strftime('%H:%M:%S')}")
            except Exception:
                pass
            return "\n".join(lines)

        if cmd == "/cpu" and len(parts) >= 2:
            name = parts[1]
            if name not in self.dev_by_name:
                return f"Unknown device. Try: {', '.join(self.dev_by_name)}"
            try:
                cpu, mem, up = self.live_device(name)
                return (f"📊 {name} (live SNMP)\n"
                        f"CPU 5min: {cpu}%\nMemory pool: {mem}% used\n"
                        f"Uptime: {up}s")
            except Exception as e:
                return f"❌ {name} did not answer ({type(e).__name__})"

        if cmd == "/ifaces" and len(parts) >= 2:
            name = parts[1]
            if name not in self.dev_by_name:
                return f"Unknown device. Try: {', '.join(self.dev_by_name)}"
            try:
                rows = self.live_ifaces(name)
                lines = [f"🔌 {name} interface table (live SNMP)\n"]
                for descr, st in rows:
                    lines.append(f"{'🟢' if st == 'up' else '🔴'} {descr:<24} {st}")
                return "\n".join(lines)
            except Exception as e:
                return f"❌ {name} did not answer ({type(e).__name__})"

        if cmd == "/alerts":
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            alerts = self.load_alerts(n)
            if not alerts:
                return "📭 No alerts recorded yet."
            lines = ["🚨 Recent alerts\n"]
            for a in reversed(alerts):
                icon = {"critical": "🔴", "warning": "⚠️", "recovery": "✅",
                        "info": "ℹ️"}.get(a["level"], "•")
                lines.append(f"{icon} {datetime.fromtimestamp(a['ts']).strftime('%H:%M:%S')} "
                             f"{a['message']}")
            return "\n".join(lines)

        if cmd == "/mute" and len(parts) > 1 and parts[1].isdigit():
            minutes = int(parts[1])
            until = time.time() + minutes * 60
            with open(self.mute_path, "w") as f:
                json.dump({"muted_until": until}, f)
            return f"🔕 Notifications muted for {minutes} min (until " \
                   f"{datetime.fromtimestamp(until).strftime('%H:%M:%S')})"

        if cmd == "/unmute":
            with open(self.mute_path, "w") as f:
                json.dump({"muted_until": 0}, f)
            return "🔔 Notifications re-enabled."

        return "Unknown command — try /help"

    # ---------------- main loop ----------------
    def run(self):
        print(f"[bot] authorized chat: {self.chat_id or '(unset!)'}")
        print("[bot] long-polling getUpdates — press Ctrl+C to stop", flush=True)
        while not self._stop:
            try:
                for upd in self.get_updates():
                    self.offset = upd["update_id"] + 1
                    msg = upd.get("message") or upd.get("edited_message") or {}
                    text = (msg.get("text") or "").strip()
                    chat_id = msg.get("chat", {}).get("id")
                    who = msg.get("from", {}).get("username") or msg.get("from", {}).get("first_name", "?")
                    if not text:
                        continue
                    print(f"[bot] {who}: {text}", flush=True)
                    reply = self.handle(chat_id, text)
                    self.send(chat_id, reply)
            except requests.RequestException as e:
                print(f"[bot] network error: {e}")
                time.sleep(5)
            except Exception as e:
                print(f"[bot] error: {e}")
                time.sleep(2)


def main():
    with open(os.path.join(HERE, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    bot = Bot(cfg)

    def stop(*_):
        bot._stop = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    bot.run()


if __name__ == "__main__":
    main()
