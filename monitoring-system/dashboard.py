#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dashboard.py — optional live web view of the monitored network.

Serves a zero-dependency status page (Python stdlib only: http.server).
Reads the engine's state.json and alerts.jsonl — it never talks SNMP
itself, so it adds no load to the network and cannot disturb polling.

Run (terminal 4, after monitor.py is running):
    python3 dashboard.py            # http://localhost:8080

Endpoints:
    /            auto-refreshing HTML status page (2 s)
    /api/status  the engine snapshot as JSON (devices + last_update)

The page intentionally matches the alert vocabulary of the system:
green = OK, amber = warning thresholds (cpu >= 70 / mem >= 75),
red = critical thresholds (cpu >= 85 / mem >= 90), grey = unreachable.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "state.json")
ALERTS_FILE = os.path.join(HERE, "alerts.jsonl")

CPU_WARN, CPU_CRIT = 70, 85
MEM_WARN, MEM_CRIT = 75, 90
PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))

PAGE_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>Smart Network Monitoring — live status</title>
<style>
:root {{
  --primary:#0F2A43; --accent:#0891B2; --ink:#334155; --soft:#64748B;
  --line:#E2E8F0; --ok:#059669; --warn:#D97706; --crit:#DC2626;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI', system-ui, sans-serif; background:#F8FAFC;
       color:var(--ink); padding:28px 34px; }}
h1 {{ color:var(--primary); font-size:22px; margin-bottom:2px; }}
.sub {{ color:var(--soft); font-size:12.5px; margin-bottom:20px; }}
table {{ border-collapse:collapse; width:100%; background:#fff;
         border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
th {{ background:var(--primary); color:#F8FAFC; text-align:left;
      padding:9px 12px; font-size:12px; }}
td {{ padding:8px 12px; border-top:1px solid var(--line); font-size:12.5px; }}
tr:nth-child(even) td {{ background:#F8FAFC; }}
.up {{ color:var(--ok); font-weight:600; }}
.down {{ color:var(--crit); font-weight:600; }}
.w {{ color:var(--warn); font-weight:600; }}
.c {{ color:var(--crit); font-weight:600; }}
.g {{ color:var(--ok); font-weight:600; }}
h2 {{ color:var(--primary); font-size:15px; margin:24px 0 10px 0; }}
.alert {{ font-family:Consolas, monospace; font-size:12px; padding:7px 12px;
          border-radius:8px; margin-bottom:6px; background:#fff;
          border:1px solid var(--line); }}
.alert.critical {{ border-left:4px solid var(--crit); }}
.alert.warning {{ border-left:4px solid var(--warn); }}
.alert.info {{ border-left:4px solid var(--accent); }}
.muted {{ color:var(--soft); }}
</style>
</head>
<body>
<h1>Smart Network Monitoring — live status</h1>
<div class="sub">served by dashboard.py &middot; reads the engine snapshot &middot;
page refreshes every 2 s &middot; updated {updated}</div>

<table>
<tr><th>Device</th><th>Reachable</th><th>CPU</th><th>Memory</th>
<th>Uptime</th><th>Interfaces</th></tr>
{rows}
</table>

<h2>Recent alerts</h2>
{alerts}
<div class="muted" style="margin-top:18px;font-size:11px">
Data source: state.json + alerts.jsonl written by monitor.py &mdash;
this view adds zero SNMP load to the network.
</div>
</body>
</html>"""


def _fmt_uptime(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def _cls(kind, pct, warn, crit):
    if pct is None:
        return "muted"
    if pct >= crit:
        return "c"
    if pct >= warn:
        return "w"
    return "g"


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"devices": {}, "last_update": None}


def load_alerts(n=15):
    try:
        with open(ALERTS_FILE) as f:
            lines = f.readlines()[-n:]
        return [json.loads(x) for x in lines if x.strip()]
    except (OSError, ValueError):
        return []


def build_rows(state):
    rows = []
    for name, d in state.get("devices", {}).items():
        reachable = bool(d.get("reachable"))
        cpu, mem, up = d.get("cpu"), d.get("mem_pct"), d.get("uptime")
        ifaces = d.get("interfaces", {})
        up_n = sum(1 for v in ifaces.values() if v == "up")
        iface_txt = f"{up_n}/{len(ifaces)} up" if ifaces else "—"
        cpu_td = (f'<td class="{_cls("cpu", cpu, CPU_WARN, CPU_CRIT)}">{cpu}%</td>'
                  if cpu is not None else '<td class="muted">—</td>')
        mem_td = (f'<td class="{_cls("mem", mem, MEM_WARN, MEM_CRIT)}">{mem:.1f}%</td>'
                  if mem is not None else '<td class="muted">—</td>')
        up_td = (f"<td>{_fmt_uptime(up)}</td>" if up is not None else '<td class="muted">—</td>')
        rows.append(
            f"<tr><td><b>{name}</b></td>"
            f"<td class=\"{'up' if reachable else 'down'}\">{'UP' if reachable else 'DOWN'}</td>"
            f"{cpu_td}{mem_td}{up_td}"
            f"<td>{iface_txt}</td></tr>")
    return "\n".join(rows) or ("<tr><td colspan=\"6\" class=\"muted\">"
                               "no state yet — start monitor.py</td></tr>")


def build_alerts_html(alerts):
    if not alerts:
        return '<div class="muted">no alerts recorded yet</div>'
    out = []
    for a in reversed(alerts):
        lvl = a.get("level", "info")
        ts = time.strftime("%H:%M:%S", time.localtime(a.get("ts", 0)))
        out.append(f'<div class="alert {lvl}">[{ts}] {a.get("message", "")}</div>')
    return "\n".join(out)


def build_page():
    state = load_state()
    updated = (time.strftime("%H:%M:%S", time.localtime(state["last_update"]))
               if state.get("last_update") else "—")
    return PAGE_TMPL.format(rows=build_rows(state), alerts=build_alerts_html(load_alerts()),
                            updated=updated)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = build_page().encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif self.path == "/api/status":
            body = json.dumps(load_state()).encode("utf-8")
            ctype = "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"dashboard: http://localhost:{PORT}  (reading {STATE_FILE})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\ndashboard: stopped")


if __name__ == "__main__":
    main()
