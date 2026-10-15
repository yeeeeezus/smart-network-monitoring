#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_dashboard.py — 7 checks for the optional web view.

Kept separate from test_system.py (the 22-check end-to-end suite) so the
core verification story stays unchanged; run both before a demo:

    python3 test_system.py && python3 test_dashboard.py
"""
import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dashboard

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  {detail}" if (detail and not cond) else ""))
    if cond:
        PASS += 1
    else:
        FAIL += 1


print("=" * 64)
print("DASHBOARD CHECKS (web view of the engine snapshot)")
print("=" * 64)

# 1. state snapshot readable, all six devices present
state = dashboard.load_state()
check("D1 state.json readable with 6 devices",
      len(state.get("devices", {})) == 6,
      f"got {len(state.get('devices', {}))}")

# 2. rendered page lists every device with reachability + colored metrics
page = dashboard.build_page()
missing = [n for n in state["devices"] if f"<b>{n}</b>" not in page]
check("D2 page renders a row per device", not missing, f"missing {missing}")
has_color = ('class="g"' in page) or ('class="w"' in page) or ('class="c"' in page)
check("D3 threshold coloring classes present", has_color)

# 3. page auto-refreshes and identifies itself
check("D4 auto-refresh (2 s) + title",
      'http-equiv="refresh" content="2"' in page and "<title>Smart Network Monitoring" in page)

# 4. alert log rendered with newest first with level classes
alerts = dashboard.load_alerts()
ahtml = dashboard.build_alerts_html(alerts)
check("D5 recent alerts rendered with level classes",
      len(alerts) > 0 and 'class="alert' in ahtml and "critical" in ahtml)

# 5+6. real HTTP server: / serves the page, /api/status serves the snapshot
results = {}


def serve():
    srv = dashboard.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
    port = srv.server_address[1]
    results["port"] = port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            results["root"] = (r.status, r.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=5) as r:
            results["api"] = (r.status, json.loads(r.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001
        results["error"] = str(e)
    finally:
        srv.shutdown()


serve()
check("D6 HTTP / serves HTML status page",
      results.get("root", (0, ""))[0] == 200 and "R1-Core" in results.get("root", (0, ""))[1],
      str(results.get("error", ""))[:80])
check("D7 /api/status serves engine snapshot JSON",
      results.get("api", (0, {}))[0] == 200 and
      len(results.get("api", (0, {}))[1].get("devices", {})) == 6)

print("=" * 64)
print(f"RESULT: {'PASS' if FAIL == 0 else 'FAIL'}  ({PASS} passed, {FAIL} failed)")
sys.exit(0 if FAIL == 0 else 1)
