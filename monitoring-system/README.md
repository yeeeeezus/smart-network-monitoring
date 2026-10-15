# Smart Network Monitoring — Graduation Project

SNMP-based network monitoring with a Telegram alarm channel, built for
Cisco Packet Tracer 8.2 (simulation) and portable to real Cisco hardware.

## What is in this package

```
packet-tracer/
  Smart_Network_Monitoring_Lab.pkt   open this file in Packet Tracer 8.2+
monitoring-system/
  snmp_lite.py     dependency-free SNMPv2c stack (BER codec, GET/WALK/traps)
  agent_sim.py     six simulated Cisco agents = the live data plane
  monitor.py       polling engine + thresholds + trap receiver + alerts
  bot.py           Telegram control panel (/status /cpu /ifaces /alerts ...)
  dashboard.py     optional zero-dependency live web view (localhost:8080)
  config.yaml      all settings (community, thresholds, devices)
  test_system.py   end-to-end verification (22 checks)
  test_dashboard.py  web view verification (7 checks)
```

## Quick start (5 minutes)

### 1. Open the lab
Open `packet-tracer/Smart_Network_Monitoring_Lab.pkt` in Cisco Packet Tracer
8.2 or newer. The network boots fully configured: OSPF triangle between
R1/R2/R3, R3-HQ router-on-a-stick (VLAN 10 users / VLAN 20 management),
R4-ISP WAN, syslog + NTP services on SVR-MGMT, and SNMP enabled on every
router and switch (`snmp-server community MonNet-RO RO`, traps to the NMS).

Verify inside Packet Tracer: click R1-Core → CLI → `show snmp`,
`show ip ospf neighbor`, and from NMS-PC Desktop → Command Prompt:
`ping 192.168.30.1`.

### 2. Create YOUR Telegram bot (BotFather)
1. In Telegram, talk to **@BotFather** → `/newbot` → follow the prompts.
2. Copy the token you receive (looks like `123456:AA...`).
3. Send any message to your new bot (press START).
4. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and
   copy the `"chat":{"id":...}` number.

### 3. Configure and run
```bash
cd monitoring-system
pip install -r requirements.txt

export TELEGRAM_BOT_TOKEN="123456:AA..."    # your token
export TELEGRAM_CHAT_ID="123456789"         # your chat id

# terminal 1 — the simulated network (R1..SW-Branch agents)
python3 agent_sim.py

# terminal 2 — the monitoring engine (polls + traps + alerts)
python3 monitor.py

# terminal 3 — the interactive bot (optional)
python3 bot.py
```

Your phone now receives every alert. The built-in incident scenario fires
after ~45s (R2 CPU storm), ~80s (R3 link down) and ~115s (R1 memory
pressure) — watch the alerts arrive in real time.

Chat with your bot: `/status`, `/cpu R2-Branch`, `/ifaces R3-HQ`,
`/alerts`, `/mute 30`.

### 4. Open the live dashboard (optional)
With the engine running (terminal 2):
```bash
python3 dashboard.py          # then open http://localhost:8080
```
The page refreshes every 2 s and reads the engine's snapshot
(state.json + alerts.jsonl), so it adds zero SNMP load to the network.
An Arabic edition of the project README lives at `../README_AR.md`.

### 5. Verify everything
```bash
python3 test_system.py        # 22 checks, ~2.5 minutes
```

## Moving to real hardware / GNS3

`config.yaml` is the ONLY file that changes: replace the simulation
endpoints with your real device addresses.

```yaml
devices:
  - {name: R1-Core,   endpoint: 192.168.20.1:161, kind: router}
  - {name: SW-HQ,     endpoint: 192.168.20.5:161, kind: switch}
```

Everything else — polling code, thresholds, traps, Telegram alerts — is
unchanged, because the agents expose the same Cisco OIDs
(`cpmCPUTotal5minRev`, `ciscoMemoryPoolUsed`, `ifOperStatus`, ...) that real
IOS answers with.

## Why an agent simulator alongside Packet Tracer?

Packet Tracer is a *simulator*: it faithfully models IOS configuration
(`snmp-server community`, trap hosts, `show snmp`) but its simulated network
stack is not reachable over a real UDP socket from an external Python
process. The graduation project therefore separates the two concerns:

| Concern | Where it lives |
|---|---|
| Network design, IOS SNMP configuration, syslog/NTP | Packet Tracer lab (.pkt) |
| Live SNMP data plane (real UDP, real BER, real OIDs) | agent_sim.py |
| Monitoring logic (polling, thresholds, traps, alerts) | monitor.py / bot.py |

The monitoring code is production-shaped: point it at real devices and it
just works.

## Repository layout notes

- `state.json` / `alerts.jsonl` / `bot_state.json` are runtime files created
  by monitor.py and bot.py — delete them any time for a fresh start.
- `test_results.json` holds the evidence from the last verification run.
