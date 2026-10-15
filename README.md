# Smart Network Monitoring System — Graduation Project Package

SNMP-based network monitoring with a Telegram alarm channel, on a simulated
Cisco enterprise network. Everything in this package opens, runs, and was
verified end to end (22/22 core checks + 7/7 dashboard checks).

> Arabic edition of this file: `README_AR.md` — كل الوثائق متوفرة بلغتين.

## Package contents

| Item | Path | What it is |
|---|---|---|
| Packet Tracer lab | `packet-tracer/Smart_Network_Monitoring_Lab.pkt` | 12 devices, opens pre-configured in PT 8.2+ |
| Technical report (EN) | `documentation/Smart_Network_Monitoring_Report_EN.pdf` | 33 pages, 9 chapters + 3 appendices |
| Technical report (AR) | `documentation/Smart_Network_Monitoring_Report_AR.pdf` | full Arabic edition, 21 pages (+ HTML source) |
| Defense presentation (EN) | `documentation/Defense_Presentation_EN.pptx` | 17 slides with speaker notes |
| Defense presentation (AR) | `documentation/Defense_Presentation_AR.pptx` | full Arabic RTL edition, same design language |
| How it was built & why | `documentation/BUILD_GUIDE_EN.md` (+ `_AR`) | phase-by-phase engineering narrative |
| Viva preparation | `documentation/VIVA_QA_EN.md` (+ `_AR`) | 15 anticipated questions with grounded answers |
| Report figures | `documentation/figures/` | topology, SNMP model, architecture (PNG, reusable) |
| Monitoring system | `monitoring-system/` | complete Python source + tests + web dashboard |
| Verification evidence | `monitoring-system/test_results.json` | results of the last 22-check run |

## The 60-second tour

1. **Open the lab** — double-click the `.pkt` file. Click R1-Core → CLI →
   `show snmp`. Every router and switch carries the same SNMP policy.
2. **Read the report** — Chapter 3 (design) → Chapter 5 (engine) →
   Chapter 7 (measured results).
3. **Run the system** — see `monitoring-system/README.md`: three commands,
   and alerts arrive on your phone (bot token required, BotFather, 5 minutes).
4. **Open the live dashboard** — `python3 dashboard.py` → `http://localhost:8080`.

## What was verified (highlights)

- 22/22 automated end-to-end checks pass (`python3 test_system.py`)
- 7/7 dashboard checks pass (`python3 test_dashboard.py`)
- Trap-to-alert latency measured at **0.4 s**; poll-to-alert 1.4–3.9 s at a
  5 s interval (production default 15 s)
- Exactly **one** critical alert during a 52-second sustained incident —
  transition-only alerting, zero duplicates
- The `.pkt` file round-trips byte-identically through the Packet Tracer
  file format codec used to generate it

## Where to fill in your details

- Report cover: `[University Name]`, `[Student Name]`, `[Student ID]`,
  `[Supervisor Name]`, `[Faculty]`, `[Department]`
- Slide 1 of both presentations (EN and AR): same placeholders
- Arabic report cover: `[اسم الجامعة]` و`[اسم الطالب]` و`[اسم المشرف]`
- `monitoring-system/.env.example` → your own bot token and chat id

## Honest engineering note

Packet Tracer is a simulator: its devices configure SNMP faithfully but are
not reachable over real UDP sockets from an external program. This project
therefore pairs the PT lab (the design plane) with six protocol-faithful
SNMP agents (the live data plane) exposing the same Cisco OIDs, community,
and trap host. The monitoring code is production-shaped: to target real
routers you change endpoint addresses in one YAML file — nothing else.
