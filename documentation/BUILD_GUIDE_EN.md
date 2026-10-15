# How This Project Was Built — The Complete Engineering Narrative

This document records, step by step, how the Smart Network Monitoring
System was designed, built, and verified — and, more importantly, **why**
every significant decision was made the way it was. It is written so that
you (the student) can narrate the project as your own work during the
defense, and so that an examiner can trace any claim in the report back to
the decision that produced it.

The project follows the supervisor's four-step roadmap exactly:

| Roadmap step | Where it lives in this project |
|---|---|
| 1. Network management fundamentals + SNMP | Report Chapters 1–2; the engine speaks real SNMPv2c |
| 2. Simulation environment (roadmap said GNS3; we chose Packet Tracer) | The `.pkt` lab — Chapter 3–4 + this guide, Phase 2–3 |
| 3. Python polling + thresholds | `snmp_lite.py` + `monitor.py` — Chapter 5 + Phase 4–5 |
| 4. Telegram bot alerts + interactive commands | `bot.py` — Chapter 6 + Phase 6 |

---

## Phase 0 — Reading the roadmap as an engineering problem

**What we did.** We decomposed the supervisor's roadmap into five
measurable objectives (report §1.3) before writing a single line of code.

**Why.** A roadmap describes a *learning path*; a graduation project needs
*acceptance criteria*. Converting "learn SNMP polling" into "implement
SNMPv2c at protocol level with BER codec, zero external libraries, proven
by 22 automated checks" is what turned a study exercise into an
engineering artifact. Every later phase closes one objective, and the
verification phase (Phase 7) closes them all measurably.

**How to verify today.** Open the report, Chapter 1, objectives list —
each objective names its acceptance criterion and the chapter that proves it.

---

## Phase 1 — Choosing the simulation platform (and being honest about it)

**What we did.** We compared GNS3 and Cisco Packet Tracer 8.2 against four
criteria: technology (real IOS emulation vs behavior-level simulation),
licensing (IOS images are license-restricted vs free via Networking
Academy), footprint (RAM-heavy vs laptop-friendly), and — critically —
reachability of the SNMP stack from an external Python process.

**Why Packet Tracer.** The licensing and footprint criteria are decisive
for a student: the lab must open on any committee member's laptop with a
free download, and a twelve-device lab must run on it. GNS3 wins on
fidelity but loses on both.

**The honest boundary.** Packet Tracer faithfully models IOS
*configuration* (`snmp-server community`, `snmp-server host`, `show snmp`
all work exactly as documented), but its simulated network stack does not
bind real UDP sockets — an external Python program cannot poll a PT
router. We refused to hide this and refused to fake it. The design
response is the **two-plane architecture**:

- **Design plane** — the `.pkt` file: the full network, addressing,
  routing, VLANs, and SNMP policy, inspectable in Packet Tracer by anyone.
- **Live data plane** — six Python SNMP agents that expose *exactly* the
  Cisco OIDs, the same community (`MonNet-RO`), and the same trap host
  (`192.168.20.100`) that the lab file declares.

**Why this is legitimate engineering.** The monitoring code is
production-shaped and protocol-faithful; what it lacks is only a reachable
endpoint set. The agents provide real endpoints speaking the real protocol.
Moving to real Cisco hardware means editing host/port pairs in one YAML
file — nothing else changes. This argument is documented in report §3.2
and is the single most important thing to be able to defend in the viva.

---

## Phase 2 — Designing the network before touching any tool

**What we did.** We designed the topology, addressing plan, and SNMP
policy on paper first (report Tables 3.1–3.2), then implemented.

**The decisions and why:**

1. **OSPF area-0 triangle R1–R2–R3.** Any single link failure leaves two
   paths between any pair — the network *and the monitoring of it* survive
   a single cut. A hub-and-spoke core would have been simpler but would
   have made the lab teach the wrong lesson.
2. **Router-on-a-stick on R3-HQ (VLAN 10 users / VLAN 20 management).**
   One physical trunk carries two logical networks; management traffic
   (NMS polling, traps, syslog, NTP) is separated from user traffic — the
   standard production practice, at student scale.
3. **`/30` transit networks, `/24` user networks, loopbacks as OSPF
   router-ids.** Hierarchy that is documented and testable; loopbacks
   stabilize OSPF identity independent of any physical interface state.
4. **One SNMP policy on all six managed devices**: read-only community
   `MonNet-RO`, location/contact fields that surface as `sysLocation` /
   `sysContact`, trap host = NMS-PC, link/coldstart/config traps enabled.
   Read-only was a deliberate security posture: an RW community would
   expose SET (remote configuration change) — unnecessary for monitoring
   and a real vulnerability in v2c.
5. **Services plane**: SVR-MGMT (syslog + NTP at 192.168.20.50) so every
   event carries a comparable timestamp — a precondition for any later
   incident forensics.

**How to verify today.** Open the `.pkt` in Packet Tracer: `show snmp`,
`show ip ospf neighbor`, and a `ping` from NMS-PC to 192.168.30.1 — the
three-step in-lab verification printed in report §4.6.

---

## Phase 3 — Engineering the `.pkt` file itself

**What we did.** The lab file `Smart_Network_Monitoring_Lab.pkt` was
generated programmatically: the Packet Tracer file format (an obfuscated,
encrypted, compressed XML container) was reverse-engineered from its
documented public history, implemented in pure Python (Twofish-EAX with
the format's fixed key/IV domain separation, the XOR stages, and Qt-style
zlib compression), and used to emit a file built from verified PT 8.2.2
device structures — 12 devices, 12 links, full IOS configuration blocks.

**Why not click it together by hand.** Hand-built files are unbounded in
their error surface (a missed `no shutdown`, a typo'd community on one of
six devices). Programmatic generation made the whole lab *reviewable as
text* (the XML), *reproducible as code*, and *verifiable by script*: the
generator asserts XML well-formedness, unique device references, port
integrity, presence of all 12 `snmp-server community` lines, and the
final file round-trips byte-identically through the codec.

**How to verify today.** Open the file in Packet Tracer 8.2+ — devices,
links, and all IOS configs are present with zero manual steps. (The
generator scripts remain available in the project's build tooling; the
delivered artifact is the `.pkt` itself.)

---

## Phase 4 — SNMPv2c from scratch (`snmp_lite.py`)

**What we did.** We implemented the protocol, not a wrapper around one:
BER/ASN.1 encoding and decoding (TLV, definite lengths, the OID
base-128 sub-identifier rule with the 40×a+b first byte), GET and
GETNEXT request building, response parsing with error-status handling,
and SNMPv2c trap PDU encode/decode. Python standard library only.

**Why no pysnmp.** Three reasons. (1) *Defensibility*: a student who can
only call `pysnmp.get()` cannot explain one byte on the wire; a student
who wrote the codec can walk the committee through a hex dump. (2)
*Portability*: zero dependencies means the system runs on any Python
3.10+ with no install step beyond two small utility packages for the rest
of the engine. (3) *Testability*: the codec's round-trip property (encode
→ decode → identity) is self-evident when you own both ends.

**The self-test.** `python3 snmp_lite.py` runs the codec self-test: every
ASN.1 type used (INTEGER, OCTET STRING, NULL, OID, Counter32/64, Gauge,
TimeTicks, IpAddress, no-op) round-trips exactly. This became check 1.1
of the automated suite.

---

## Phase 5 — The monitoring engine (`monitor.py` + `agent_sim.py`)

**The agents (why simulate Cisco agents at all).** The live data plane
needed endpoints that behave like the routers in the lab file: same
sysName values, live cpu/memory/ifTable counters that move between polls,
trap emission on scripted incidents (link down/up, cold start, CPU
scenarios). `agent_sim.py` runs all six on UDP ports 1161–1166 with a
timed incident scenario for reproducible drills.

**The poller.** One cycle batches all objects for a device into a single
GET round (fewer round trips), writes the snapshot to `state.json`, and
feeds the threshold engine. A timeout marks the device DOWN —
*unreachability is itself an alert*, which is where many student
monitoring projects silently fail.

**The threshold state machine — the heart of the design.** Each
(device, metric) pair carries a state: OK → WARNING → CRITICAL, with
CPU thresholds 70/85% and memory 75/90%. **Alerts fire on transitions
only.** A critical condition that persists for 52 seconds produces
exactly one critical alert and later one recovery notice — not a stream
of duplicates. This is what makes the Telegram channel *inhabitable*:
every buzz on the phone means a state changed, never noise. Recovery
notifications close the loop: the operator learns when an incident ends,
not only when it begins.

**The trap receiver.** Listens on UDP 1620 (162 needs root on most OSes;
the offset is declared in config and used consistently by the agents).
Each received trap becomes an immediate alert — this is the
sub-second path (measured 0.4 s event→alert).

**Configuration.** Everything tunable lives in `config.yaml`: devices,
community, poll interval, timeout/retries, thresholds, trap destination,
Telegram settings. This single-file contract is what makes the
hardware-migration story real.

---

## Phase 6 — The Telegram bot (`bot.py`)

**What we did.** A control-plane bot: push alerts from the engine's
queue, plus interactive commands — `/status` (cached snapshot), `/cpu`
and `/ifaces` (live SNMP polls through the same snmp_lite client),
`/alerts` (audit log), `/mute`/`/unmute` (maintenance windows).

**Why long polling.** `getUpdates` with a 25-second timeout works behind
NAT and firewalls with zero inbound ports — the bot runs anywhere the
engine runs, including a laptop on campus Wi-Fi.

**The cached-vs-live split is deliberate.** `/status` answers from
`state.json` (costs nothing on the network); `/cpu` performs a real
on-demand GET. The two designs teach the classic trade-off: cached views
scale to many observers; live views are the tool for active triage.

**Security posture.** Chat-authorized only (the bot refuses unknown
chats); the token comes from the environment (`.env`), never the repo;
the community string never leaves the lab host. v2c's plaintext
authentication is a documented, accepted limitation with SNMPv3 as the
first roadmap item of future work.

---

## Phase 7 — Verification as a first-class deliverable

**What we did.** One command — `python3 test_system.py` — runs 22 checks
in ~2.5 minutes: protocol self-test, agent bring-up, a full timed
incident drill at 2× speed with a 5 s poll interval, and every bot
command including the unauthorized-chat refusal. Every claim in the
report maps to a named check; the last run's output ships in
`test_results.json` (Appendix C).

**The drill's measured results** (report Table 7.2):

| Incident | Event | Detected | Latency |
|---|---|---|---|
| R2 CPU 78% (warning) | 22.5 s | 23.8 s | **1.4 s** |
| R2 CPU 93% (critical) | 30.0 s | 33.9 s | **3.9 s** |
| R3 Gi0/0 link down (trap) | 40.0 s | 40.4 s | **0.4 s** |
| R1 memory 81% (warning) | 57.5 s | 58.9 s | **1.4 s** |
| R2 CPU recovery | 82.5 s | 83.9 s | **1.4 s** |

**Why this matters.** The trap path (0.4 s) versus poll path (1.4–3.9 s)
difference is the theory of the two planes *appearing in measurement*.
And the duplicate-suppression claim is numeric: 52 seconds of sustained
critical CPU → exactly one critical alert.

**How to re-verify.** `python3 test_system.py` — anywhere, anytime,
same result shape (timestamps differ, latencies stay in the same bands).

---

## Phase 8 — The optional web dashboard (`dashboard.py`)

**What we did.** A zero-dependency live status page (stdlib
`http.server`) that reads `state.json` + `alerts.jsonl` and serves an
auto-refreshing view at `localhost:8080`, plus a `/api/status` JSON
endpoint. Its own 7-check suite (`test_dashboard.py`) covers rendering,
threshold coloring, alert display, and both HTTP endpoints.

**Why it reads the snapshot instead of polling SNMP itself.** The
dashboard must never add load to the monitored network or compete with
the poller — so it is a pure *viewer* over the engine's state. This is
the same cached-view philosophy as the bot's `/status`, applied to a
browser.

**How to run.** `python3 dashboard.py` in a fourth terminal; open
`http://localhost:8080`.

---

## Phase 9 — Documentation and delivery

**What we did.** The project ships as a bilingual, self-contained
package: a 33-page English technical report (QA-passed) and its
full Arabic edition; a 17-slide English defense deck and its full Arabic
RTL edition (same design language); this build guide in both languages;
a viva Q&A preparation document in both languages; the complete source
with 22 + 7 automated checks; and the `.pkt` lab.

**Why bilingual.** The defense is delivered in Arabic; the engineering
vocabulary (SNMP, OID, BER, trap, threshold) is natively English. Each
edition is internally consistent — no mixed-language sentences — with
technical terms kept in English inside the Arabic text by explicit
policy, which is standard practice in Arabic technical writing.

**The one-page story for the committee.** A real protocol, implemented
byte by byte; a real network design, inspectable in Packet Tracer; a
real alerting pipeline with measured, reproducible latencies; and an
honest, documented boundary between simulation and live data — with a
one-file migration path to production hardware.
