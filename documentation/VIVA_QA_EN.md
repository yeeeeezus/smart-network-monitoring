# Viva Preparation — Anticipated Questions and Strong Answers

Fifteen questions a graduation committee is most likely to ask about this
project, each with a grounded answer you can deliver from memory. Rehearse
them out loud; every number below is real and reproducible.

---

**Q1. Why did you choose Packet Tracer instead of GNS3 as the roadmap suggested?**
GNS3 emulates real IOS images — higher fidelity — but it requires
license-restricted IOS images and is RAM-heavy for a twelve-device lab.
Packet Tracer is free through Cisco Networking Academy and runs the whole
lab on a laptop. The decisive extra fact: PT models IOS *configuration*
faithfully (all `snmp-server` commands work, `show snmp` reports them) but
its simulated stack is not reachable over real UDP from an external
process. So I paired PT as the design plane with six protocol-faithful
SNMP agents as the live data plane — same Cisco OIDs, same community, same
trap host. Migration to real hardware is a YAML edit.

**Q2. If Packet Tracer isn't reachable, is this "real" monitoring?**
The monitoring code is real: it speaks SNMPv2c at the protocol level I
implemented myself, polls real UDP endpoints, receives real trap PDUs, and
measures real detection latencies (0.4 s trap-to-alert). What is simulated
is the *endpoint set*. The boundary is documented, not hidden, and the
code is production-shaped: change host/port pairs in one config file and
it targets real routers.

**Q3. Why implement SNMP yourself instead of using pysnmp?**
Three reasons. Defensibility: I can walk you through every byte of a GET
request — version, community, PDU, the BER TLV structure — because I wrote
the codec. Portability: zero dependencies beyond two small utility
packages. Testability: the encode→decode round-trip property is
self-evident when I own both ends, and it is check 1.1 of my suite.

**Q4. Explain BER encoding in one minute.**
BER is ASN.1's basic encoding: every field is Type-Length-Value. The type
byte identifies the ASN.1 tag (0x02 INTEGER, 0x04 OCTET STRING, 0x06 OID,
0x30 SEQUENCE...). The length is one byte for values under 128, or the
long form (0x81/0x82...) for bigger ones, big-endian. An OID encodes its
first two sub-identifiers as 40×a+b in one byte, then each remaining
sub-identifier in base-128 with continuation bits. A whole SNMP message
is nested TLVs: SEQUENCE(version, community, PDU).

**Q5. Why do alerts fire on transitions only?**
A threshold crossing that persists is one incident, not many events. My
state machine keeps a state per (device, metric) — OK, WARNING, CRITICAL
— and alerts only when the state changes, with a recovery notice when it
clears. In the drill, 52 seconds of sustained critical CPU produced
exactly one critical alert. Without this, a 15-second poll interval over a
5-minute incident would spam the operator with ~20 identical messages and
train them to mute the channel.

**Q6. Polling versus traps — when do you rely on each?**
Polling gives me trends and threshold detection on *any* metric I choose,
at a latency bounded by the poll interval (measured 1.4–3.9 s at a 5 s
interval). Traps give me sub-second notification of *events the device
knows about* — link down/up, cold start (measured 0.4 s) — but only those
the agent is configured to send. So: degradation (CPU, memory creeping
up) is a polling job; discrete failures are a trap job. The engine uses
both planes.

**Q7. What exactly is a community string and what are its risks?**
In SNMPv2c it is a plaintext password sent in every message. Mine is
`MonNet-RO`, read-only: an attacker who learns it can read MIB values but
cannot send SETs. I deliberately avoided an RW community — that would
expose remote configuration changes. The real fix is SNMPv3's USM
(authentication + privacy), which is my first future-work item; the engine
is modular enough to add it at the message-processing layer.

**Q8. Walk me through 1.3.6.1.4.1.9.9.109... — what does that OID mean?**
1 = iso, 3 = org, 6 = dod, 1 = internet — the standard root. 4 =
private, 1 = enterprises, 9 = cisco: from here we are in Cisco's vendor
tree. 9.109 is the CISCO-PROCESS-MIB; the full value ends at
cpmCPUTotal5minRev — the 5-minute CPU average I poll. My Table 2.1 lists
every OID the engine uses with its meaning.

**Q9. Why 15 seconds as the production poll interval?**
It is a load-vs-freshness trade-off. Detection latency for polled metrics
is bounded by the interval; 15 s across six devices is trivial bandwidth
(one batched GET per device) while keeping worst-case detection for slow
degradation well under a minute. For the drill I used 5 s to compress the
timeline, and the measured latencies scaled exactly as theory predicts:
0 to interval plus processing.

**Q10. Why Telegram rather than email or SMS?**
Delivery latency and interactivity. Email arrives in minutes and is
batched by clients; SMS costs money per message and has no command
channel. The Bot API is free, pushes in under a second, works over
plain HTTPS long polling (no inbound ports — runs on campus Wi-Fi), and
gives me a two-way console: /status, /cpu, /ifaces, /alerts, /mute. The
operator carries the NMS in their pocket.

**Q11. How is the bot secured?**
Chat authorization: a whitelist in config; any other chat gets refused.
The token is read from an environment variable, never committed — the
repo ships a .env.example template. The community string never leaves the
lab host. Alerts themselves contain no credentials.

**Q12. What happens if the monitoring host itself dies?**
That is the single point of failure in this architecture, and I am
honest about it: everything — poller, trap receiver, bot — runs on one
host. The data to detect it exists (devices stop being polled; agents'
counters freeze), but nothing alerts on it today. Production answer:
systemd auto-restart plus a second lightweight watchdog, or two monitors
splitting the device list — straightforward extensions of the same code.

**Q13. What did you deliberately NOT build?**
SNMPv3 security (future work #1); time-series storage and dashboards like
Grafana (future work #2 — though I added a zero-load snapshot viewer);
anomaly detection with learned baselines (future work #4 — the engine
already produces the data structure it needs); and multi-host
distribution. The scope was chosen so that everything built is built to
production shape, rather than everything sketched.

**Q14. Your report says 22 automated checks — what do they actually prove?**
Phase 1: the BER codec round-trips every type I use. Phase 2: all six
agents answer GETs, my walk returns full interface tables, counters move
between reads. Phase 3: the timed incident drill — warning, critical,
link-down trap, memory warning, recovery — with detection latencies
measured per alert, plus duplicate suppression (52 s sustained critical →
1 alert). Phase 4: every bot command, including the unauthorized-chat
refusal. One command, 2.5 minutes, rerunnable anywhere — that is the
difference between "works on my machine" and verified.

**Q15. If we gave you real Cisco routers right now, how long to move this?**
Change six host/port pairs in config.yaml from the local agent ports to
the routers' addresses with port 161, set the trap destination to the
monitor host's address, and run. The code, thresholds, alerting logic,
bot, dashboard, and tests are unchanged. That was the design contract
from Phase 1.
