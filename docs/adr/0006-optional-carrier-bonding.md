# ADR 0006 — Optional carrier bonding for the layer-3 engine

Status: **Accepted — phase 1 implemented** behind the `[l3.bond] experimental = true` flag (see "Implementation notes")
Date: 2026-10-26 (proposed), 2026-10-27 (phase 1)
Supersedes: none. Related: [0001](0001-reverse-transport-generations.md) (generations), the l3 package doc (`internal/tunnel/l3/doc.go`), and the existing `multipath` carrier (`internal/tunnel/l3/multipath.go`).

---

## Context

A single tunnel between two servers rides one carrier, which is one flow. On the
routes this product exists to cross, one flow is exactly what a censor's shaper
counts, rate-limits, and — once it has carried enough — blocks. The field
evidence is consistent: a low-volume flow survives for months while a
high-volume flow to the same kind of endpoint dies in hours, because the trigger
is sustained per-flow rate, per-IP cumulative volume, and flow behaviour, layered
on top of protocol/SNI detection. A single carrier also has a single failure
mode: when the one path it uses is filtered, the whole tunnel is down.

The engine already has two partial answers:

- **`multipath`** (`internal/tunnel/l3/multipath.go`) spreads the **plain UDP**
  carrier over several sockets on consecutive ports. It is datagram-only,
  udp-only (refused for every other carrier at `config.go:231-238`), homogeneous
  (one carrier type), and has **no health model**: a path is considered dead only
  when a write returns an error (`multipath.go:243-248`). A filtered path whose
  writes still succeed keeps taking its share of traffic and dropping it — a
  permanent loss of 1/N of the tunnel with nothing to detect it.
- **Health-scored failover** (`internal/utils/network/healthscore.go`, score
  `rtt + 2*jitter + 20*loss`, 15%/3-check hysteresis) exists **only in the reverse
  client**, steers new connections, and does not migrate live ones. The l3 engine
  has none of it.

We want one tunnel to run several **heterogeneous** carriers at once — and in
**both directions at once** (a dial-mode ICMP path and a listen-mode ICMP path in
the same tunnel, which the field evidence shows matters because one-way ICMP
filtering is real) — select the healthy ones by real measurement, spread traffic
intelligently, and survive the loss of any subset without dropping the session.

This ADR records the carrier contract we are building against, which carriers are
eligible and why, and the design of the new optional **`bond`** carrier.

---

## The capability constraint (why bonding lives in l3, over datagram carriers only)

A bond splits the tunnel's traffic across paths and the far end reassembles. For
that to be correct, every path must carry **independent, unreliable, unordered
datagrams**: the l3 session above already provides its own AEAD, explicit nonce,
and a 2048-counter replay window (`session.go`, `replay.go`) that absorbs the
reordering several paths produce. Putting the tunnel on anything that retransmits
stacks two ARQ timers on one path and collapses throughput under loss — the
TCP-over-TCP meltdown the package doc forbids (`doc.go:31-40`).

From the code audit, every transport/carrier in the tree falls into one of two
classes:

| Class | Members | Bond-eligible? |
|---|---|---|
| **Datagram, unreliable, unordered** (l3 carriers) | `udp`, `pck`, `sni`, `xdi`, `spoof`, **`quic` (RFC 9221 DATAGRAM frames)** | **Yes** |
| **Reliable, ordered streams** | every reverse transport (`tcp`, `stealth`, `tcpmux`, `ws`/`wss`/mux, `kcp`, reverse-`xdi`/`pck` = KCP+smux, reverse-`quic` = **streams**), and the direct engine (smux over TCP/stealth/ws/wss) | **No** |

This settles a question raised in design discussion: a "reverse ICMP + direct
ICMP" bond does **not** mean bridging the reverse engine and the l3 engine. The
reverse `xdi` transport is KCP (reliable, ordered, with smux HOL across streams)
and cannot be packet-bonded. "Direct and reverse at once" is instead realised as
**two l3 `xdi` carriers with opposite `mode`** inside one bond (see D2). The three
engines keep sharing no code, per the architecture doc.

Confirmed carrier facts the bond relies on (from the audit, `file:line` in the
source):

- **`quic` l3 carrier uses `SendDatagram`/`ReceiveDatagram`, never `OpenStream`**
  (`carrier_quic.go:481,402,430`; `EnableDatagrams:true` at `:100`). A lost
  packet does not delay later ones. **Caveat:** quic-go's `SendDatagram` can
  **block** when its send queue is full; the bond must never let one path's send
  block another's (see D1, isolation).
- **Two `xdi` carriers in opposite directions on one host do not collide**, with
  the same or different token: the dialler socket reads only replies carrying its
  own echo id, the listener reads only requests, a raw socket never sees the
  host's own egress, the kernel auto-reply carries direction byte `C` while the
  dialler accepts only `S`, and the three iptables rule strings differ
  (`icmpconn_linux.go`, `icmpguard_linux.go`, `icmpframe.go`). This is the
  property that makes D2 possible.
- **What breaks and must be designed around:** two `xdi` paths in the **same**
  direction can draw the **same echo id** (per-process random allocator,
  `icmpframe.go:85-88`) and two `xdi` **listeners** with one token both accept
  every request; `pck` paths on the **same port** self-capture each other's and
  the host's own segments (no `PACKET_IGNORE_OUTGOING`, BPF matches dst port
  only); `spoof` derives one token-keyed port for both directions and cross-feeds
  or hits `EADDRINUSE`. These bound which combinations a bond may hold (see
  "Per-carrier constraints").

---

## Decision

### D1 — The bond is a `DatagramCarrier`; the session and the pumps do not change

`bond` implements the existing `DatagramCarrier` interface (`net.PacketConn` +
`Overhead()` + `CarrierName()`, `carrier.go:27-37`) and, like `multipath`, the
optional batch interfaces. It is constructed by `openBareCarrier`
(`carrier.go:208`) when `carrier = "bond"`, wrapped by FEC exactly as every other
carrier is (`carrier.go:196-203`), and handed to the `Tunnel` which reads and
writes it through the same two pumps (`tunnel_pumps.go`). **Nothing in
`session.go`, `tunnel.go`, `tunnel_pumps.go`, or the handshake changes.** The
session's AEAD, replay window, rekey, and MTU probe all continue to work because
to them a bond is just a carrier that happens to drop and reorder a little more.

Isolation requirement: each sub-path has its own send goroutine/queue. A path
whose write blocks (quic full queue) or stalls must never hold up another path's
sends; the scheduler simply stops choosing a path that is not draining.

### D2 — Per-path carrier **and** per-path mode (this is "direct + reverse at once")

A bond path is `{carrier, mode, carrier-params}`. `mode` is per **path**, not per
tunnel: one path may be `dial` (this host sends ICMP echo requests — "direct"
direction) while another is `listen` (the peer dials in, this host replies —
"reverse" direction), in the **same** tunnel. This is the required "reverse ICMP +
direct ICMP simultaneously", built entirely inside l3.

The tunnel's handshake role stays one per host (the existing `Mode`: the
initiator seals `typeInit`, the responder answers). This is **decoupled** from
each path's socket direction. Bootstrapping rule: the bond must hold **at least
one path over which the initiator can send the first handshake datagram now** — a
`dial` path from the initiator, or a `listen` path the peer has already reached.
Listen-only-on-initiator with no inbound yet is refused at validation with a
message that says why, rather than coming up and carrying nothing (the failure
mode `config.go` already guards against elsewhere).

### D3 — Authenticated per-path probe, handled entirely inside the bond

Silent-failure detection (the headline requirement) and peer-address
authentication are solved by one mechanism: a small **probe** the bond sends on
each path and whose ack it expects back on that path.

- **Key:** `probeKey = HKDF-SHA256(token, "backpack-l3-bond-probe-v1")`, a
  dedicated label, domain-separated from the session PSK (`"backpack-l3-psk-v1"`)
  and from the `xdi`/`pck`/`spoof` tag labels, in the spirit of `session.go`'s
  domain separation. The bond is already constructed with the token (carriers
  take it today).
- **Wire shape:** a probe/ack datagram opens with a magic first byte **outside
  the l3 `kind` range `1..5`** (`wire.go`), followed by a path id, a nonce, a
  timestamp, and an HMAC over all of it under `probeKey`. Because real l3
  datagrams always start with `kind ∈ 1..5`, and the bond consumes probe
  datagrams before passing anything up, probes and tunnel data are never
  confusable in either direction.
- **Interception:** the bond's `ReadFrom` loop checks each datagram: magic byte +
  valid HMAC → handle internally (record RTT, mark the path alive, and on a
  `listen` path update that path's learned peer address) and **do not** pass it
  up; otherwise hand it to the tunnel unchanged. A forged datagram with the magic
  byte but a bad HMAC is dropped by the bond — never acted on, never passed up.
- **What it buys:**
  1. **Silent-failure detection.** A path whose probes stop being acked is marked
     down **even though `WriteTo` keeps succeeding** — the exact case `multipath`
     misses today and the reason 1/N of a bonded tunnel would otherwise vanish.
  2. **Peer-auth before address change.** A `listen` path accepts or moves its
     peer address **only** from an authenticated probe, never from an arbitrary
     datagram. This closes the `pinnedCarrier` hole (`carrier.go:309-349`, which
     learns peer from unauthenticated packets) for bonded paths.
  3. **Live RTT/jitter/loss per path**, feeding D4.

Probes are separate small datagrams, not per-packet framing, so **`Overhead()` is
unaffected by them** and the data path stays zero-overhead passthrough.

### D4 — Quality-based flowlet scheduler (no malicious reordering, no HOL)

Paths differ in RTT (e.g. `xdi` ~40 ms vs `pck` ~90 ms). Round-robin per packet
across paths of unequal RTT reorders the inner TCP/game traffic, produces
duplicate-ACKs, and collapses throughput — and the reorder depth a bond may
produce is bounded by the session replay window (2048), so unbounded spreading is
also a correctness limit, not only a performance one.

The scheduler is therefore **flowlet-based**, reusing the proven reverse-engine
scoring:

- Each path has a score `rtt + 2*jitter + 20*loss%` from its probes
  (`healthscore.go` formula), lower is better.
- A **flowlet** is a run of packets with no gap larger than the max inter-path
  RTT delta. Within a flowlet, packets stay on one path (no reordering). At a gap
  larger than the delta — where reordering can no longer occur — the scheduler may
  move to another path, weighted by score. This spreads load across paths and IPs
  without reordering a single flow's in-flight packets.
- **Hysteresis + backoff** (requirement): a path must beat the current choice by
  ≥15% for 3 consecutive probe intervals before it is preferred (the reverse
  engine's anti-flap rule); a path that fails re-enters service only after a
  backoff that grows on repeated failure (e.g. 30 s → 5 min), so a flapping path
  does not thrash the tunnel.
- Deliberate reordering is never introduced; the replay window absorbs only the
  incidental interleave two live paths cause.

### D5 — MTU is the minimum the paths can carry (max overhead)

`Overhead()` must return the **maximum** overhead across member paths, so the
interface MTU (`MTUFor`, `config.go:328`) is sized for the smallest path. The
heterogeneity is real: `udp` 28 (v4), `xdi` 33, `pck`/`sni` 52, `quic` 60, plus
AEAD 29 and encap. `multipath` returns `paths[0]`'s overhead
(`multipath.go:443`), correct only because its paths are homogeneous; the bond
must not copy that. Getting this wrong reproduces the exact "handshake ok, then
downloads stall" black-hole the engine warns about — large packets silently
dropped on the narrowest path.

### D6 — Discovery / health-check before a path enters service

On start, every configured, permitted path is opened and **probed** before it
carries tunnel data; only paths that pass (probe acked, within RTT/loss/MTU
bounds) enter the scheduler. A path that fails is held out and **re-probed on the
backoff of D4**, so a path that comes back (e.g. ICMP reopened during a crackdown)
is picked up automatically. The discovery results — per-path RTT, jitter, loss,
measured MTU, direction, pass/fail and reason — are recorded in the metrics
snapshot (D-stats) and surfaced in the wizard/panel, so an operator sees which
carriers actually work between **their** two servers (the "test between the two
servers" requirement).

### D7 — Optional, feature-flagged, off by default, inert when unused

`bond` is a new carrier value; absent it, every existing tunnel behaves exactly
as today (the `multipath` precedent: a single carrier is returned untouched,
`multipath.go:131-133`). The feature is gated so that **bonding cannot be enabled
without health-check + silent-failure detection** — there is no config path that
turns on multi-path spreading while leaving D3/D6 off, because a bond without them
is the 1/N-silent-loss bug by construction. One process per tunnel is preserved
(D1 adds goroutines inside the existing process, not new processes).

---

## Per-carrier constraints the bond enforces (from the audit)

These are validated up front (like every other l3 misconfiguration) rather than
discovered as a silent half-working tunnel:

- **`xdi`:** every `xdi` path in a bond gets a **distinct echo id** (the
  per-process allocator can repeat; the bond assigns explicitly). **At most one
  `listen`-mode `xdi` path per bond per host** (two listeners with one token both
  accept every request and cross-feed). Opposite-direction `xdi` (one dial, one
  listen) is explicitly supported — this is the headline feature — and is
  collision-free per the audit.
- **`pck`:** mixed-direction or multiple `pck` paths must use **distinct tunnel
  ports**; same-port `pck` self-captures the host's own egress and, with one
  token, the dialler's handshake is valid input to the local listener
  (`pckframe.go` BPF matches dst port only, no `PACKET_IGNORE_OUTGOING`). All
  `pck` paths run in the one tunnel process, so the per-netns+id `flock` ownership
  is satisfied (it fails only across processes).
- **`spoof`:** **not permitted in opposite directions within one bond** (one
  token-derived port both ways → `EADDRINUSE` or cross-feed, no on-wire tag to
  tell paths apart). A single `spoof` path is fine.
- **`quic`:** each quic path owns its send goroutine so a blocked `SendDatagram`
  cannot stall the bond (D1). The listener's shared 512 inbox is per quic carrier,
  unchanged.
- **No NIC pinning** exists for `xdi`/`quic`, so two such paths to the same peer
  IP take the same route and buy little diversity; the wizard warns and steers
  toward different peer IPs / different carriers for genuine path diversity.

---

## Data plane

```
TUN ─▶ pumpFromTUN ─▶ session.seal ─▶ bond.WriteTo/WriteBatch
                                         │  flowlet scheduler (D4)
                                         ├─▶ path 0  (e.g. xdi dial)
                                         ├─▶ path 1  (e.g. xdi listen)
                                         └─▶ path k  (e.g. pck :port2)
peer ◀───────────────────────────────────┘  each path: own send queue (D1)

bond.ReadFrom ◀── merge all paths ──▶ intercept probe/ack (D3) or pass up
         │
         ▼
   pumpFromCarrier ─▶ route by kind ─▶ session.open ─▶ TUN
```

The merge, the per-path send isolation, the pinned-and-authenticated peer per
path, and the "one address reported upward" rule are adapted from `multipath`
(`multipath.go`), whose `reported`/`stableAddr` design already solves "several
ports must not read as a peer moving every packet" — extended so the learned
address comes only from an authenticated probe.

## Control plane / failover model

Failover is **autonomous**, inside the engine process, with **no dependency on
the panel or any control plane** (requirement). The probe loop (D3), the scheduler
(D4), and the discovery/backoff (D6) all run in the `Tunnel`'s own goroutines
under the generation context (`tunnel.go:406-438`). The panel only *reads* the
per-path stats from the snapshot; it never has to act for the tunnel to recover.
Live sessions are preserved across path loss as far as the protocol allows:
losing a path loses only its in-flight datagrams (the session's ARQ-free layer
expects that), and the session itself — keys, counters, peer — is untouched while
any path survives.

## Configuration (sketch; finalised in phase 1)

```toml
[l3]
mode    = "dial"            # the handshake role for THIS host
token   = "…"
carrier = "bond"
local_ip = "10.10.0.1/30"
peer_ip  = "10.10.0.2"

  [[l3.bond.path]]
  carrier = "xdi"
  mode    = "dial"          # direct-direction ICMP
  addr    = "KHAREJ:0"

  [[l3.bond.path]]
  carrier = "xdi"
  mode    = "listen"        # reverse-direction ICMP, same tunnel
  addr    = "0.0.0.0:0"

  [[l3.bond.path]]
  carrier = "pck"
  mode    = "dial"
  addr    = "KHAREJ:9100"   # distinct port per pck path
```

The Setup Link carries the whole path set so the two ends never disagree (the
existing `backpack://` link mechanism). Validation enforces the per-carrier
constraints above before anything is opened.

## Test plan (simulation results reported separately from real-network results)

- **Unit:** probe encode/decode + HMAC reject; scheduler flowlet boundaries and
  score/hysteresis; `Overhead()` = max; per-carrier validation rejects the unsafe
  combinations (same-port pck, two listen-xdi, opposite-direction spoof);
  bootstrap refusal when no path can carry the first handshake.
- **Integration (netns, Linux):** a bond of `udp`+`xdi`(dial)+`xdi`(listen)
  between two network namespaces carries a stream; killing one path mid-transfer
  keeps the session up and shifts traffic; a **silently black-holed** path (writes
  succeed, nothing delivered) is detected by probe loss and removed — the test
  that would have caught the `multipath` gap.
- **Race:** `-race` over the scheduler, the per-path send isolation, and the
  shared merge/inbox.
- **Failure injection:** per-path loss/latency/stall injected via a wrapping
  carrier (the `wrapCarrier` hook already exists, `tunnel.go:218,346-348`);
  assert no reordering within a flowlet and bounded reorder across paths (within
  the replay window).
- **Bench gates:** the existing allocation/wall-clock gates
  (`bench_gate_test.go`) extended to the bond data path.
- **Real two-server test:** run only where two hosts are available; its numbers
  are reported **separately and labelled as real-network**, never merged with the
  loopback/netns figures (the performance-notes discipline).

## Rollback

`bond` is additive: a new carrier value, a new file set, and config that no
existing tunnel emits. Rollback is removing the `bond` path table (or the build);
every other carrier and the whole reverse/direct engine are untouched because
they share no code with it. If a bonded tunnel misbehaves, switching its carrier
back to a single `udp`/`xdi`/`pck` is a one-line edit and a restart.

## Implementation notes (phase 1, 2026-10-27)

Code: `internal/tunnel/l3/bond.go` (carrier, per-path queues, control loop,
scheduler), `bond_probe.go` (D3 wire + key), `bond_health.go` (state machine),
`bond_config.go` (validation), `config/l3.go` (`[l3.bond]`, `[[l3.bond.path]]`).
Touched outside the new files, each one line or a pure refactor: `carrier.go`
(the `bond` case in `openBareCarrier`), `config.go` (Config.Bond, validation
order, table mapping), `tunnel.go` (`New` hands the tunnel's logger to the bond),
`mtuprobe.go` (see MTU below), `carrier_obfuscated.go` (`spoofOverhead` factored
out of `openSpoof` so a bond can count it before the carrier is open). `session.go`,
`tunnel_pumps.go`, the handshake and the replay window are unchanged.

Where the build differs from the decisions above, and why:

- **Feature flag (D7).** `carrier = "bond"` is refused unless `[l3.bond]
  experimental = true`. Bond paths set under any other carrier are refused too,
  rather than silently ignored. There is no flag that enables spreading without
  probes: the probe loop and the scheduler are the same code path.
- **Scheduler (D4) — tiered flowlets instead of gap-only flowlets.** A gap-based
  flowlet cannot spread a continuously busy tunnel (an aggregate of many flows
  rarely pauses for a whole RTT delta), and switching only towards slower paths
  drifts the tunnel onto the slowest one. The build instead anchors on the
  best-*score* path (so a fast but lossy path does not pull traffic onto itself)
  and forms a **tier** of in-service paths whose smoothed RTT is within
  `max(anchor/8, 2 ms)` of the anchor. Traffic rotates over the tier in 64 KiB
  flowlets by smooth weighted round-robin, weights ∝ 1/score. Reordering between
  tier members is bounded by a fraction of the RTT, inside what RACK (RFC 8985)
  absorbs without retransmitting; paths outside the tier are hot standby —
  probed, ready, and used the moment the tier empties. Hysteresis (15 % for 3
  rounds) is applied to the score each path is weighed by.
- **Backoff.** 5 s doubling to 5 min (ADR sketch: 30 s → 5 min). The commonest
  failure is a short blip; a path down for two seconds should not idle for thirty.
  The cap is still reached after seven consecutive failures; it resets once a path
  has stayed up for a minute.
- **Discovery (D6).** A path enters service after 3 consecutive answered probes,
  at least one of them **full-size** (padded to the configured MTU's datagram:
  `mtu + encap + 29 (+8 FEC)`). Discovery probes run at a quarter of the probe
  interval; in service, one probe per interval and one in ten full-size. Out of
  service when: no answer for 3 intervals + timeout ("silent"), ≥ 50 % loss over
  the last 20 probes, or 3 full-size probes lost while small ones are answered
  ("MTU shrank"). A listening path starts discovery only once its peer has
  probed it.
- **MTU (D5) and AutoMTU.** `Overhead()` is the maximum over every configured
  path (an estimate by carrier kind for a path not yet open). An AutoMTU probe
  crosses one path only, so for a bond the search ceiling is capped at the
  configured MTU (`mtuprobe.go`); the bond's own full-size probes guarantee
  every in-service path carries that size. Lowering still works.
- **Probe replay (D3).** A probe is answered, and may move a listening path's
  peer, only if it is the first, carries a higher sequence from the instance
  already followed, or comes from a new instance (peer restart) after the old one
  has been quiet for 3 intervals. Answers are matched to an outstanding probe and
  counted once. A listening path drops data until its peer has authenticated.
- **xdi echo id.** The ADR's concern about repeated echo ids is already handled:
  `acquireXdiSessionID` (`icmpframe.go`) draws from a per-process set, so a
  collision is impossible. Only the "one listening xdi per bond" rule is enforced.
- **Path open failures.** Paths open in parallel; one that fails (a QUIC peer not
  yet reachable, a missing capability) is held down and reopened on the backoff,
  as is a path whose carrier later closes. Only "no path opened at all" fails the
  generation, which hands over to the tunnel's existing restart.

Not yet built (later phases): the `backpack://` Setup Link carrying the path
set, the wizard/panel view of per-path stats (`PathStats()` exists for it), the
metrics-snapshot export, netns integration tests over real `xdi`/`pck`
(Linux + CAP_NET_RAW), a bench gate for the bond data path, and the real
two-server test.

## Test results (phase 1)

**Simulated — loopback, Windows 11 dev host, Go 1.26.9.** The `network`
package does not compile on Windows (pre-existing, unrelated to this change), so
the suite ran on a scratch copy with five `syscall` casts patched; the project
itself was not modified for this. Raw carriers cannot run there, so bond paths
were plain `udp`, which exercises the same bond code (a path's *mode*, not its
carrier, makes it direct or reverse).

| Test | Result |
|---|---|
| 32 bond tests (unit, config, integration with fault injection, full tunnel over a bond) | pass |
| same, `-race`, `-count=3` | pass, no races |
| whole `l3` package, `-race` | pass except `TestAUDPListenerThatCannotBindIsReported`, which expects Linux's "address already in use" text (Windows words it differently; the test is about the forwarder, not the bond) |
| `config` package | pass (reference regenerated) |
| `FuzzParseBondMsg`, 20 s | ~860 k execs, no failure |
| silently black-holed path taken out (probe interval 100 ms) | ~0.8 s |
| `GOOS=linux go vet` / `go build ./...` | clean |

Fault-injection cases covered: silent black hole (writes succeed, nothing
delivered), path that drops datagrams above 400 bytes (held out with an MTU
reason), path whose writes block forever (sender never blocks; traffic spills to
the other path; the stuck one is taken out), recovery after the backoff, one
direct + one reverse path with the direct one failing, forged/replayed/
unauthenticated probes and data on a listening path, partial open failure.

**Real network — not run.** No two-server measurement has been made. The
loopback figures above are not network measurements and are not to be quoted as
such.

## Rejected alternatives

- **Bond at the session layer (paths visible to `session.go`).** Rejected: it
  would thread a path id through seal/open/replay and the pumps, touching the most
  security-sensitive, most-tested code in the package for a feature that an
  isolated carrier delivers. D1/D3 keep the blast radius at the carrier.
- **Bridge the reverse engine's transports into the bond.** Rejected: they are
  reliable ordered streams; packet-bonding them is the TCP-over-TCP meltdown the
  package forbids, and it would fuse two engines the architecture keeps
  code-disjoint. "Direct + reverse" is delivered by per-path `mode` instead (D2).
- **Extend `multipath` in place.** Rejected: `multipath` is deliberately
  udp-only, homogeneous, and health-free; bolting heterogeneous carriers, probes,
  and a scheduler onto it would make one type do two jobs. `bond` is the second,
  richer thing; `multipath` stays the simple one.
- **ML/behavioural path selection.** Rejected for the same reason the project
  rejected ML traffic classification (design-decisions MISC-10): the scheduler
  must be legible and testable. Score + hysteresis is the legible version.

---

<div dir="rtl">

## خلاصهٔ فارسی

**مسئله:** یک تونل روی یک حامل = یک جریان، و یک جریان دقیقاً همان چیزی است که
شکل‌دهندهٔ ترافیک ایران می‌شمارد، throttle می‌کند و بعد از رسیدن به آستانهٔ حجمی
می‌بندد. به‌علاوه یک حامل یک نقطهٔ خرابی دارد. الان دو پاسخ ناقص داریم:
`multipath` که فقط UDP، فقط هم‌نوع، و **بدون مدل سلامت** است (مسیری که بی‌صدا
فیلتر شود ولی نوشتنش موفق باشد، برای همیشه ۱/N ترافیک را گم می‌کند)، و
failoverِ امتیازدهی‌شده که فقط در موتور ریورس هست.

**تصمیم:** یک حامل اختیاری جدید به نام **`bond`** در موتور l3، که:
- **(D1)** خودش یک `DatagramCarrier` است، پس جلسه و pumpها **اصلاً تغییر
  نمی‌کنند** و FEC/MTU/probe موجود رویش کار می‌کنند. هر مسیر صف ارسال خودش را
  دارد تا یک مسیرِ بلاک‌شده (مثل صف پر QUIC) بقیه را متوقف نکند.
- **(D2)** هر مسیر `carrier` و **`mode` خودش** را دارد. یعنی یک مسیر `xdi` در حالت
  `dial` (ICMP دایرکت) و یک مسیر `xdi` در حالت `listen` (ICMP ریورس) **در یک
  تونل**، هم‌زمان — همان خواستهٔ حتمیِ تو. حسابرسی کد تأیید کرد این دو جهت روی یک
  هاست هیچ تداخلی ندارند. این «پل‌زدن موتور ریورس و l3» **نیست** (آن‌ها
  قابل‌اطمینان/stream‌اند و bond نمی‌شوند)؛ فقط جهتِ هر-مسیر است.
- **(D3)** یک **probeِ احرازشده با کلیدِ مشتق از توکن** که کاملاً داخل خود bond
  مدیریت می‌شود: مسیری که probeهایش جواب نگیرد مرده حساب می‌شود **حتی وقتی
  WriteTo موفق است** (همان حفرهٔ multipath)، و مسیر `listen` آدرس peer را فقط از
  probeِ احرازشده می‌پذیرد (بستنِ حفرهٔ `pinnedCarrier`). probe سربار per-packet
  اضافه نمی‌کند.
- **(D4)** زمان‌بندِ **flowlet** با فرمول `rtt + 2×jitter + 20×loss` و
  هیسترزیسِ ۱۵٪/۳-بار و backoff: بار بین مسیرها و IPها پخش می‌شود بدون به‌هم‌ریختنِ
  ترتیبِ یک جریان (جلوگیری از reordering و HOL).
- **(D5)** `Overhead()` = **بیشینهٔ** سربار مسیرها، تا MTU برای باریک‌ترین مسیر
  درست باشد و سیاه‌چالهٔ «دانلود هنگ می‌کند» پیش نیاید.
- **(D6)** فاز **کشف/تست سلامت** قبل از ورود هر مسیر به سرویس، و تستِ دوره‌ایِ
  مسیرهای مرده با backoff؛ نتیجه (RTT/jitter/loss/MTU/جهت/دلیلِ رد) در snapshot و
  پنل. این همان «تست واقعی بین دو سرور» است.
- **(D7)** پشت feature flag، پیش‌فرض خاموش، و وقتی خاموش است رفتار تونل‌های فعلی
  **هیچ تغییری نمی‌کند**. bonding بدون health-check و تشخیص خرابی خاموش قابل
  فعال‌سازی نیست. «یک پروسه برای هر تونل» حفظ می‌شود.

**قیدهای هر-حامل (از حسابرسی):** هر مسیر `xdi` باید echo-id متمایز بگیرد و در هر
bond حداکثر یک مسیر `xdi` از نوع `listen` باشد؛ مسیرهای `pck` باید پورت متمایز
داشته باشند (وگرنه پکت خروجی خودِ هاست را می‌بلعند)؛ `spoof` در دو جهت مخالفِ یک
bond مجاز نیست؛ هر مسیر `quic` صف ارسال خودش را دارد. همه قبل از باز شدن تونل
اعتبارسنجی می‌شوند.

**تست‌ها:** unit، integration روی netns (از جمله تستِ مسیرِ بی‌صدا فیلترشده که
multipath نمی‌گرفت)، race، و failure-injection با همان hookِ `wrapCarrier`
موجود. نتیجهٔ تست شبیه‌سازی‌شده **جدا** از تست واقعی دو سرور گزارش می‌شود.

**عقب‌گرد:** `bond` افزودنی است؛ حذف جدول مسیرها یا بیلد، کل سیستم را به حالت قبل
برمی‌گرداند چون با بقیهٔ حامل‌ها و موتورها کدِ مشترک ندارد.

**وضعیت فاز ۱ (۲۰۲۶-۱۰-۲۷):** پیاده شد، پشت `[l3.bond] experimental = true`.
تفاوت‌ها با طرح اولیه و دلیلشان در بخش «Implementation notes» آمده: زمان‌بندِ
**لایه‌ای (tier)** به‌جای flowletِ صرفاً مبتنی بر فاصله (تا ترافیکِ پیوسته هم پخش
شود و reordering در حدی بماند که TCP تحمل می‌کند)، backoff از ۵ ثانیه به‌جای ۳۰،
سقف AutoMTU برای bond برابر MTUِ تنظیم‌شده، و قاعدهٔ ضد-replay برای probe.
تست‌ها: ۳۲ تستِ bond و `-race` و fuzz روی loopback سبز؛ **تست واقعی بین دو سرور
هنوز اجرا نشده** و اعداد loopback اندازه‌گیریِ شبکه نیستند.

</div>

---

*A product fork of BackPack. Last verified against the code at the time of writing (post-`9d58f84`).*
