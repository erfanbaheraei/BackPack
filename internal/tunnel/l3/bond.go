package l3

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/backpack/backpack/internal/utils/network"
	"github.com/sirupsen/logrus"
)

// Several carriers at once, of different kinds and in different directions,
// as one carrier (ADR 0006).
//
// A bond is a DatagramCarrier, so the session, the pumps, the handshake, FEC
// and the MTU probe above it are the ones every other carrier gets: to them a
// bond is a carrier that drops and reorders a little more. Underneath, each
// path is an ordinary carrier opened with its own mode — so an xdi path that
// dials and an xdi path that listens can serve one tunnel together.
//
// What the bond adds over multipath:
//
//   - Health. Every path is probed (bond_probe.go) and only paths that answer
//     carry traffic. A path whose writes succeed but whose packets go nowhere
//     is found by its probes going unanswered, and taken out.
//   - Discovery. A path is measured before it carries anything, including
//     whether it carries the largest datagram the tunnel sends.
//   - Recovery. A failed path is retried on a growing backoff, and a path
//     whose carrier closes is reopened, with no panel or operator involved.
//   - Isolation. Each path has its own send queue and goroutine, so one whose
//     writes block (a QUIC connection with a full queue) cannot hold up the
//     others; the scheduler simply stops getting room on it.
//   - Authenticated addresses. A listening path learns where its peer is only
//     from a probe that authenticated, never from an arbitrary datagram.
//
// # How traffic is spread
//
// The paths in service are ranked by score (bond_health.go). The best one
// anchors a tier: the paths whose smoothed RTT is within an eighth of the
// anchor's (at least 2 ms) of it. Traffic rotates over the tier in flowlets of
// bondQuantum bytes, weighted by score, by smooth weighted round-robin.
//
// The tier is what keeps this from reordering the traffic inside the tunnel.
// Moving between two paths reorders at most by the difference in their one-way
// delays; inside the tier that is a fraction of the RTT, well within the
// reordering a modern TCP absorbs without retransmitting (RACK, RFC 8985,
// tolerates a quarter of the minimum RTT). A path much slower than the anchor
// is a hot standby: probed, ready, and used the moment the tier empties —
// spraying traffic across very different delays would reorder every flow in
// the tunnel. Spreading still does what it is for: same-route carriers, which
// is what a bond of xdi, pck and udp to one server is, share the tunnel's
// volume instead of one of them carrying all of it.

const (
	// bondQueue is how many datagrams may wait on one path's send queue. A
	// full queue means the path is not draining; the scheduler tries another
	// and, failing that, drops — a carrier is allowed to.
	bondQueue = 512

	// bondProbeQueue is the separate, smaller queue probes and their answers
	// take, ahead of data, so a busy path is still measured honestly.
	bondProbeQueue = 32

	// bondQuantum is the flowlet: how many bytes go on one path before the
	// scheduler considers the next.
	bondQuantum = 64 << 10

	// bondTierFloor is the smallest RTT difference the tier tolerates, so
	// paths on a fast route are not split by measurement noise.
	bondTierFloor = 2 * time.Millisecond

	// bondInbox matches multipath's merged receive queue.
	bondInbox = pathQueue
)

var errBondNoPath = errors.New("l3: bond: no path is in service")

// bondOpener opens one path's carrier. openBareCarrier in production; tests
// put a constrained or failing path in front of it.
type bondOpener func(ctx context.Context, cfg Config) (DatagramCarrier, net.Addr, error)

// BondPathStats is one path's figures, for diagnostics and the management
// screens.
type BondPathStats struct {
	Path      string
	State     string
	Reason    string
	RTT       time.Duration
	Jitter    time.Duration
	Loss      float64
	Score     float64
	InService bool
	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64
	Drops     uint64
}

type bondCarrier struct {
	cfg      BondConfig
	key      []byte
	inst     uint32
	paths    []*bondPath
	fullSize int
	overhead int
	open     bondOpener
	log      *logrus.Logger

	ctx    context.Context
	cancel context.CancelFunc
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	sched atomic.Pointer[bondSchedule]

	// The scheduler's own state, under sendMu. Writes arrive from the send
	// pump, the handshake loop and the MTU probe at once.
	sendMu   sync.Mutex
	schedGen uint64
	cur      int
	flowlet  int
	wrr      []int

	in      chan pathPacket
	queueMu sync.Mutex

	mu          sync.Mutex
	deadline    time.Time
	reported    net.Addr
	foreignHook func(net.Addr)
	serving     bool

	badProbes atomic.Uint64
}

// bondPath is one carrier in the bond.
type bondPath struct {
	b    *bondCarrier
	idx  int
	spec BondPath
	sub  Config

	sendq  chan []byte
	probeq chan []byte

	mu        sync.Mutex
	conn      DatagramCarrier
	gen       int
	peer      net.Addr
	fixed     bool // the peer came from the configuration
	opening   bool
	openAfter time.Time
	nextProbe time.Time
	estimate  int // overhead, from the carrier's kind, before it is open

	// The peer's probes, for refusing a replayed one: the instance followed
	// and the highest sequence accepted from it.
	peerInst uint32
	peerSeq  uint64
	peerSeen time.Time

	health bondHealth

	txPackets, txBytes, rxPackets, rxBytes, drops atomic.Uint64
}

// bondSchedule is the tier traffic is spread over, rebuilt by the control
// loop and read by the data path without a lock.
type bondSchedule struct {
	gen     uint64
	paths   []int
	weights []int
}

// openBond builds the bond the config describes.
func openBond(ctx context.Context, cfg Config) (DatagramCarrier, net.Addr, error) {
	b, peer, err := newBondCarrier(ctx, cfg, openBareCarrier)
	if err != nil {
		return nil, nil, err
	}
	return b, peer, nil
}

// newBondCarrier opens every path at once — a QUIC path that cannot reach its
// peer would otherwise hold the rest up for its whole handshake timeout — and
// keeps whichever opened. Only when none did is it an error.
func newBondCarrier(ctx context.Context, cfg Config, open bondOpener) (*bondCarrier, net.Addr, error) {
	bc := cfg.Bond
	if bc.ProbeEvery <= 0 {
		bc.ProbeEvery = bondDefaultProbeEvery
	}
	log := bc.log
	if log == nil {
		log = logrus.StandardLogger()
	}
	encap, err := NewEncap(cfg.Encap, cfg.GREKey)
	if err != nil {
		return nil, nil, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	full := mtu + encap.Overhead() + dataOverhead
	if cfg.FEC.Enabled() {
		full += fecOverhead
	}

	bctx, cancel := context.WithCancel(context.Background())
	b := &bondCarrier{
		cfg:      bc,
		key:      bondProbeKey(cfg.Token),
		inst:     randomInstance(),
		fullSize: full,
		open:     open,
		log:      log,
		ctx:      bctx,
		cancel:   cancel,
		closed:   make(chan struct{}),
		in:       make(chan pathPacket, bondInbox),
		cur:      -1,
	}
	now := time.Now()
	for i, spec := range bc.Paths {
		sub := cfg
		sub.Carrier, sub.Mode, sub.Addr = spec.Carrier, spec.Mode, spec.Addr
		// Error correction wraps the bond as a whole, and a path is one socket.
		sub.FEC, sub.Multipath, sub.Bond = FECConfig{}, MultipathConfig{}, BondConfig{}
		b.paths = append(b.paths, &bondPath{
			b: b, idx: i, spec: spec, sub: sub,
			sendq:    make(chan []byte, bondQueue),
			probeq:   make(chan []byte, bondProbeQueue),
			health:   newBondHealth(now),
			estimate: estimateOverhead(sub),
		})
	}

	// The reported address. The dialling side knows it now, and it is the
	// same one the tunnel re-resolves before each handshake, so the two never
	// disagree. The listening side pins the first one data arrives from.
	var peer net.Addr
	if cfg.Mode == ModeDial {
		rctx, rcancel := context.WithTimeout(ctx, carrierResolveTimeout)
		addr, _, err := resolveDatagramEndpoint(rctx, cfg.Addr)
		rcancel()
		if err != nil {
			cancel()
			return nil, nil, fmt.Errorf("l3: bond: resolving %q: %w", cfg.Addr, err)
		}
		peer = addr
		b.reported = addr
	}

	// A cancelled ctx — the tunnel shutting down while a path is still
	// dialling — cancels the opens too.
	stop := context.AfterFunc(ctx, cancel)
	var wg sync.WaitGroup
	errs := make([]error, len(b.paths))
	for i, p := range b.paths {
		wg.Add(1)
		go func(i int, p *bondPath) {
			defer wg.Done()
			errs[i] = p.openNow()
		}(i, p)
	}
	wg.Wait()
	stop()
	if err := ctx.Err(); err != nil {
		b.Close()
		return nil, nil, err
	}
	opened := 0
	for i, err := range errs {
		if err == nil {
			opened++
			continue
		}
		log.Warnf("l3: bond path %d (%s) did not open: %v — retrying in the background", i+1, b.paths[i].spec, err)
	}
	if opened == 0 {
		b.Close()
		return nil, nil, fmt.Errorf("l3: bond: no path could be opened: %w", errors.Join(errs...))
	}

	for _, p := range b.paths {
		b.overhead = max(b.overhead, p.estimate)
		p.mu.Lock()
		if p.conn != nil {
			b.overhead = max(b.overhead, p.conn.Overhead())
		}
		p.mu.Unlock()
	}

	for _, p := range b.paths {
		b.wg.Add(1)
		go p.sendLoop()
	}
	b.wg.Add(1)
	go b.controlLoop()
	return b, peer, nil
}

// randomInstance draws the prober's identity. Never zero: zero is what an
// unset field reads as.
func randomInstance() uint32 {
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			panic("l3: bond: no randomness: " + err.Error())
		}
		if v := binary.BigEndian.Uint32(buf[:]); v != 0 {
			return v
		}
	}
}

// estimateOverhead is a carrier's cost on the wire, known before it is open,
// so a path that failed to open still counts towards the MTU: when it comes
// back, it must fit what the tunnel is already sending.
func estimateOverhead(cfg Config) int {
	v6 := false
	if host, _, err := net.SplitHostPort(cfg.Addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			v6 = true
		}
	}
	extra := 0
	if v6 {
		extra = ipv6HeaderLen - ipv4HeaderLen
	}
	switch cfg.Carrier {
	case CarrierUDP:
		return ipv4HeaderLen + udpHeaderLen + extra
	case CarrierQuic:
		return quicOverhead + extra
	case CarrierXdi:
		return network.XdiOverhead() + extra
	case CarrierPck, CarrierSNI:
		return network.PckOverhead() + extra
	case CarrierSpoof:
		return spoofOverhead(cfg)
	}
	return 0
}

// openNow opens the path's carrier and starts reading it.
func (p *bondPath) openNow() error {
	conn, peer, err := p.b.open(p.b.ctx, p.sub)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opening = false
	now := time.Now()
	if err != nil {
		p.health.fail(now, "open: "+err.Error())
		p.openAfter = p.health.retryAt
		return err
	}
	select {
	case <-p.b.closed:
		conn.Close()
		return net.ErrClosed
	default:
	}
	p.conn = conn
	p.gen++
	if peer != nil {
		p.peer, p.fixed = peer, true
	} else {
		// A listening path keeps the peer it authenticated before, if any:
		// the probes it sends there will say soon enough whether it is right.
		p.fixed = false
	}
	if h := p.b.hook(); h != nil {
		if f, ok := conn.(foreignTagHooker); ok {
			f.SetForeignHook(h)
		}
	}
	if p.health.state == bondDown {
		p.health.enter(bondProbing, now, "opened")
	}
	p.nextProbe = now
	go p.readLoop(conn, p.gen)
	return nil
}

// connFailed retires a carrier that stopped working, if it is still the
// current one, and schedules it to be reopened.
func (p *bondPath) connFailed(gen int, err error) {
	p.mu.Lock()
	if p.gen != gen || p.conn == nil {
		p.mu.Unlock()
		return
	}
	conn := p.conn
	p.conn = nil
	now := time.Now()
	p.health.fail(now, "carrier closed: "+err.Error())
	p.openAfter = p.health.retryAt
	p.mu.Unlock()
	conn.Close()
	p.b.log.Warnf("l3: bond path %d (%s) lost its carrier: %v — reopening in %s",
		p.idx+1, p.spec, err, p.health.retryAt.Sub(now).Round(time.Second))
}

// readLoop drains one carrier: probes are handled here, everything else goes
// up to the tunnel.
func (p *bondPath) readLoop(conn DatagramCarrier, gen int) {
	b := p.b
	width := 1
	br := asBatchReader(conn)
	if br != nil {
		width = batchSize
	}
	bufs := make([][]byte, width)
	sizes := make([]int, width)
	froms := make([]net.Addr, width)
	for j := range bufs {
		bufs[j] = make([]byte, maxMTU+256)
	}
	for {
		var count int
		var err error
		if br != nil {
			count, err = br.ReadBatch(bufs, sizes, froms)
			if errors.Is(err, errNoBatch) {
				br, err = nil, nil
				continue
			}
		} else {
			sizes[0], froms[0], err = conn.ReadFrom(bufs[0])
			if err == nil {
				count = 1
			}
		}
		for j := 0; j < count; j++ {
			if sizes[j] < 0 || sizes[j] > len(bufs[j]) {
				continue
			}
			p.receive(bufs[j][:sizes[j]], froms[j])
		}
		if err == nil {
			continue
		}
		select {
		case <-b.closed:
			return
		default:
		}
		if errors.Is(err, net.ErrClosed) {
			p.connFailed(gen, err)
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-b.closed:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// receive handles one datagram from this path.
func (p *bondPath) receive(buf []byte, from net.Addr) {
	b := p.b
	if isBondMsg(buf) {
		p.control(buf, from)
		return
	}
	p.rxPackets.Add(1)
	p.rxBytes.Add(uint64(len(buf)))
	// A listening path that has not yet authenticated its peer has no
	// business passing anything up: the peer always probes before it sends,
	// so whatever arrives first is somebody else's.
	p.mu.Lock()
	known := p.fixed || p.peerInst != 0
	p.mu.Unlock()
	if !known {
		p.drops.Add(1)
		return
	}
	b.queueMu.Lock()
	defer b.queueMu.Unlock()
	select {
	case <-b.closed:
		return
	default:
	}
	if len(b.in) == cap(b.in) {
		p.drops.Add(1)
		return
	}
	frame := network.GetDatagramBuffer(len(buf))
	copy(frame, buf)
	b.in <- pathPacket{frame, from}
}

// control handles a probe or an answer.
func (p *bondPath) control(buf []byte, from net.Addr) {
	b := p.b
	m, ok := parseBondMsg(buf, b.key)
	if !ok {
		b.badProbes.Add(1)
		return
	}
	now := time.Now()
	switch m.typ {
	case bondTypeAck:
		// Ours, and for this path: an answer that crossed onto another path
		// says nothing about either.
		if m.inst != b.inst || int(m.path) != p.idx {
			return
		}
		p.mu.Lock()
		p.health.onAck(m.seq, now)
		p.mu.Unlock()

	case bondTypeProbe:
		if m.inst == b.inst {
			// Our own probe, reflected back at us.
			return
		}
		p.mu.Lock()
		if !p.freshProbe(m, now) {
			p.mu.Unlock()
			return
		}
		moved := false
		if !p.fixed && from != nil && !sameAddr(p.peer, from) {
			moved = p.peer != nil
			p.peer = from
		}
		dst := p.peer
		p.mu.Unlock()
		if moved {
			b.log.Infof("l3: bond path %d (%s): peer moved to %s", p.idx+1, p.spec, from)
		}
		if dst == nil {
			return
		}
		ack := make([]byte, bondMinLen)
		bondMsg{typ: bondTypeAck, path: m.path, inst: m.inst, seq: m.seq}.put(ack, b.key)
		select {
		case p.probeq <- ack:
		default:
		}
	}
}

// freshProbe decides whether an authenticated probe is new, which is what it
// takes to answer it and to move a listening path's peer address.
//
// A probe is new if it is the first, if it is from the instance already
// followed with a higher sequence, or if it is from a new instance — a peer
// that restarted — once the old one has gone quiet. A replayed probe is none
// of these while the peer it was captured from is alive, so it moves nothing.
func (p *bondPath) freshProbe(m bondMsg, now time.Time) bool {
	quiet := 3 * p.b.cfg.ProbeEvery
	switch {
	case p.peerInst == 0,
		m.inst == p.peerInst && m.seq > p.peerSeq,
		m.inst != p.peerInst && now.Sub(p.peerSeen) > quiet:
		p.peerInst, p.peerSeq, p.peerSeen = m.inst, m.seq, now
		return true
	}
	return false
}

// sendLoop is the path's own writer: nothing it waits on can hold up another
// path. Probes and answers go ahead of data.
func (p *bondPath) sendLoop() {
	b := p.b
	defer b.wg.Done()
	bufs := make([][]byte, 0, batchSize)
	for {
		select {
		case f := <-p.probeq:
			p.write([][]byte{f}, false)
			continue
		default:
		}
		var first []byte
		select {
		case <-b.closed:
			p.drain()
			return
		case f := <-p.probeq:
			p.write([][]byte{f}, false)
			continue
		case first = <-p.sendq:
		}
		bufs = append(bufs[:0], first)
	more:
		for len(bufs) < batchSize {
			select {
			case f := <-p.sendq:
				bufs = append(bufs, f)
			default:
				break more
			}
		}
		p.write(bufs, true)
		for i, f := range bufs {
			network.PutDatagramBuffer(f)
			bufs[i] = nil
		}
	}
}

// write puts frames on this path's carrier, in one call where it can batch.
func (p *bondPath) write(frames [][]byte, data bool) {
	p.mu.Lock()
	conn, peer, gen := p.conn, p.peer, p.gen
	p.mu.Unlock()
	if conn == nil || peer == nil {
		if data {
			p.drops.Add(uint64(len(frames)))
		}
		return
	}
	sent := 0
	var err error
	if bw := asBatchWriter(conn); bw != nil && len(frames) > 1 {
		sent, err = bw.WriteBatch(frames, peer)
		sent = min(max(sent, 0), len(frames))
		if errors.Is(err, errNoBatch) {
			err = nil
		}
	}
	for err == nil && sent < len(frames) {
		var n int
		n, err = conn.WriteTo(frames[sent], peer)
		if err == nil && n != len(frames[sent]) {
			err = fmt.Errorf("l3: short datagram write")
		}
		if err == nil {
			sent++
		}
	}
	if data {
		p.txPackets.Add(uint64(sent))
		for _, f := range frames[:sent] {
			p.txBytes.Add(uint64(len(f)))
		}
		p.drops.Add(uint64(len(frames) - sent))
	}
	if errors.Is(err, net.ErrClosed) {
		p.connFailed(gen, err)
	}
}

// drain returns queued buffers to the pool at shutdown.
func (p *bondPath) drain() {
	for {
		select {
		case f := <-p.sendq:
			network.PutDatagramBuffer(f)
		default:
			return
		}
	}
}

// controlLoop probes, evaluates, reopens and reschedules. It is the whole of
// the failover: nothing outside this process is asked for anything.
func (b *bondCarrier) controlLoop() {
	defer b.wg.Done()
	tick := max(b.cfg.ProbeEvery/4, 25*time.Millisecond)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	b.reschedule()
	for {
		select {
		case <-b.closed:
			return
		case <-ticker.C:
		}
		now := time.Now()
		for _, p := range b.paths {
			p.step(now)
		}
		// Rebuilt every tick, not only when a path changes state: the weights
		// move with the (hysteresis-filtered) scores, and the tier with the
		// RTTs. Unchanged, it is not replaced, and the rotation carries on.
		b.reschedule()
	}
}

// step runs one path's share of a control tick. It returns whether the path
// changed state.
func (p *bondPath) step(now time.Time) bool {
	b := p.b
	p.mu.Lock()
	if p.conn == nil {
		if !p.opening && !now.Before(p.openAfter) {
			p.opening = true
			p.mu.Unlock()
			go func() {
				if err := p.openNow(); err != nil {
					b.log.Debugf("l3: bond path %d (%s) did not reopen: %v", p.idx+1, p.spec, err)
				} else {
					b.log.Infof("l3: bond path %d (%s) reopened", p.idx+1, p.spec)
				}
			}()
			return false
		}
		p.mu.Unlock()
		return false
	}
	if p.peer == nil && p.health.state == bondProbing {
		// A listening path has nobody to probe until its peer probes it, so
		// its discovery starts from then, not from when the socket opened.
		p.health.since, p.health.reason = now, "waiting for the peer's first probe"
		p.mu.Unlock()
		return false
	}
	before, beforeReason := p.health.state, p.health.reason
	changed := p.health.evaluate(now, b.cfg.ProbeEvery)
	after, reason, retry := p.health.state, p.health.reason, p.health.retryAt

	var probe []byte
	if p.peer != nil && after != bondDown && !now.Before(p.nextProbe) {
		seq, full := p.health.nextProbe(now)
		size := bondMinLen
		if full {
			size = max(b.fullSize, bondMinLen)
		}
		probe = make([]byte, size)
		bondMsg{typ: bondTypeProbe, path: byte(p.idx), inst: b.inst, seq: seq}.withFull(full).put(probe, b.key)
		every := b.cfg.ProbeEvery
		if after == bondProbing {
			every /= 4
		}
		p.nextProbe = now.Add(every)
	}
	rtt := p.health.srtt
	p.mu.Unlock()

	if probe != nil {
		select {
		case p.probeq <- probe:
		default:
			// The path is not draining even its probes; the probe counts
			// as lost when it times out, which is the truth.
		}
	}
	if changed && after != before {
		switch after {
		case bondUp:
			b.log.Infof("l3: bond path %d (%s) is in service (rtt %s)", p.idx+1, p.spec, rtt.Round(time.Millisecond))
		case bondDown:
			b.log.Warnf("l3: bond path %d (%s) is out of service: %s — retrying in %s",
				p.idx+1, p.spec, reason, retry.Sub(now).Round(time.Second))
		case bondProbing:
			b.log.Debugf("l3: bond path %d (%s) is being probed again (was %s: %s)",
				p.idx+1, p.spec, before, beforeReason)
		}
	}
	return changed
}

// withFull sets the full-size flag.
func (m bondMsg) withFull(full bool) bondMsg {
	if full {
		m.flags |= bondFlagFull
	}
	return m
}

// reschedule rebuilds the tier from the paths' current health.
func (b *bondCarrier) reschedule() {
	type cand struct {
		idx   int
		srtt  time.Duration
		score float64
	}
	var up []cand
	for _, p := range b.paths {
		p.mu.Lock()
		if p.conn != nil && p.health.state == bondUp {
			up = append(up, cand{p.idx, p.health.srtt, p.health.score})
		}
		p.mu.Unlock()
	}
	next := &bondSchedule{}
	if old := b.sched.Load(); old != nil {
		next.gen = old.gen
	}
	if len(up) > 0 {
		anchor := up[0]
		for _, c := range up[1:] {
			if c.score < anchor.score {
				anchor = c
			}
		}
		slack := max(anchor.srtt/8, bondTierFloor)
		for _, c := range up {
			d := c.srtt - anchor.srtt
			if d < 0 {
				d = -d
			}
			if d <= slack {
				next.paths = append(next.paths, c.idx)
				// +1 keeps a perfect loopback score from dividing by zero.
				w := int(1000 * (anchor.score + 1) / (c.score + 1))
				next.weights = append(next.weights, max(w, 1))
			}
		}
	}

	old := b.sched.Load()
	if old != nil && equalInts(old.paths, next.paths) && equalInts(old.weights, next.weights) {
		return
	}
	next.gen++
	b.sched.Store(next)

	b.mu.Lock()
	was := b.serving
	b.serving = len(next.paths) > 0
	b.mu.Unlock()
	switch {
	case was && len(next.paths) == 0:
		b.log.Warnf("l3: bond: no path is in service; traffic is dropped until one answers")
	case !was && len(next.paths) > 0:
		names := make([]string, len(next.paths))
		for i, idx := range next.paths {
			names[i] = b.paths[idx].spec.String()
		}
		b.log.Infof("l3: bond: carrying traffic over %s", strings.Join(names, ", "))
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pick is smooth weighted round-robin over the tier: deterministic, spread in
// proportion to the weights, and never two picks of a light path in a row
// while a heavier one is waiting.
func (s *bondSchedule) pick(current []int) int {
	total, best := 0, 0
	for i, w := range s.weights {
		current[i] += w
		total += w
		if current[i] > current[best] {
			best = i
		}
	}
	current[best] -= total
	return best
}

// route chooses the path for the next n bytes. Under sendMu.
func (b *bondCarrier) route(n int) (*bondSchedule, int) {
	s := b.sched.Load()
	if s == nil || len(s.paths) == 0 {
		return nil, -1
	}
	if s.gen != b.schedGen {
		b.schedGen = s.gen
		b.wrr = make([]int, len(s.paths))
		b.cur, b.flowlet = -1, 0
	}
	if b.cur < 0 || b.flowlet >= bondQuantum {
		b.cur, b.flowlet = s.pick(b.wrr), 0
	}
	b.flowlet += n
	return s, b.cur
}

// enqueue hands one datagram to the chosen path, or to another path in the
// tier when that one's queue is full. Under sendMu.
func (b *bondCarrier) enqueue(p []byte) error {
	s, at := b.route(len(p))
	if s == nil {
		return errBondNoPath
	}
	frame := network.GetDatagramBuffer(len(p))
	copy(frame, p)
	for k := 0; k < len(s.paths); k++ {
		i := (at + k) % len(s.paths)
		select {
		case b.paths[s.paths[i]].sendq <- frame:
			if k > 0 {
				// Stay on the path that had room, so the flowlet holds.
				b.cur = i
			}
			return nil
		default:
		}
	}
	network.PutDatagramBuffer(frame)
	b.paths[s.paths[at]].drops.Add(1)
	return fmt.Errorf("l3: bond: every path in service is congested")
}

// WriteTo queues a datagram on a path. The address is ignored: each path knows
// its own peer.
func (b *bondCarrier) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-b.closed:
		return 0, net.ErrClosed
	default:
	}
	b.sendMu.Lock()
	err := b.enqueue(p)
	b.sendMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteBatch queues a run of datagrams under one lock. It never blocks.
func (b *bondCarrier) WriteBatch(bufs [][]byte, _ net.Addr) (int, error) {
	select {
	case <-b.closed:
		return 0, net.ErrClosed
	default:
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for i, p := range bufs {
		if err := b.enqueue(p); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// ReadFrom returns the next datagram from any path, honouring the read
// deadline the tunnel sets on it.
func (b *bondCarrier) ReadFrom(p []byte) (int, net.Addr, error) {
	b.mu.Lock()
	dl := b.deadline
	b.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case pkt := <-b.in:
		n := copy(p, pkt.data)
		network.PutDatagramBuffer(pkt.data)
		return n, b.stableAddr(pkt.addr), nil
	case <-b.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, timeoutError{}
	}
}

// ReadBatch drains queued datagrams after the first, without waiting for more.
func (b *bondCarrier) ReadBatch(bufs [][]byte, sizes []int, froms []net.Addr) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, addr, err := b.ReadFrom(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0], froms[0] = n, addr
	count := 1
	for count < len(bufs) {
		select {
		case pkt := <-b.in:
			sizes[count] = copy(bufs[count], pkt.data)
			froms[count] = b.stableAddr(pkt.addr)
			network.PutDatagramBuffer(pkt.data)
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

// stableAddr is the one address reported upward, for the reason multipath
// gives: paths of different kinds arrive from different addresses — a UDP
// port here, a bare IP for xdi there — and passing each through would read to
// the tunnel as a peer moving on every packet.
func (b *bondCarrier) stableAddr(seen net.Addr) net.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reported == nil {
		b.reported = seen
	}
	return b.reported
}

func (b *bondCarrier) hook() func(net.Addr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.foreignHook
}

// SetForeignHook passes the tunnel's hook to every path that reports another
// tunnel's traffic, now and on every reopen.
func (b *bondCarrier) SetForeignHook(f func(net.Addr)) {
	b.mu.Lock()
	b.foreignHook = f
	b.mu.Unlock()
	for _, p := range b.paths {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if h, ok := conn.(foreignTagHooker); ok {
			h.SetForeignHook(f)
		}
	}
}

func (b *bondCarrier) Close() error {
	var err error
	b.once.Do(func() {
		b.queueMu.Lock()
		close(b.closed)
		b.queueMu.Unlock()
		b.cancel()
		for _, p := range b.paths {
			p.mu.Lock()
			conn := p.conn
			p.conn = nil
			p.mu.Unlock()
			if conn != nil {
				if e := conn.Close(); e != nil && err == nil {
					err = e
				}
			}
		}
		b.wg.Wait()
		b.queueMu.Lock()
		defer b.queueMu.Unlock()
		for {
			select {
			case pkt := <-b.in:
				network.PutDatagramBuffer(pkt.data)
			default:
				return
			}
		}
	})
	return err
}

// LocalAddr is the first open path's.
func (b *bondCarrier) LocalAddr() net.Addr {
	for _, p := range b.paths {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if conn != nil {
			return conn.LocalAddr()
		}
	}
	return nil
}

// Overhead is the largest of the paths', so the interface MTU fits the
// narrowest one (ADR 0006, D5). multipath can take its first path's because
// its paths are all alike; a bond's are not.
func (b *bondCarrier) Overhead() int { return b.overhead }

func (b *bondCarrier) CarrierName() string {
	names := make([]string, len(b.paths))
	for i, p := range b.paths {
		names[i] = p.spec.Carrier + "/" + p.spec.Mode
	}
	return "bond(" + strings.Join(names, "+") + ")"
}

func (b *bondCarrier) SetDeadline(t time.Time) error { return b.SetReadDeadline(t) }

func (b *bondCarrier) SetReadDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	b.mu.Unlock()
	return nil
}

// SetWriteDeadline does nothing: a write only queues, and never blocks.
func (b *bondCarrier) SetWriteDeadline(time.Time) error { return nil }

// Diag says what the bond is made of, and passes on each path's own note.
func (b *bondCarrier) Diag() string {
	lines := []string{fmt.Sprintf("l3: bond of %d paths (probe every %s, full-size probes of %d bytes)",
		len(b.paths), b.cfg.ProbeEvery, b.fullSize)}
	for _, p := range b.paths {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if d, ok := conn.(interface{ Diag() string }); ok {
			if note := d.Diag(); note != "" {
				lines = append(lines, fmt.Sprintf("l3: bond path %d (%s): %s", p.idx+1, p.spec, note))
			}
		}
	}
	return strings.Join(lines, "\n")
}

// Warning passes on what the paths found wrong with the host.
func (b *bondCarrier) Warning() string {
	var lines []string
	for _, p := range b.paths {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if w, ok := conn.(interface{ Warning() string }); ok {
			if warning := w.Warning(); warning != "" {
				lines = append(lines, fmt.Sprintf("bond path %d (%s): %s", p.idx+1, p.spec, warning))
			}
		}
	}
	return strings.Join(lines, "\n")
}

// PathStats reports every path's measurements and counters.
func (b *bondCarrier) PathStats() []BondPathStats {
	s := b.sched.Load()
	inService := map[int]bool{}
	if s != nil {
		for _, i := range s.paths {
			inService[i] = true
		}
	}
	out := make([]BondPathStats, len(b.paths))
	for i, p := range b.paths {
		p.mu.Lock()
		out[i] = BondPathStats{
			Path:   p.spec.String(),
			State:  p.health.state.String(),
			Reason: p.health.reason,
			RTT:    p.health.srtt,
			Jitter: p.health.jitter,
			Loss:   p.health.loss(),
			Score:  p.health.score,
		}
		p.mu.Unlock()
		out[i].InService = inService[i]
		out[i].TxPackets = p.txPackets.Load()
		out[i].TxBytes = p.txBytes.Load()
		out[i].RxPackets = p.rxPackets.Load()
		out[i].RxBytes = p.rxBytes.Load()
		out[i].Drops = p.drops.Load()
	}
	return out
}
