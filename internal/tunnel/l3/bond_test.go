package l3

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These run the bond over real UDP sockets on loopback, with a fault carrier
// in front of chosen paths. Loopback stands in for the two servers: the
// numbers they produce are not network measurements, and are not reported as
// such. Raw carriers (xdi, pck) need Linux and CAP_NET_RAW; plain udp paths
// exercise the same bond code, and a path's mode is what makes it direct or
// reverse, not its carrier.

// bondTestEvery is fast enough that a test sees paths come and go in well
// under a second.
const bondTestEvery = 100 * time.Millisecond

const bondTestToken = "a-bond-test-token"

// faultCarrier stands a broken path in front of a working one.
type faultCarrier struct {
	DatagramCarrier
	blackhole atomic.Bool  // writes succeed and nothing is sent
	maxSize   atomic.Int64 // larger datagrams vanish; 0 is no limit
	stalled   atomic.Bool  // writes block until Close
	release   chan struct{}
	once      sync.Once
}

func newFault(c DatagramCarrier) *faultCarrier {
	return &faultCarrier{DatagramCarrier: c, release: make(chan struct{})}
}

func (f *faultCarrier) WriteTo(p []byte, addr net.Addr) (int, error) {
	if f.stalled.Load() {
		<-f.release
		return 0, net.ErrClosed
	}
	if f.blackhole.Load() {
		return len(p), nil
	}
	if m := f.maxSize.Load(); m > 0 && int64(len(p)) > m {
		return len(p), nil
	}
	return f.DatagramCarrier.WriteTo(p, addr)
}

func (f *faultCarrier) Close() error {
	f.once.Do(func() { close(f.release) })
	return f.DatagramCarrier.Close()
}

// bondNet hands each bond pre-bound listening sockets, so both ends know every
// port before either is built, and records the fault carrier on every path.
type bondNet struct {
	t      *testing.T
	mu     sync.Mutex
	pre    map[string]DatagramCarrier
	faults map[string]*faultCarrier
}

func newBondNet(t *testing.T) *bondNet {
	return &bondNet{t: t, pre: map[string]DatagramCarrier{}, faults: map[string]*faultCarrier{}}
}

// listen pre-binds a loopback socket under a placeholder name, and returns the
// address the other end should dial.
func (n *bondNet) listen(name string) string {
	c, err := listenUDP("127.0.0.1:0", 0)
	if err != nil {
		n.t.Fatal(err)
	}
	n.mu.Lock()
	n.pre[name] = c
	n.mu.Unlock()
	return c.LocalAddr().String()
}

func (n *bondNet) opener(side string) bondOpener {
	return func(ctx context.Context, cfg Config) (DatagramCarrier, net.Addr, error) {
		n.mu.Lock()
		pre, ok := n.pre[cfg.Addr]
		delete(n.pre, cfg.Addr)
		n.mu.Unlock()
		var c DatagramCarrier
		var peer net.Addr
		var err error
		if ok && cfg.Mode == ModeListen {
			c = pre
		} else {
			c, peer, err = openBareCarrier(ctx, cfg)
			if err != nil {
				return nil, nil, err
			}
		}
		f := newFault(c)
		n.mu.Lock()
		n.faults[side+"/"+cfg.Addr] = f
		n.mu.Unlock()
		return f, peer, nil
	}
}

func (n *bondNet) fault(side, addr string) *faultCarrier {
	n.mu.Lock()
	defer n.mu.Unlock()
	f := n.faults[side+"/"+addr]
	if f == nil {
		n.t.Fatalf("no path %s/%s", side, addr)
	}
	return f
}

func (n *bondNet) bond(side, mode string, paths ...BondPath) *bondCarrier {
	n.t.Helper()
	cfg := Config{Mode: mode, Token: bondTestToken, Encap: "gre", MTU: 1400, Carrier: CarrierBond,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, Paths: paths, log: quietLogger()}}
	cfg.Bond.normalise(mode)
	cfg.Addr = cfg.Bond.tunnelAddr()
	b, _, err := newBondCarrier(context.Background(), cfg, n.opener(side))
	if err != nil {
		n.t.Fatalf("%s: %v", side, err)
	}
	n.t.Cleanup(func() { b.Close() })
	return b
}

func awaitInService(t *testing.T, b *bondCarrier, want []bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		stats := b.PathStats()
		ok := true
		for i, w := range want {
			if stats[i].InService != w {
				ok = false
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("paths in service never became %v: %+v", want, stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// datagram is a numbered stand-in for a sealed tunnel datagram. It starts with
// the data kind, as the real ones do, never with the probe magic.
func datagram(i, size int) []byte {
	p := make([]byte, size)
	p[0] = typeData
	binary.BigEndian.PutUint32(p[1:5], uint32(i))
	return p
}

// collect reads datagrams until none arrives for quiet, and returns their
// numbers.
func collect(b *bondCarrier, quiet time.Duration) map[int]bool {
	got := map[int]bool{}
	buf := make([]byte, 2048)
	for {
		b.SetReadDeadline(time.Now().Add(quiet))
		n, _, err := b.ReadFrom(buf)
		if err != nil {
			return got
		}
		if n >= 5 && buf[0] == typeData {
			got[int(binary.BigEndian.Uint32(buf[1:5]))] = true
		}
	}
}

func send(t *testing.T, b *bondCarrier, from, to, size int) {
	t.Helper()
	for i := from; i < to; i++ {
		if _, err := b.WriteTo(datagram(i, size), nil); err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if i%64 == 63 {
			time.Sleep(time.Millisecond) // stay inside loopback socket buffers
		}
	}
}

// twoDialPaths is the plain shape: A dials B on two paths.
func twoDialPaths(t *testing.T) (*bondNet, *bondCarrier, *bondCarrier, [2]string) {
	n := newBondNet(t)
	b0, b1 := n.listen("127.0.0.1:1"), n.listen("127.0.0.1:2")
	B := n.bond("B", ModeListen,
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"},
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:2"})
	A := n.bond("A", ModeDial,
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: b0},
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: b1})
	awaitInService(t, A, []bool{true, true}, 3*time.Second)
	awaitInService(t, B, []bool{true, true}, 3*time.Second)
	return n, A, B, [2]string{b0, b1}
}

func TestBondCarriesTrafficBothWays(t *testing.T) {
	_, A, B, _ := twoDialPaths(t)

	send(t, A, 0, 500, 1000)
	if got := collect(B, 300*time.Millisecond); len(got) != 500 {
		t.Fatalf("A→B: %d of 500 arrived", len(got))
	}
	// The listening side sends only where an authenticated probe told it to.
	send(t, B, 0, 500, 1000)
	if got := collect(A, 300*time.Millisecond); len(got) != 500 {
		t.Fatalf("B→A: %d of 500 arrived", len(got))
	}
}

// Same-RTT paths share the volume, in flowlets, rather than one carrying it all.
func TestBondSpreadsVolumeOverTheTier(t *testing.T) {
	_, A, B, _ := twoDialPaths(t)
	const count, size = 2000, 1000
	send(t, A, 0, count, size)
	collect(B, 300*time.Millisecond)
	stats := A.PathStats()
	total := stats[0].TxBytes + stats[1].TxBytes
	for i, s := range stats {
		if share := float64(s.TxBytes) / float64(total); share < 0.25 {
			t.Fatalf("path %d carried %.0f%% of the volume: %+v", i, 100*share, stats)
		}
	}
}

// The failure multipath cannot see: the path's writes succeed and nothing
// arrives. The bond notices from its probes, takes the path out, and what is
// sent afterwards arrives over the other.
func TestBondDetectsASilentlyBlackholedPath(t *testing.T) {
	n, A, B, addrs := twoDialPaths(t)
	n.fault("A", addrs[0]).blackhole.Store(true)

	start := time.Now()
	awaitInService(t, A, []bool{false, true}, 5*time.Second)
	t.Logf("silent path taken out after %s (loopback, probe interval %s)", time.Since(start).Round(time.Millisecond), bondTestEvery)
	if r := A.PathStats()[0].Reason; !strings.HasPrefix(r, "silent") && !strings.HasPrefix(r, "loss") {
		t.Fatalf("taken out for %q", r)
	}
	collect(B, 100*time.Millisecond)

	send(t, A, 0, 500, 1000)
	if got := collect(B, 300*time.Millisecond); len(got) != 500 {
		t.Fatalf("after failover %d of 500 arrived", len(got))
	}
}

// A path that comes back is found again, on its backoff, with nothing asked of
// anybody.
func TestBondRecoversAPathThatComesBack(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the first backoff step")
	}
	n, A, _, addrs := twoDialPaths(t)
	f := n.fault("A", addrs[0])
	f.blackhole.Store(true)
	awaitInService(t, A, []bool{false, true}, 5*time.Second)
	f.blackhole.Store(false)
	awaitInService(t, A, []bool{true, true}, bondBackoffMin+5*time.Second)
}

// A path that answers small probes and drops large datagrams would carry ping
// and stall every download. It never enters service, and says why.
func TestBondHoldsOutAPathTooNarrowForTheTunnel(t *testing.T) {
	n := newBondNet(t)
	b0, b1 := n.listen("127.0.0.1:1"), n.listen("127.0.0.1:2")
	n.bond("B", ModeListen,
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"},
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:2"})
	A := n.bond("A", ModeDial,
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: b0},
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: b1})
	n.fault("A", b0).maxSize.Store(400)

	awaitInService(t, A, []bool{false, true}, 3*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(A.PathStats()[0].Reason, "MTU") {
		if time.Now().After(deadline) {
			t.Fatalf("narrow path's reason: %q", A.PathStats()[0].Reason)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// One path whose writes block must not hold up the tunnel: WriteTo never
// waits, traffic spills to the path that drains, and the stuck path is taken
// out once its probes stop being answered.
func TestBondIsolatesAPathWhoseWritesBlock(t *testing.T) {
	n, A, B, addrs := twoDialPaths(t)
	n.fault("A", addrs[0]).stalled.Store(true)

	var got map[int]bool
	done := make(chan struct{})
	go func() { defer close(done); got = collect(B, 500*time.Millisecond) }()

	const count = 3000
	start := time.Now()
	for i := 0; i < count; i++ {
		_, _ = A.WriteTo(datagram(i, 500), nil)
		if i%64 == 63 {
			time.Sleep(time.Millisecond)
		}
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("writing %d datagrams took %s: a blocked path held the sender", count, took)
	}
	<-done
	// What the stuck path had queued, and the batch it was writing, is lost;
	// everything else arrived.
	if len(got) < count-bondQueue-batchSize {
		t.Fatalf("%d of %d arrived; expected all but the stuck path's queue", len(got), count)
	}
	awaitInService(t, A, []bool{false, true}, 5*time.Second)
}

// The headline case: one path in each direction in the same tunnel — A dials
// B on one, B dials A on the other (with xdi, that is direct and reverse ICMP
// at once). Both serve; losing the direct one leaves the reverse one carrying
// the tunnel.
func TestBondRunsDirectAndReversePathsTogether(t *testing.T) {
	n := newBondNet(t)
	toB := n.listen("127.0.0.1:21") // B listens: the direct path
	toA := n.listen("127.0.0.1:11") // A listens: the reverse path
	A := n.bond("A", ModeDial,
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: toB},
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:11"})
	B := n.bond("B", ModeListen,
		BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:21"},
		BondPath{Carrier: "udp", Mode: ModeDial, Addr: toA})
	awaitInService(t, A, []bool{true, true}, 3*time.Second)
	awaitInService(t, B, []bool{true, true}, 3*time.Second)

	send(t, A, 0, 300, 800)
	if got := collect(B, 300*time.Millisecond); len(got) != 300 {
		t.Fatalf("A→B over both directions: %d of 300", len(got))
	}
	send(t, B, 0, 300, 800)
	if got := collect(A, 300*time.Millisecond); len(got) != 300 {
		t.Fatalf("B→A over both directions: %d of 300", len(got))
	}

	n.fault("A", toB).blackhole.Store(true)
	awaitInService(t, A, []bool{false, true}, 5*time.Second)
	awaitInService(t, B, []bool{false, true}, 5*time.Second)
	collect(B, 100*time.Millisecond)
	collect(A, 100*time.Millisecond)
	send(t, A, 1000, 1300, 800)
	if got := collect(B, 300*time.Millisecond); len(got) != 300 {
		t.Fatalf("A→B on the reverse path alone: %d of 300", len(got))
	}
	send(t, B, 1000, 1300, 800)
	if got := collect(A, 300*time.Millisecond); len(got) != 300 {
		t.Fatalf("B→A on the reverse path alone: %d of 300", len(got))
	}
}

// A listening path learns its peer only from a probe that authenticated, and
// only from one that is new: junk, forgeries and replays move nothing.
func TestBondListenPathTrustsOnlyAuthenticatedFreshProbes(t *testing.T) {
	n := newBondNet(t)
	addr := n.listen("127.0.0.1:1")
	B := n.bond("B", ModeListen, BondPath{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"})
	dst, _ := net.ResolveUDPAddr("udp", addr)
	key := bondProbeKey(bondTestToken)

	sock := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	peerOf := func() net.Addr {
		p := B.paths[0]
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.peer
	}
	probe := func(seq uint64) []byte {
		b := make([]byte, bondMinLen)
		bondMsg{typ: bondTypeProbe, inst: 0x1234, seq: seq}.put(b, key)
		return b
	}
	// answered reports whether an answer arrived. The bond's own probes may
	// arrive at the same socket once it follows it, and are skipped.
	answered := func(c *net.UDPConn) bool {
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 2048)
		for {
			k, err := c.Read(buf)
			if err != nil {
				return false
			}
			if m, ok := parseBondMsg(buf[:k], key); ok && m.typ == bondTypeAck {
				return true
			}
		}
	}

	x, y := sock(), sock()

	x.WriteTo(datagram(1, 100), dst)
	if got := collect(B, 200*time.Millisecond); len(got) != 0 {
		t.Fatal("data from an unauthenticated sender was passed up")
	}
	forged := make([]byte, 48)
	forged[0] = bondMagic
	x.WriteTo(forged, dst)
	time.Sleep(50 * time.Millisecond)
	if peerOf() != nil || B.badProbes.Load() != 1 {
		t.Fatalf("a forged probe: peer %v, bad %d", peerOf(), B.badProbes.Load())
	}

	captured := probe(5)
	x.WriteTo(captured, dst)
	if !answered(x) || !sameAddr(peerOf(), x.LocalAddr()) {
		t.Fatalf("an authenticated probe from %s was not followed (peer %v)", x.LocalAddr(), peerOf())
	}

	y.WriteTo(captured, dst) // a replay, from somewhere else
	if answered(y) || !sameAddr(peerOf(), x.LocalAddr()) {
		t.Fatalf("a replayed probe moved the peer to %v", peerOf())
	}

	y.WriteTo(probe(6), dst) // a new, authenticated probe: a real move
	if !answered(y) || !sameAddr(peerOf(), y.LocalAddr()) {
		t.Fatalf("a fresh probe from %s did not move the peer (%v)", y.LocalAddr(), peerOf())
	}
	y.WriteTo(datagram(2, 100), dst)
	if got := collect(B, 200*time.Millisecond); !got[2] {
		t.Fatal("data from the authenticated peer was not passed up")
	}
}

// stubCarrier is a path that opens and never delivers, with a chosen cost.
type stubCarrier struct {
	overhead int
	closed   chan struct{}
	once     sync.Once
}

func (s *stubCarrier) ReadFrom([]byte) (int, net.Addr, error) {
	<-s.closed
	return 0, nil, net.ErrClosed
}
func (s *stubCarrier) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (s *stubCarrier) Close() error                     { s.once.Do(func() { close(s.closed) }); return nil }
func (s *stubCarrier) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (s *stubCarrier) SetDeadline(time.Time) error      { return nil }
func (s *stubCarrier) SetReadDeadline(time.Time) error  { return nil }
func (s *stubCarrier) SetWriteDeadline(time.Time) error { return nil }
func (s *stubCarrier) Overhead() int                    { return s.overhead }
func (s *stubCarrier) CarrierName() string              { return "stub" }

// The MTU must fit the narrowest path, so the bond reports the largest cost —
// not the first path's, which is what multipath can get away with.
func TestBondOverheadIsTheLargestPaths(t *testing.T) {
	costs := map[string]int{"127.0.0.1:1": 28, "127.0.0.1:2": 52, "127.0.0.1:3": 41}
	open := func(_ context.Context, cfg Config) (DatagramCarrier, net.Addr, error) {
		return &stubCarrier{overhead: costs[cfg.Addr], closed: make(chan struct{})}, nil, nil
	}
	cfg := Config{Mode: ModeListen, Token: "t", Encap: "gre", MTU: 1400, Carrier: CarrierBond,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, log: quietLogger(), Paths: []BondPath{
			{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"},
			{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:2"},
			{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:3"},
		}}}
	b, _, err := newBondCarrier(context.Background(), cfg, open)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Overhead() != 52 {
		t.Fatalf("overhead %d, want 52", b.Overhead())
	}
}

// One path that cannot open does not stop the others; none opening is an
// error, so the tunnel's own restart takes over.
func TestBondOpensWhatItCan(t *testing.T) {
	fail := errors.New("refused")
	open := func(_ context.Context, cfg Config) (DatagramCarrier, net.Addr, error) {
		if cfg.Addr == "127.0.0.1:2" {
			return nil, nil, fail
		}
		return &stubCarrier{overhead: 28, closed: make(chan struct{})}, nil, nil
	}
	cfg := Config{Mode: ModeListen, Token: "t", Encap: "gre", MTU: 1400, Carrier: CarrierBond,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, log: quietLogger(), Paths: []BondPath{
			{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"},
			{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:2"},
		}}}
	b, _, err := newBondCarrier(context.Background(), cfg, open)
	if err != nil {
		t.Fatalf("one failed path failed the bond: %v", err)
	}
	if s := b.PathStats()[1]; s.State != "down" || !strings.Contains(s.Reason, "refused") {
		t.Fatalf("the failed path reads %+v", s)
	}
	b.Close()

	cfg.Bond.Paths = cfg.Bond.Paths[1:]
	if _, _, err := newBondCarrier(context.Background(), cfg, open); !errors.Is(err, fail) {
		t.Fatalf("no path opened, got %v", err)
	}
}

// Before any path has qualified, nothing is sent anywhere.
func TestBondWritesNothingBeforeAPathQualifies(t *testing.T) {
	open := func(_ context.Context, cfg Config) (DatagramCarrier, net.Addr, error) {
		return &stubCarrier{overhead: 28, closed: make(chan struct{})}, nil, nil
	}
	cfg := Config{Mode: ModeListen, Token: "t", Encap: "gre", MTU: 1400, Carrier: CarrierBond,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, log: quietLogger(),
			Paths: []BondPath{{Carrier: "udp", Mode: ModeListen, Addr: "127.0.0.1:1"}}}}
	b, _, err := newBondCarrier(context.Background(), cfg, open)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.WriteTo([]byte{typeData, 1}, nil); !errors.Is(err, errBondNoPath) {
		t.Fatalf("got %v, want %v", err, errBondNoPath)
	}
}

// schedulerWith builds a bond with hand-set health, to test the tier.
func schedulerWith(t *testing.T, paths ...[2]float64) *bondCarrier {
	b := &bondCarrier{log: quietLogger(), cur: -1}
	for i, p := range paths {
		bp := &bondPath{b: b, idx: i, conn: &stubCarrier{closed: make(chan struct{})},
			spec: BondPath{Carrier: "udp", Mode: ModeDial, Addr: "x"}, sendq: make(chan []byte, bondQueue)}
		bp.health.state = bondUp
		bp.health.srtt = time.Duration(p[0] * float64(time.Millisecond))
		bp.health.score = p[1]
		b.paths = append(b.paths, bp)
	}
	b.reschedule()
	return b
}

func TestBondTierExcludesPathsMuchSlowerThanTheBest(t *testing.T) {
	// 80 ms and 85 ms share the tier; 200 ms is standby.
	b := schedulerWith(t, [2]float64{80, 80}, [2]float64{85, 90}, [2]float64{200, 200})
	if got := b.sched.Load().paths; !equalInts(got, []int{0, 1}) {
		t.Fatalf("tier %v, want [0 1]", got)
	}
	// The anchor is the best score, not the lowest RTT: a fast path that loses
	// packets does not drag the tunnel onto itself.
	b = schedulerWith(t, [2]float64{80, 280}, [2]float64{100, 100})
	if got := b.sched.Load().paths; !equalInts(got, []int{1}) {
		t.Fatalf("tier %v, want [1]", got)
	}
}

// Within a flowlet every datagram takes one path, so nothing inside it is
// reordered; flowlets rotate in proportion to the weights.
func TestBondFlowletsStayOnOnePathAndRotateByWeight(t *testing.T) {
	b := schedulerWith(t, [2]float64{80, 100}, [2]float64{80, 100})
	const size = 1000
	var order []int
	b.sendMu.Lock()
	for i := 0; i < 1000; i++ {
		_, at := b.route(size)
		order = append(order, at)
	}
	b.sendMu.Unlock()
	switches, counts := 0, [2]int{}
	for i, at := range order {
		counts[at]++
		if i > 0 && at != order[i-1] {
			switches++
			if i%(bondQuantum/size+1) != 0 {
				t.Fatalf("switched path mid-flowlet at datagram %d", i)
			}
		}
	}
	if switches == 0 || counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("no rotation: %v, %d switches", counts, switches)
	}
	if d := counts[0] - counts[1]; d > bondQuantum/size+1 || d < -(bondQuantum/size+1) {
		t.Fatalf("equal weights split %v", counts)
	}
}

// The bond is a drop-in carrier: a whole tunnel runs over it, handshake and
// all, with nothing in the tunnel knowing.
func TestTunnelRunsOverABond(t *testing.T) {
	ports := [2]int{freeUDPPort(t), freeUDPPort(t)}
	at := func(p int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(p)) }
	dialDev, listenDev := newFakeDevice(1400), newFakeDevice(1400)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	listener, err := New(Config{
		Mode: ModeListen, Token: bondTestToken, Carrier: CarrierBond,
		LocalIP: "10.10.0.2/30", PeerIP: "10.10.0.1", MTU: 1400,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, Paths: []BondPath{
			{Carrier: "udp", Mode: ModeListen, Addr: at(ports[0])},
			{Carrier: "udp", Mode: ModeListen, Addr: at(ports[1])},
		}},
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener.openDevice = func(deviceSpec) (packetDevice, error) { return listenDev, nil }
	start(t, ctx, cancel, listener, listenDev)

	dialer, err := New(Config{
		Mode: ModeDial, Token: bondTestToken, Carrier: CarrierBond,
		LocalIP: "10.10.0.1/30", PeerIP: "10.10.0.2", MTU: 1400,
		Bond: BondConfig{Experimental: true, ProbeEvery: bondTestEvery, Paths: []BondPath{
			{Carrier: "udp", Mode: ModeDial, Addr: at(ports[0])},
			{Carrier: "udp", Mode: ModeDial, Addr: at(ports[1])},
		}},
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	dialer.openDevice = func(deviceSpec) (packetDevice, error) { return dialDev, nil }
	start(t, ctx, cancel, dialer, dialDev)

	awaitSession(t, dialer, 5*time.Second)
	across(t, dialDev, listenDev, ipv4Packet(1, 2, 3, 4))
	across(t, listenDev, dialDev, ipv4Packet(5, 6, 7, 8))
	for i := 0; i < 20; i++ {
		pkt := ipv4Packet(9, 9, 9, byte(i))
		dialDev.inject <- pkt
		if got := listenDev.receive(t, 5*time.Second); !bytes.Equal(got, pkt) {
			t.Fatalf("packet %d changed in transit", i)
		}
	}
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
