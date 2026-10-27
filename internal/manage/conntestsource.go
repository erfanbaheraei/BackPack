package manage

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/backpack/backpack/internal/tui"
)

// Choosing the address the kharej tests from.
//
// A kharej with several public addresses reaches Iran from whichever one its
// routing table prefers, which need not be the one its tunnels will use — and
// filtering on the Iran route is often per address, so one address can pass
// where its neighbour is throttled. When this server has more than one address
// of a family, the operator picks the one the test leaves from. Iran needs no
// change: it answers whatever address the coordinator's hello came from, and
// dials the direct tunnels back to that same address.
//
// What the choice reaches:
//   - every exchange with Iran's coordinator (ctAskContext), so the hello —
//     and with it the address Iran dials the direct tunnels and the spoof probe
//     to — leaves from it
//   - the reverse transports whose engine takes local_addr: tcp, tcpmux,
//     stealth, ws, wss, wsmux, wssmux
//   - the direct udp and quic listeners, which bind it
//   - the path-MTU probe
//
// What it cannot reach today, and says so before the test starts: the reverse
// datagram transports (udp, kcp, quic, xdi, pck), whose engines open their own
// unbound sockets; the managed helpers (naive, xhttp, reality), which dial
// Iran themselves; and the raw direct carriers (pck, sni, xdi), which take
// their source from the routing table. Those rows run from the default route.
//
// An empty choice is no binding at all — exactly the behaviour before this
// existed, which the loopback tests depend on.

// ctSources is the chosen source per family ("IPv4", "IPv6"). A family that is
// absent is the system's choice.
type ctSources map[string]net.IP

type ctSourcesKey struct{}

// ctWithSources carries the choice down to every dial the kharej side makes.
func ctWithSources(ctx context.Context, s ctSources) context.Context {
	if len(s) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctSourcesKey{}, s)
}

// ctSourceFor is the chosen source for talking to host, or nil.
func ctSourceFor(ctx context.Context, host string) net.IP {
	s, _ := ctx.Value(ctSourcesKey{}).(ctSources)
	return s[ctFamily(host)]
}

// ctDialer is a dialer leaving from the chosen source for host, if there is one.
func ctDialer(ctx context.Context, network, host string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if ip := ctSourceFor(ctx, host); ip != nil {
		if strings.HasPrefix(network, "udp") {
			d.LocalAddr = &net.UDPAddr{IP: ip}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	return d
}

// ctSourceApplies reports whether a row's tunnel actually leaves from the
// chosen source. See the list above for why the others do not.
func ctSourceApplies(kind, tr string) bool {
	switch kind {
	case "reverse":
		return !isDatagram(tr) && !managedTransport(tr)
	case "direct":
		return tr == "udp" || tr == "quic"
	}
	return false
}

// ctBindReverse puts the chosen source on a reverse client as local_addr. It
// leaves alone every transport that cannot honour it: local_addr on a datagram
// transport or a managed helper stops the engine at load.
func ctBindReverse(ctx context.Context, host, tr string, spec *TunnelSpec) {
	if ip := ctSourceFor(ctx, host); ip != nil && ctSourceApplies("reverse", tr) {
		spec.LocalAddr = ip.String()
	}
}

// ctBindDirect is a direct listener's bind address: the chosen source on the
// same port when the carrier binds one (udp, quic), addr unchanged otherwise.
func ctBindDirect(ctx context.Context, host, tr, addr string) string {
	if ip := ctSourceFor(ctx, host); ip != nil && ctSourceApplies("direct", tr) {
		return net.JoinHostPort(ip.String(), addrPort(addr))
	}
	return addr
}

// ctKharejSeen carries back, from a kharej run, the address it checked in from,
// so the board and the path summary can name both ends of the path.
type ctKharejSeen struct {
	mu   sync.Mutex
	addr string
}

type ctKharejSeenKey struct{}

func ctWithKharejSeen(ctx context.Context) (context.Context, *ctKharejSeen) {
	s := &ctKharejSeen{}
	return context.WithValue(ctx, ctKharejSeenKey{}, s), s
}

// get is safe on nil, so a caller that kept no recorder reads "".
func (s *ctKharejSeen) get() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// ctNoteKharej records the check-in address where a caller asked for it.
func ctNoteKharej(ctx context.Context, ip string) {
	if s, _ := ctx.Value(ctKharejSeenKey{}).(*ctKharejSeen); s != nil {
		s.mu.Lock()
		s.addr = ip
		s.mu.Unlock()
	}
}

// ctAddrIP is the IP of a TCP or UDP address, without the port.
func ctAddrIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	}
	return ""
}

// ctLocalAddresses is swapped by tests; the real one reads this host's
// interfaces.
var ctLocalAddresses = ConnTestAddresses

// ctLinkFamilies is the families a test link's routes use, IPv4 first.
func ctLinkFamilies(raw string) []string {
	a, err := parseConnTestLink(raw)
	if err != nil {
		return nil
	}
	hosts := []string{a.Host}
	if len(a.Routes) > 0 {
		hosts = hosts[:0]
		for _, r := range a.Routes {
			hosts = append(hosts, r.Host)
		}
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[ctFamily(h)] = true
	}
	var out []string
	for _, f := range []string{"IPv4", "IPv6"} {
		if seen[f] {
			out = append(out, f)
		}
	}
	return out
}

// ctChooseSources asks, for each family the test uses, which of this server's
// addresses to test from — only when there is more than one to choose between.
// Automatic, going back and ended input (a script, a pipe) all mean the
// system's choice, so a non-interactive run is never stopped by the question.
func ctChooseSources(families []string) ctSources {
	byFamily := map[string][]ConnTestAddress{}
	for _, a := range ctLocalAddresses() {
		byFamily[a.Family] = append(byFamily[a.Family], a)
	}
	out := ctSources{}
	for _, f := range families {
		candidates := byFamily[f]
		if len(candidates) < 2 {
			continue
		}
		tui.Info(fmt.Sprintf("This server has %d public %s addresses. Choose the one the test connects to Iran from.",
			len(candidates), f))
		opts := []tui.Option{{Title: "Automatic", Desc: "the system's default route chooses"}}
		for _, c := range candidates {
			opts = append(opts, tui.Option{Title: c.Host, Desc: c.Interface})
		}
		pick := tui.ChooseOpt(f+" address to test from", opts)
		if pick <= 0 {
			continue
		}
		if ip := net.ParseIP(candidates[pick-1].Host); ip != nil {
			out[f] = ip
		}
	}
	return out
}

// ctSourceNotice says, once, which address the test leaves from and which rows
// cannot follow it, so a result is never read as more than it measured.
func ctSourceNotice(s ctSources) string {
	if len(s) == 0 {
		return ""
	}
	var from []string
	for _, f := range []string{"IPv4", "IPv6"} {
		if ip := s[f]; ip != nil {
			from = append(from, ip.String())
		}
	}
	return fmt.Sprintf("Testing from %s. These still leave from the default route, because their "+
		"engine chooses its own source: reverse udp, kcp, quic, xdi, pck; naive, xhttp, reality; "+
		"direct pck, sni, xdi.", strings.Join(from, " and "))
}
