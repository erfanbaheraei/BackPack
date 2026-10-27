package l3

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// CarrierBond runs the tunnel over several carriers at once. It is not in
// knownCarrier on purpose: it is a carrier of carriers, opened by bond.go, and
// a path inside a bond may not itself be a bond.
const CarrierBond = "bond"

// maxBondPaths caps a bond for the same reason maxPaths caps multipath: every
// live path widens the interleave the replay window above has to absorb.
const maxBondPaths = 8

// Probe interval bounds. Below the floor the probes start to cost something on
// a slow path; above the ceiling a silently dead path carries traffic into
// nothing for too long before it is noticed.
const (
	bondDefaultProbeEvery = time.Second
	bondMinProbeEvery     = 100 * time.Millisecond
	bondMaxProbeEvery     = 10 * time.Second
)

// BondConfig is the resolved [l3.bond] table. See bond.go and ADR 0006.
type BondConfig struct {
	// Experimental is the feature flag; carrier = "bond" is refused without it.
	Experimental bool

	// ProbeEvery is how often a path in service is probed. Zero takes the
	// default.
	ProbeEvery time.Duration

	// Paths are the carriers the bond runs over.
	Paths []BondPath

	// log is the tunnel's logger, set by New. The bond reports its paths
	// coming and going through it; nil falls back to the standard logger.
	log *logrus.Logger
}

// BondPath is one carrier inside a bond, with its own direction.
type BondPath struct {
	Carrier string
	Mode    string
	Addr    string
}

func (p BondPath) String() string {
	return fmt.Sprintf("%s/%s %s", p.Carrier, p.Mode, p.Addr)
}

// normalise fills in each path's mode from the tunnel's and lower-cases names,
// so everything downstream compares like with like.
func (b *BondConfig) normalise(tunnelMode string) {
	for i := range b.Paths {
		p := &b.Paths[i]
		p.Carrier = strings.ToLower(strings.TrimSpace(p.Carrier))
		p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
		if p.Mode == "" {
			p.Mode = tunnelMode
		}
		p.Addr = strings.TrimSpace(p.Addr)
	}
}

// tunnelAddr is what the tunnel-level addr means for a bond when it is left
// out: the first dialled path's peer, which is the address the dialling side
// re-resolves before each handshake and the one the bond reports upward.
func (b *BondConfig) tunnelAddr() string {
	for _, p := range b.Paths {
		if p.Mode == ModeDial {
			return p.Addr
		}
	}
	if len(b.Paths) > 0 {
		return b.Paths[0].Addr
	}
	return ""
}

// validate refuses every bond that would come up half-working. Each rule is a
// failure seen in the carrier audit (ADR 0006, "Per-carrier constraints"),
// caught here rather than as a tunnel that silently carries less than it says.
func (b *BondConfig) validate(c *Config) error {
	if !b.Experimental {
		return fmt.Errorf("l3: carrier %q is experimental and off by default; "+
			"set experimental = true in [l3.bond] to turn it on", CarrierBond)
	}
	if len(b.Paths) == 0 {
		return fmt.Errorf("l3: carrier %q needs at least one [[l3.bond.path]]", CarrierBond)
	}
	if len(b.Paths) > maxBondPaths {
		return fmt.Errorf("l3: a bond has %d paths; at most %d are supported", len(b.Paths), maxBondPaths)
	}
	if b.ProbeEvery == 0 {
		b.ProbeEvery = bondDefaultProbeEvery
	}
	if b.ProbeEvery < bondMinProbeEvery || b.ProbeEvery > bondMaxProbeEvery {
		return fmt.Errorf("l3: bond probe interval %s is outside %s..%s",
			b.ProbeEvery, bondMinProbeEvery, bondMaxProbeEvery)
	}
	if c.Multipath.Enabled() {
		return fmt.Errorf("l3: paths (multipath) and a bond do not combine; list the sockets as bond paths instead")
	}

	var (
		dials, xdiListen, spoofs int
		pckPorts                 = map[string]int{}
		udpBinds                 = map[string]int{}
	)
	for i, p := range b.Paths {
		n := i + 1
		if p.Carrier == CarrierBond {
			return fmt.Errorf("l3: bond path %d is itself a bond", n)
		}
		if !knownCarrier(p.Carrier) {
			return fmt.Errorf("l3: bond path %d: carrier %q is not available (have %q, %q, %q, %q, %q, %q)",
				n, p.Carrier, CarrierUDP, CarrierPck, CarrierXdi, CarrierSpoof, CarrierQuic, CarrierSNI)
		}
		switch p.Mode {
		case ModeDial:
			dials++
		case ModeListen:
		default:
			return fmt.Errorf("l3: bond path %d: unknown mode %q (want %q or %q)", n, p.Mode, ModeDial, ModeListen)
		}
		host, port, err := net.SplitHostPort(p.Addr)
		if err != nil {
			return fmt.Errorf("l3: bond path %d: addr %q must be host:port: %w", n, p.Addr, err)
		}
		if p.Mode == ModeDial && host == "" {
			return fmt.Errorf("l3: bond path %d dials, so addr %q needs the peer's host", n, p.Addr)
		}

		switch p.Carrier {
		case CarrierXdi:
			// Two listeners on one token both accept every echo request and
			// feed each other's traffic. One dial and one listen is fine, and
			// is the point: the audit found the two directions never collide.
			// Dialled xdi paths need nothing here — the echo identifier is
			// drawn from a per-process set (icmpframe.go), so it cannot repeat.
			if p.Mode == ModeListen {
				xdiListen++
				if xdiListen > 1 {
					return fmt.Errorf("l3: bond path %d: at most one listening xdi path per bond "+
						"(two would both answer every echo request)", n)
				}
			}
		case CarrierPck, CarrierSNI:
			// The packet socket filters on destination port only and sees this
			// host's own egress, so two pck paths on one port read each other.
			if prev, dup := pckPorts[port]; dup {
				return fmt.Errorf("l3: bond paths %d and %d are both pck on port %s; "+
					"each pck path needs its own port", prev, n, port)
			}
			pckPorts[port] = n
		case CarrierSpoof:
			// Its port is derived from the token alone, the same both ways,
			// and nothing on the wire tells two spoof paths apart.
			spoofs++
			if spoofs > 1 {
				return fmt.Errorf("l3: bond path %d: at most one spoof path per bond", n)
			}
			if p.Mode == ModeListen && c.Spoof.SpoofPeerIP == "" {
				return fmt.Errorf("l3: bond path %d: carrier %q needs spoof_peer_ip when listening, "+
					"because the peer forges the source of every packet it sends", n, CarrierSpoof)
			}
		case CarrierUDP, CarrierQuic:
			// Both bind a UDP socket when listening; one address cannot be
			// bound twice.
			if p.Mode == ModeListen {
				if prev, dup := udpBinds[p.Addr]; dup {
					return fmt.Errorf("l3: bond paths %d and %d both listen on %s", prev, n, p.Addr)
				}
				udpBinds[p.Addr] = n
			}
		}
	}

	// The handshake initiator re-resolves its peer from a dialled path's
	// address before every handshake (resolvePeer), and has to be able to send
	// its first message without waiting to be reached. A listen-only initiator
	// has neither, so it is refused here rather than left to wait.
	if c.Mode == ModeDial && dials == 0 {
		return fmt.Errorf("l3: this end dials the handshake, so its bond needs at least one path with mode = %q", ModeDial)
	}
	return nil
}
