package l3

import (
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/backpack/backpack/config"
)

func bondConfig(mode string, paths ...BondPath) Config {
	return Config{
		Mode: mode, Token: "a-bond-token", Carrier: CarrierBond,
		LocalIP: "10.10.0.1/30", PeerIP: "10.10.0.2",
		Bond: BondConfig{Experimental: true, Paths: paths},
	}
}

func TestBondConfigAcceptsDirectAndReverseICMPTogether(t *testing.T) {
	c := bondConfig(ModeDial,
		BondPath{Carrier: "xdi", Mode: "dial", Addr: "203.0.113.5:0"},
		BondPath{Carrier: "XDI", Mode: "Listen", Addr: "0.0.0.0:0"},
		BondPath{Carrier: "pck", Addr: "203.0.113.5:9100"}, // mode taken from the tunnel
	)
	if err := c.Validate(); err != nil {
		t.Fatalf("a dial+listen xdi bond was refused: %v", err)
	}
	if c.Addr != "203.0.113.5:0" {
		t.Fatalf("tunnel addr %q, want the first dialled path's", c.Addr)
	}
	if c.Bond.Paths[1].Carrier != "xdi" || c.Bond.Paths[1].Mode != ModeListen || c.Bond.Paths[2].Mode != ModeDial {
		t.Fatalf("paths not normalised: %+v", c.Bond.Paths)
	}
	if c.Bond.ProbeEvery != bondDefaultProbeEvery {
		t.Fatalf("probe interval %s, want the default", c.Bond.ProbeEvery)
	}
}

func TestBondConfigRefusesWhatWouldHalfWork(t *testing.T) {
	dial := BondPath{Carrier: "udp", Mode: "dial", Addr: "203.0.113.5:9000"}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"feature flag off", func(c *Config) { c.Bond.Experimental = false }, "experimental"},
		{"no paths", func(c *Config) { c.Bond.Paths = nil }, "at least one"},
		{"too many paths", func(c *Config) {
			for i := 0; i < maxBondPaths; i++ {
				c.Bond.Paths = append(c.Bond.Paths, dial)
			}
		}, "at most"},
		{"two listening xdi", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths,
				BondPath{Carrier: "xdi", Mode: "listen", Addr: "0.0.0.0:0"},
				BondPath{Carrier: "xdi", Mode: "listen", Addr: "0.0.0.0:0"})
		}, "one listening xdi"},
		{"pck on one port twice", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths,
				BondPath{Carrier: "pck", Mode: "dial", Addr: "203.0.113.5:9100"},
				BondPath{Carrier: "sni", Mode: "listen", Addr: "0.0.0.0:9100"})
		}, "own port"},
		{"two spoof", func(c *Config) {
			c.Spoof.SpoofPeerIP = "203.0.113.5"
			c.Bond.Paths = append(c.Bond.Paths,
				BondPath{Carrier: "spoof", Mode: "dial", Addr: "203.0.113.5:0"},
				BondPath{Carrier: "spoof", Mode: "listen", Addr: "0.0.0.0:0"})
		}, "one spoof"},
		{"listening spoof without its peer", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths, BondPath{Carrier: "spoof", Mode: "listen", Addr: "0.0.0.0:0"})
		}, "spoof_peer_ip"},
		{"udp and quic on one bind", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths,
				BondPath{Carrier: "udp", Mode: "listen", Addr: "0.0.0.0:9000"},
				BondPath{Carrier: "quic", Mode: "listen", Addr: "0.0.0.0:9000"})
		}, "both listen"},
		{"a bond inside a bond", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths, BondPath{Carrier: "bond", Mode: "dial", Addr: "203.0.113.5:1"})
		}, "itself a bond"},
		{"a reliable transport", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths, BondPath{Carrier: "tcp", Mode: "dial", Addr: "203.0.113.5:1"})
		}, "not available"},
		{"dial path without a host", func(c *Config) {
			c.Bond.Paths = append(c.Bond.Paths, BondPath{Carrier: "udp", Mode: "dial", Addr: ":9000"})
		}, "peer's host"},
		{"initiator with no dialled path", func(c *Config) {
			c.Bond.Paths = []BondPath{{Carrier: "udp", Mode: "listen", Addr: "0.0.0.0:9000"}}
		}, "at least one path with mode"},
		{"probe interval too short", func(c *Config) { c.Bond.ProbeEvery = time.Millisecond }, "probe interval"},
		{"combined with multipath", func(c *Config) { c.Multipath.Paths = 2 }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := bondConfig(ModeDial, dial)
			tc.edit(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The responder may dial out: a listen-mode tunnel whose only path dials is the
// "reverse" half of a bond, and is valid.
func TestBondConfigResponderMayOnlyDial(t *testing.T) {
	c := bondConfig(ModeListen, BondPath{Carrier: "xdi", Mode: "dial", Addr: "198.51.100.7:0"})
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Paths written for a carrier that does not read them are refused rather than
// silently ignored.
func TestBondPathsWithoutABondAreRefused(t *testing.T) {
	c := bondConfig(ModeDial, BondPath{Carrier: "udp", Mode: "dial", Addr: "203.0.113.5:9000"})
	c.Carrier, c.Addr = CarrierUDP, "203.0.113.5:9000"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "read only when") {
		t.Fatalf("got %v", err)
	}
}

// Without [l3.bond] a configuration validates exactly as before.
func TestBondAbsentChangesNothing(t *testing.T) {
	c := Config{Mode: ModeDial, Addr: "203.0.113.5:9000", Token: "t",
		LocalIP: "10.10.0.1/30", PeerIP: "10.10.0.2"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Carrier != CarrierUDP || len(c.Bond.Paths) != 0 {
		t.Fatalf("carrier %q, %d bond paths", c.Carrier, len(c.Bond.Paths))
	}
}

func TestBondConfigReadsFromTOML(t *testing.T) {
	const file = `
[l3]
mode     = "dial"
carrier  = "bond"
token    = "a-bond-token"
local_ip = "10.10.0.1/30"
peer_ip  = "10.10.0.2"

[l3.bond]
experimental      = true
probe_interval_ms = 500

  [[l3.bond.path]]
  carrier = "xdi"
  mode    = "dial"
  addr    = "203.0.113.5:0"

  [[l3.bond.path]]
  carrier = "xdi"
  mode    = "listen"
  addr    = "0.0.0.0:0"
`
	var doc struct {
		L3 config.L3Config `toml:"l3"`
	}
	if _, err := toml.Decode(file, &doc); err != nil {
		t.Fatal(err)
	}
	c, err := ConfigFromTable(doc.L3)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Bond.Paths) != 2 || c.Bond.Paths[1].Mode != ModeListen || c.Bond.ProbeEvery != 500*time.Millisecond {
		t.Fatalf("read %+v", c.Bond)
	}
}
