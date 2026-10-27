package manage

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/backpack/backpack/internal/tui"
)

// What matters on the wire: Iran's coordinator records the address the hello
// came from and dials the direct tunnels back to it, so the hello has to leave
// from the chosen address — over TCP and over UDP alike.
func TestTheCoordinatorSeesTheChosenSourceAddress(t *testing.T) {
	chosen := net.ParseIP("127.0.0.2")
	ctx := ctWithSources(context.Background(), ctSources{"IPv4": chosen})

	t.Run("tcp", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		seen := make(chan net.IP, 2)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				seen <- c.RemoteAddr().(*net.TCPAddr).IP
				bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("ok\n"))
				c.Close()
			}
		}()
		port := ln.Addr().(*net.TCPAddr).Port

		if reply, err := ctAskContext(ctx, "127.0.0.1", port, "hello"); err != nil || reply != "ok" {
			t.Fatalf("ask: %q %v", reply, err)
		}
		if got := <-seen; !got.Equal(chosen) {
			t.Fatalf("the coordinator saw %s, want the chosen %s", got, chosen)
		}
		if _, err := ctAskContext(context.Background(), "127.0.0.1", port, "hello"); err != nil {
			t.Fatal(err)
		}
		if got := <-seen; !got.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("with no choice the coordinator saw %s, want the system's 127.0.0.1", got)
		}
	})

	t.Run("udp", func(t *testing.T) {
		// Nothing listens on TCP at this port, so the ask falls through to UDP
		// as it does against a coordinator whose TCP is filtered.
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		seen := make(chan net.IP, 1)
		go func() {
			buf := make([]byte, 512)
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			seen <- from.(*net.UDPAddr).IP
			pc.WriteTo([]byte("ok\n"), from)
		}()
		port := pc.LocalAddr().(*net.UDPAddr).Port
		if reply, err := ctAskContext(ctx, "127.0.0.1", port, "hello"); err != nil || reply != "ok" {
			t.Fatalf("ask: %q %v", reply, err)
		}
		if got := <-seen; !got.Equal(chosen) {
			t.Fatalf("the coordinator saw %s over UDP, want the chosen %s", got, chosen)
		}
	})
}

// The choice is offered only when there is one to make, and Automatic, going
// back and ended input all leave the system to choose — so a scripted
// `link apply` on a multihomed server is never stopped by the question.
func TestTheSourceIsAskedOnlyWhenThereIsAChoice(t *testing.T) {
	old := ctLocalAddresses
	defer func() { ctLocalAddresses = old }()
	ctLocalAddresses = func() []ConnTestAddress {
		return []ConnTestAddress{
			{Host: "198.18.10.1", Family: "IPv4", Interface: "eth0"},
			{Host: "198.18.10.2", Family: "IPv4", Interface: "eth0"},
			{Host: "2001:db8::5", Family: "IPv6", Interface: "eth0"},
		}
	}
	for _, tc := range []struct {
		name, input string
		want        string
	}{
		{"the second address", "3\n", "198.18.10.2"},
		{"the first address", "2\n", "198.18.10.1"},
		{"automatic", "1\n", ""},
		{"going back", "0\n", ""},
		{"no input at all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := tui.SetInput(strings.NewReader(tc.input))
			defer restore()
			got := ctChooseSources([]string{"IPv4", "IPv6"})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("chose %v, want the system's choice", got)
				}
				return
			}
			if !got["IPv4"].Equal(net.ParseIP(tc.want)) {
				t.Fatalf("IPv4 source %v, want %s", got["IPv4"], tc.want)
			}
			// One IPv6 address is no choice, so it is neither asked nor bound.
			if got["IPv6"] != nil {
				t.Fatalf("IPv6 bound to %v with only one address to choose from", got["IPv6"])
			}
		})
	}
	// A family the link does not use is not asked about.
	restore := tui.SetInput(strings.NewReader("3\n"))
	defer restore()
	if got := ctChooseSources([]string{"IPv6"}); len(got) != 0 {
		t.Fatalf("asked about IPv4 for an IPv6-only link: %v", got)
	}
}

// The source reaches the tunnels that can leave from it, and only those:
// local_addr on a datagram reverse transport stops the engine at load.
func TestTheSourceReachesOnlyTunnelsThatCanUseIt(t *testing.T) {
	ip := net.ParseIP("198.18.10.2")
	ctx := ctWithSources(context.Background(), ctSources{"IPv4": ip})
	for _, tc := range []struct {
		kind, tr string
		applies  bool
	}{
		{"reverse", "tcp", true},
		{"reverse", "tcpmux", true},
		{"reverse", "ws", true},
		{"reverse", "wss", true},
		{"reverse", "udp", false},
		{"reverse", "kcp", false},
		{"reverse", "quic", false},
		{"reverse", "xdi", false},
		{"reverse", "pck", false},
		{"reverse", "naive", false},
		{"reverse", "reality", false},
		{"direct", "udp", true},
		{"direct", "quic", true},
		{"direct", "pck", false},
		{"direct", "sni", false},
		{"direct", "xdi", false},
	} {
		var spec TunnelSpec
		addr := "0.0.0.0:9100"
		if tc.kind == "reverse" {
			ctBindReverse(ctx, "203.0.113.9", tc.tr, &spec)
		} else {
			addr = ctBindDirect(ctx, "203.0.113.9", tc.tr, addr)
		}
		switch {
		case !tc.applies && (spec.LocalAddr != "" || addr != "0.0.0.0:9100"):
			t.Errorf("%s/%s took the source it cannot honour: local_addr %q, bind %q", tc.kind, tc.tr, spec.LocalAddr, addr)
		case tc.applies && tc.kind == "reverse" && spec.LocalAddr != ip.String():
			t.Errorf("%s/%s local_addr %q, want %s", tc.kind, tc.tr, spec.LocalAddr, ip)
		case tc.applies && tc.kind == "direct" && addr != "198.18.10.2:9100":
			t.Errorf("%s/%s binds %q, want the chosen address on the same port", tc.kind, tc.tr, addr)
		}
	}

	// No choice, or a choice for the other family, changes nothing.
	for _, ctx := range []context.Context{
		context.Background(),
		ctWithSources(context.Background(), ctSources{"IPv6": net.ParseIP("2001:db8::5")}),
	} {
		var spec TunnelSpec
		ctBindReverse(ctx, "203.0.113.9", "tcp", &spec)
		addr := ctBindDirect(ctx, "203.0.113.9", "udp", "0.0.0.0:9100")
		if spec.LocalAddr != "" || addr != "0.0.0.0:9100" {
			t.Fatalf("bound without a choice for the family: local_addr %q, bind %q", spec.LocalAddr, addr)
		}
	}
}

func TestTheFamiliesComeFromTheLinksRoutes(t *testing.T) {
	one := ConnTestLink{Host: "203.0.113.9", Coord: 40001, Tok: ctNewSecret()}
	if got := ctLinkFamilies(one.Short()); len(got) != 1 || got[0] != "IPv4" {
		t.Fatalf("one IPv4 route: %v", got)
	}
	two := ctSuiteLink([]connTestAddr{
		{Host: "::1", Coord: 40002, Tok: ctNewSecret()},
		{Host: "127.0.0.1", Coord: 40001, Tok: ctNewSecret()},
	})
	if got := ctLinkFamilies(two); len(got) != 2 || got[0] != "IPv4" || got[1] != "IPv6" {
		t.Fatalf("two routes: %v", got)
	}
	if got := ctLinkFamilies("not a link"); got != nil {
		t.Fatalf("a non-link: %v", got)
	}
}

func TestTheNoticeNamesTheSourceAndTheRowsThatCannotFollowIt(t *testing.T) {
	if ctSourceNotice(nil) != "" {
		t.Fatal("a notice with nothing chosen")
	}
	n := ctSourceNotice(ctSources{"IPv4": net.ParseIP("198.18.10.2")})
	for _, want := range []string{"198.18.10.2", "default route", "kcp", "xdi"} {
		if !strings.Contains(n, want) {
			t.Errorf("notice %q does not mention %q", n, want)
		}
	}
}
