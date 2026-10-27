package l3

import (
	"bytes"
	"testing"
)

func TestBondProbeRoundTrips(t *testing.T) {
	key := bondProbeKey("a-token")
	want := bondMsg{typ: bondTypeProbe, flags: bondFlagFull, path: 3, inst: 0xDEADBEEF, seq: 1<<40 + 7}
	buf := make([]byte, 200) // padded, as a full-size probe is
	want.put(buf, key)
	got, ok := parseBondMsg(buf, key)
	if !ok {
		t.Fatal("a probe this side built did not authenticate")
	}
	if got != want {
		t.Fatalf("probe changed in transit: got %+v, want %+v", got, want)
	}
}

// Every header byte is covered by the MAC: none can be changed in flight, and a
// key derived from another token verifies nothing.
func TestBondProbeRejectsTamperingAndOtherTokens(t *testing.T) {
	key := bondProbeKey("a-token")
	buf := make([]byte, bondMinLen)
	bondMsg{typ: bondTypeAck, path: 1, inst: 42, seq: 9}.put(buf, key)

	for i := 1; i < bondMinLen; i++ {
		bad := bytes.Clone(buf)
		bad[i] ^= 0x01
		if _, ok := parseBondMsg(bad, key); ok {
			t.Errorf("flipping byte %d still authenticated", i)
		}
	}
	if _, ok := parseBondMsg(buf, bondProbeKey("another-token")); ok {
		t.Error("a probe authenticated under another tunnel's token")
	}
	if _, ok := parseBondMsg(buf[:bondMinLen-1], key); ok {
		t.Error("a truncated probe authenticated")
	}
	// Padding is not covered, and must not matter.
	padded := append(bytes.Clone(buf), 0xAA, 0xBB)
	if _, ok := parseBondMsg(padded, key); !ok {
		t.Error("padding after the MAC broke authentication")
	}
}

// A probe must never be mistaken for the tunnel's own traffic, in either
// direction: its first byte is outside every first byte the layers above write.
func TestBondMagicIsOutsideEveryUpperLayerKind(t *testing.T) {
	probe := make([]byte, 64)
	bondMsg{typ: bondTypeProbe, inst: 1, seq: 1}.put(probe, bondProbeKey("t"))
	if _, _, err := parseHeader(probe); err == nil {
		t.Fatal("the l3 layer would accept a bond probe as one of its messages")
	}
	if _, _, _, _, ok := parseFECHeader(probe); ok {
		t.Fatal("the FEC layer would accept a bond probe as one of its frames")
	}
	for kind := byte(0); kind <= typeProbeAck; kind++ {
		if isBondMsg([]byte{kind, 0, 0}) {
			t.Fatalf("a datagram starting with %d would be taken for a probe", kind)
		}
	}
}

// The probe key is domain-separated from the session's pre-shared key.
func TestBondProbeKeyIsNotTheSessionKey(t *testing.T) {
	psk, err := l3PSK("a-token")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(psk, bondProbeKey("a-token")) {
		t.Fatal("the probe key equals the session PSK")
	}
	if bytes.Equal(bondProbeKey("a"), bondProbeKey("b")) {
		t.Fatal("two tokens gave one probe key")
	}
}
