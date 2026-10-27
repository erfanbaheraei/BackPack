package l3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// The bond's health probe (ADR 0006, D3).
//
// Each path is probed on its own, and the answer is expected back on that same
// path. A path whose probes stop being answered is taken out of service even
// though writes to it keep succeeding — the failure multipath cannot see — and
// a listening path moves its peer address only on a probe that authenticated,
// never on whatever datagram happened to arrive.
//
// The probe lives entirely inside the bond. Nothing above it ever sees one, and
// nothing about the tunnel's own datagrams changes: the bond adds no bytes to
// them, so Overhead() is unaffected.
//
// # Wire format
//
//	 0       1      2       3      4               8                     16
//	+-------+------+-------+------+---------------+---------------------+-----+---------+
//	| magic | type | flags | path | inst (u32BE)  | seq (u64BE)         | mac | padding |
//	+-------+------+-------+------+---------------+---------------------+-----+---------+
//
// magic is outside every first byte the layers above write — l3 kinds are 1..5
// (wire.go) and FEC kinds 0..1 (fec.go) — so a probe is never mistaken for
// tunnel traffic. mac is HMAC-SHA256 over the 16-byte header, truncated to 16
// bytes, under a key derived from the token with its own label. Padding is not
// covered: it exists only to make a probe the size of the largest datagram the
// tunnel sends, so the path's MTU is tested along with its liveness.
//
// inst and seq identify the prober: inst is drawn at random when the bond is
// built, seq counts its probes on that path. An answer echoes both, which is
// what lets the prober match it to the probe it sent, reject a replayed one,
// and tell its own probe reflected back at it from the peer's.
const (
	bondMagic byte = 0xB7

	bondTypeProbe byte = 1
	bondTypeAck   byte = 2

	// bondFlagFull marks a probe padded to the largest datagram the tunnel
	// sends. Its answer proves the path carries that size.
	bondFlagFull byte = 1

	bondHeaderLen = 16
	bondMACLen    = 16
	bondMinLen    = bondHeaderLen + bondMACLen

	// bondProbeLabel separates this key from the session PSK
	// ("backpack-l3-psk-v1") and from every carrier's tag, so knowing one
	// tells nothing about the others.
	bondProbeLabel = "backpack-l3-bond-probe-v1"
)

// bondMsg is a probe or its answer.
type bondMsg struct {
	typ   byte
	flags byte
	path  byte
	inst  uint32
	seq   uint64
}

// bondProbeKey derives the probe key from the token.
func bondProbeKey(token string) []byte {
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(token), []byte(bondProbeLabel), nil)
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF-SHA256 can produce 255*32 bytes; 32 cannot fail.
		panic("l3: deriving the bond probe key: " + err.Error())
	}
	return key
}

// isBondMsg is the cheap test every received datagram goes through.
func isBondMsg(buf []byte) bool {
	return len(buf) > 0 && buf[0] == bondMagic
}

// put writes the header and its MAC into dst, which must be at least
// bondMinLen long. Anything past that is padding and is left as it is.
func (m bondMsg) put(dst []byte, key []byte) {
	_ = dst[bondMinLen-1]
	dst[0] = bondMagic
	dst[1] = m.typ
	dst[2] = m.flags
	dst[3] = m.path
	binary.BigEndian.PutUint32(dst[4:8], m.inst)
	binary.BigEndian.PutUint64(dst[8:16], m.seq)
	mac := hmac.New(sha256.New, key)
	mac.Write(dst[:bondHeaderLen])
	copy(dst[bondHeaderLen:bondMinLen], mac.Sum(nil)[:bondMACLen])
}

// parseBondMsg authenticates a received probe or answer. ok is false for
// anything short, of an unknown type, or whose MAC does not verify — which a
// caller treats as noise and drops.
func parseBondMsg(buf []byte, key []byte) (m bondMsg, ok bool) {
	if len(buf) < bondMinLen || buf[0] != bondMagic {
		return bondMsg{}, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:bondHeaderLen])
	if !hmac.Equal(mac.Sum(nil)[:bondMACLen], buf[bondHeaderLen:bondMinLen]) {
		return bondMsg{}, false
	}
	m = bondMsg{
		typ:   buf[1],
		flags: buf[2],
		path:  buf[3],
		inst:  binary.BigEndian.Uint32(buf[4:8]),
		seq:   binary.BigEndian.Uint64(buf[8:16]),
	}
	if m.typ != bondTypeProbe && m.typ != bondTypeAck {
		return bondMsg{}, false
	}
	return m, true
}
