package l3

import "testing"

// Whatever arrives on a path, the probe parser neither panics nor accepts
// anything it did not build.
func FuzzParseBondMsg(f *testing.F) {
	key := bondProbeKey("a-fuzz-token")
	valid := make([]byte, bondMinLen)
	bondMsg{typ: bondTypeProbe, path: 2, inst: 7, seq: 9}.put(valid, key)
	f.Add(valid)
	f.Add([]byte{bondMagic})
	f.Add([]byte{typeData, 0, 0, 0})
	f.Add(make([]byte, 1500))
	f.Fuzz(func(t *testing.T, buf []byte) {
		m, ok := parseBondMsg(buf, key)
		if !ok {
			return
		}
		// Anything accepted must be exactly what put would have written.
		again := make([]byte, bondMinLen)
		m.put(again, key)
		for i := range again {
			if again[i] != buf[i] {
				t.Fatalf("accepted a message put would not write: byte %d", i)
			}
		}
	})
}
