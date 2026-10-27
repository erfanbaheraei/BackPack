package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The written private half is the pair of the printed public half, and is
// readable by signsums (base64 of the 64-byte key).
func TestTheWrittenKeyMatchesThePrintedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	pubB64, err := generate(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("the written key is not a base64 Ed25519 private key (%d bytes, %v)", len(priv), err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("the printed key is not a base64 Ed25519 public key")
	}
	msg := []byte("backpack release v0.0.0\nsums")
	if !ed25519.Verify(pub, msg, ed25519.Sign(ed25519.PrivateKey(priv), msg)) {
		t.Fatal("the written private half does not sign for the printed public half")
	}
}

// An existing file is never overwritten: it may be the only copy of a key.
func TestAnExistingKeyFileIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("the only copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(path); err == nil {
		t.Fatal("generate overwrote an existing file")
	}
	if b, _ := os.ReadFile(path); string(b) != "the only copy" {
		t.Fatalf("the existing file changed to %q", b)
	}
}

// The private half is never printed: main prints the public half and the
// path, nothing else.
func TestThePrivateHalfIsNeverPrinted(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "fmt.Print") && strings.Contains(line, "priv") {
			t.Fatalf("a print statement mentions the private key: %s", strings.TrimSpace(line))
		}
	}
}
