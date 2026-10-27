package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backpack/backpack/internal/app"
)

func signedSums(t *testing.T, tag string) (pubB64, path string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "SHA256SUMS")
	sums := []byte("abc123  backpack_linux_amd64.tar.gz\n")
	if err := os.WriteFile(path, sums, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, app.ReleaseSignedMessage(tag, sums))
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub), path, priv
}

func TestAGoodSignatureVerifies(t *testing.T) {
	pub, path, _ := signedSums(t, "v1.2.3")
	if err := verify(pub, path, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
}

func TestEveryWayASignatureCanBeWrongIsRefused(t *testing.T) {
	pub, path, _ := signedSums(t, "v1.2.3")
	other, _, _ := signedSums(t, "v1.2.3")

	if err := verify(pub, path, "v1.2.4"); err == nil {
		t.Error("a signature for another tag verified")
	}
	if err := verify(other, path, "v1.2.3"); err == nil || !strings.Contains(err.Error(), "pinned key") {
		t.Errorf("a signature by another key verified: %v", err)
	}
	if err := verify("not-a-key", path, "v1.2.3"); err == nil {
		t.Error("a malformed pinned key was accepted")
	}
	if err := verify(pub, path, ""); err == nil {
		t.Error("an empty tag was accepted")
	}

	tampered := filepath.Join(t.TempDir(), "SHA256SUMS")
	sig, _ := os.ReadFile(path + ".sig")
	os.WriteFile(tampered, []byte("evil  backpack_linux_amd64.tar.gz\n"), 0o644)
	os.WriteFile(tampered+".sig", sig, 0o644)
	if err := verify(pub, tampered, "v1.2.3"); err == nil {
		t.Error("an altered checksum list verified")
	}

	unsigned := filepath.Join(t.TempDir(), "SHA256SUMS")
	os.WriteFile(unsigned, []byte("abc\n"), 0o644)
	if err := verify(pub, unsigned, "v1.2.3"); err == nil || !strings.Contains(err.Error(), "RELEASE_SIGNING_KEY") {
		t.Errorf("a missing signature was not reported as the secret missing: %v", err)
	}

	garbage := filepath.Join(t.TempDir(), "SHA256SUMS")
	os.WriteFile(garbage, []byte("abc\n"), 0o644)
	os.WriteFile(garbage+".sig", []byte("!!!\n"), 0o644)
	if err := verify(pub, garbage, "v1.2.3"); err == nil {
		t.Error("an unreadable signature was accepted")
	}
}

// The key compiled into the binary is a usable Ed25519 public key.
func TestThePinnedKeyIsUsable(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(app.ReleasePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("app.ReleasePublicKey is not a base64 Ed25519 public key (%d bytes, %v)", len(pub), err)
	}
}
