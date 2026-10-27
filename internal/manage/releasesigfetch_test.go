package manage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/backpack/backpack/internal/app"
)

// The updater's whole signature path, as it runs on a server: the signature is
// fetched from the release beside the checksums and checked against the key
// pinned in the binary. Every way a published signature can be wrong — absent,
// another key's, another release's, over altered checksums, unreadable — is a
// refusal, and only the publisher's signature for this tag passes.
func TestTheUpdaterFetchesTheSignatureAndRefusesAnyThatDoesNotVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer withReleaseKey(t, base64.StdEncoding.EncodeToString(pub))()

	const tag = "v9.9.9"
	const sigPath = "/releases/download/" + tag + "/" + sigAssetName
	sums := []byte("0123abcd  backpack_linux_amd64.tar.gz\n")

	var mu sync.Mutex
	served := map[string][]byte{}
	serve := func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		if b == nil {
			delete(served, sigPath)
		} else {
			served[sigPath] = b
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		b, ok := served[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	old := repoURLOverride
	repoURLOverride = srv.URL
	defer func() { repoURLOverride = old }()

	sign := func(key ed25519.PrivateKey, forTag string, over []byte) []byte {
		sig := ed25519.Sign(key, app.ReleaseSignedMessage(forTag, over))
		return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	altered := []byte("ffffffff  backpack_linux_amd64.tar.gz\n")

	for _, tc := range []struct {
		name   string
		served []byte
		ok     bool
		want   string
	}{
		{"no signature published", nil, false, "publishes no signature"},
		{"the publisher's signature for this tag", sign(priv, tag, sums), true, ""},
		{"another key's signature", sign(other, tag, sums), false, "not signed"},
		{"another release's signature served under this tag", sign(priv, "v9.9.8", sums), false, "not signed"},
		{"a signature over other checksums", sign(priv, tag, altered), false, "not signed"},
		{"an unreadable signature", []byte("not base64 at all!\n"), false, "not readable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serve(tc.served)
			err := verifyChecksumSignature(tag, sums)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// The key this build pins is a usable Ed25519 public key; a build fault here
// would make every release refuse to install.
func TestThePinnedReleaseKeyIsUsable(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(app.ReleasePublicKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("app.ReleasePublicKey is not a base64 Ed25519 public key (%d bytes, %v)", len(pub), err)
	}
}
