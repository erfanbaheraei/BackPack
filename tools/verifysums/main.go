// Command verifysums checks a release's SHA256SUMS signature against the key
// compiled into the binary, for the release workflow.
//
// It runs after signing and before publishing. A build carrying a pinned key
// refuses any release whose signature does not verify (see
// internal/manage/releasesig.go), so a release published unsigned — the secret
// missing — or signed with a key that is not the pinned one would install
// nowhere through the updater. This turns that into a failed workflow instead
// of a published release nobody can update to.
//
// The check is the updater's own: Ed25519 over app.ReleaseSignedMessage(tag,
// sums), with the signature as base64 of the raw 64 bytes.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/backpack/backpack/internal/app"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: verifysums <path to SHA256SUMS> [tag]")
		os.Exit(2)
	}
	path := os.Args[1]
	tag := releaseTag()
	if len(os.Args) == 3 {
		tag = os.Args[2]
	}
	if err := verify(app.ReleasePublicKey, path, tag); err != nil {
		fmt.Fprintln(os.Stderr, "release signature check failed:", err)
		os.Exit(1)
	}
	fmt.Println("Signature verifies for", tag, "against the pinned release key.")
}

// verify checks path.sig over path for tag under the base64 public key.
func verify(pubB64, path, tag string) error {
	if tag == "" {
		return fmt.Errorf("no release tag: set GITHUB_REF_NAME, pass one, or run from the repository root")
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("the pinned release key is not a base64 Ed25519 public key")
	}
	sums, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sigB64, err := os.ReadFile(path + ".sig")
	if err != nil {
		return fmt.Errorf("no signature beside %s (is RELEASE_SIGNING_KEY set?): %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s.sig is not a base64 Ed25519 signature", path)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), app.ReleaseSignedMessage(tag, sums), sig) {
		return fmt.Errorf("%s.sig does not verify for %s under the pinned key: it was made "+
			"for other checksums or another tag, or RELEASE_SIGNING_KEY is not the private "+
			"half of app.ReleasePublicKey", path, tag)
	}
	return nil
}

// releaseTag is the tag being released: CI's, or the VERSION file's.
func releaseTag() string {
	if t := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME")); t != "" {
		return t
	}
	v, err := os.ReadFile("VERSION")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(v))
}
