// Command releasekey generates the Ed25519 pair that release signatures use.
//
// Run it once, with `make release-key RELEASE_KEY_OUT=<file>`. It produces two
// things:
//
//   - the public half, printed, which goes into app.ReleasePublicKey and ships
//     in every binary from then on
//   - the private half, written to the -out file and never printed, which goes
//     into the repository's RELEASE_SIGNING_KEY secret and must not go anywhere
//     else
//
// The private half is never printed because a terminal is not private: its
// scrollback is logged, recorded and pasted, and a key that has been on a
// screen has to be assumed copied. The file is created owner-only and is never
// overwritten. Keep it outside the repository and outside any synced folder;
// once the secret is set, keep it only in an offline backup or delete it. A
// lost private key cannot sign again, and replacing it means a key rotation.
//
// Rotating is the same operation, and it is not free: a machine running an
// older binary trusts the old key, so it will refuse a release signed with the
// new one until it has been updated by some other route. Publish one release
// carrying the new public key while still signing with the old private key,
// then switch.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("out", "", "file to write the private half to (created owner-only, never overwritten)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: releasekey -out <file>\n"+
			"The private half is written to <file> and never printed.")
		os.Exit(2)
	}
	pub, err := generate(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Public key — paste into ReleasePublicKey in internal/app/app.go:")
	fmt.Println()
	fmt.Println("    " + pub)
	fmt.Println()
	fmt.Println("Private key written to " + *out + " — store its contents as the")
	fmt.Println("RELEASE_SIGNING_KEY repository secret. It was not printed.")
}

// generate makes a pair, writes the private half to path and returns the public
// half. The file must not exist: overwriting the only copy of a signing key is
// not something to do by accident.
func generate(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("could not generate a key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("could not create %s (it must not already exist): %w", path, err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("could not write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("could not write %s: %w", path, err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
