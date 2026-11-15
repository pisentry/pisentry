// Command pisentry-bundle makes and signs rule bundles for
// `pisentry update-patterns`. It is a maintainer tool used by the release
// workflow and is not shipped with the agent.
//
//	pisentry-bundle keygen -out FILE
//	pisentry-bundle sign -version N [-expires 2160h] [-min-agent v0.2.2] -out DIR FILE...
//
// sign reads the private key (base64 seed, as keygen writes it) from the
// environment variable PISENTRY_BUNDLE_KEY, never from a flag.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pisentry/pisentry/internal/rules"
)

const keyEnv = "PISENTRY_BUNDLE_KEY"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:], os.Getenv(keyEnv), time.Now())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  pisentry-bundle keygen -out FILE
  pisentry-bundle sign -version N [-expires 2160h] [-min-agent v0.2.2] -out DIR FILE...

sign reads the base64 private key from $`+keyEnv+`.`)
	os.Exit(1)
}

// keygen writes a new private key to a file only the current user can read
// and prints the public key and its key ID for internal/rules/bundle.go.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "write the private key here (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("private key: %s (keep it secret)\npublic key:  %s\nkey id:      %s\n",
		*out, base64.StdEncoding.EncodeToString(pub), rules.KeyID(pub))
	return nil
}

// sign validates each rule file, copies it into out as bundle-<name>.json and
// writes bundle.manifest and bundle.sig next to them.
func sign(args []string, key string, now time.Time) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	version := fs.Uint64("version", 0, "bundle version; must be higher than every version published before")
	expires := fs.Duration("expires", 90*24*time.Hour, "how long the manifest stays valid")
	minAgent := fs.String("min-agent", "", "lowest pisentry version that can load these rules, e.g. v0.2.2")
	out := fs.String("out", "", "output directory (created; must be empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("$%s is not set", keyEnv)
	}
	priv, err := rules.ParsePrivateKey(key)
	if err != nil {
		return err
	}
	if *version == 0 || *out == "" || fs.NArg() == 0 {
		return errors.New("-version, -out and at least one rule file are required")
	}
	if *expires <= 0 {
		return errors.New("-expires must be positive")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if entries, err := os.ReadDir(*out); err != nil {
		return err
	} else if len(entries) > 0 {
		return fmt.Errorf("%s is not empty", *out)
	}

	m := rules.Manifest{
		SchemaVersion:   rules.ManifestSchemaVersion,
		Version:         *version,
		Created:         now.UTC().Truncate(time.Second),
		Expires:         now.UTC().Truncate(time.Second).Add(*expires),
		MinAgentVersion: *minAgent,
	}
	for _, src := range fs.Args() {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if _, _, err := rules.LoadBytes(src, b); err != nil {
			return err
		}
		name := filepath.Base(src)
		if !strings.HasPrefix(name, rules.BundleFilePrefix) {
			name = rules.BundleFilePrefix + name
		}
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, rules.ManifestFile{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))})
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			return err
		}
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	mb = append(mb, '\n')
	sb, err := rules.SignManifest(mb, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, rules.ManifestName), mb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, rules.SignatureName), sb, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed bundle version %d, %d files, key id %s, expires %s, in %s\n",
		m.Version, len(m.Files), rules.KeyID(priv.Public().(ed25519.PublicKey)), m.Expires.Format(time.RFC3339), *out)
	return nil
}
